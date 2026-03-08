"""
Config Hot-Reload Module - XClaw AgentGuard

Watches configuration files for changes and applies updates without restart.
Supports both watchdog-based file monitoring and polling fallback.

Features:
- File change detection (watchdog or polling)
- Config validation before applying
- Callback triggering for detectors/plugins
- Audit logging of config changes
- Thread-safe implementation
"""

import os
import json
import time
import logging
import hashlib
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Set, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime

# Optional watchdog import
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

from ..core.config_schema import ConfigValidator, DetectorConfig


logger = logging.getLogger(__name__)


@dataclass
class ConfigChangeEvent:
    """Configuration change event data"""
    timestamp: str
    file_path: str
    change_type: str  # 'modified', 'created', 'deleted'
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    validation_errors: List[str] = field(default_factory=list)
    applied_successfully: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ConfigReloadCallback:
    """Callback interface for config reload notifications"""
    
    def __init__(self, name: str, callback: Callable[[str, Dict[str, Any]], None]):
        self.name = name
        self.callback = callback
    
    def invoke(self, config_file: str, new_config: Dict[str, Any]) -> None:
        """Invoke the callback with new configuration"""
        try:
            self.callback(config_file, new_config)
        except Exception as e:
            logger.error(f"Config reload callback '{self.name}' failed: {e}")


class ConfigFileWatcher:
    """
    Watches configuration files for changes
    
    Supports both watchdog-based monitoring and polling fallback.
    Validates new configurations before applying changes.
    """
    
    def __init__(
        self,
        config_dir: Optional[str] = None,
        poll_interval: float = 2.0,
        use_watchdog: bool = True,
        audit_logger: Optional[Any] = None
    ):
        """
        Initialize config file watcher
        
        Args:
            config_dir: Directory to watch for config files
            poll_interval: Polling interval in seconds (fallback mode)
            use_watchdog: Whether to use watchdog if available
            audit_logger: Optional audit logger for config changes
        """
        self.config_dir = Path(config_dir) if config_dir else Path.cwd()
        self.poll_interval = poll_interval
        self.use_watchdog = use_watchdog and WATCHDOG_AVAILABLE
        self.audit_logger = audit_logger
        
        # File state tracking
        self._file_hashes: Dict[str, str] = {}
        self._file_timestamps: Dict[str, float] = {}
        
        # Callbacks
        self._callbacks: List[ConfigReloadCallback] = []
        self._validator: Optional[ConfigValidator] = None
        self._detector_configs: Dict[str, DetectorConfig] = {}
        
        # Threading
        self._lock = threading.RLock()
        self._observer: Optional[Any] = None
        self._polling_thread: Optional[threading.Thread] = None
        self._running = False
        
        # Config schemas for validation
        self._config_schemas: Dict[str, DetectorConfig] = {}
    
    def register_schema(self, config_id: str, schema: DetectorConfig) -> None:
        """Register a configuration schema for validation"""
        with self._lock:
            self._config_schemas[config_id] = schema
    
    def register_callback(
        self, 
        name: str, 
        callback: Callable[[str, Dict[str, Any]], None]
    ) -> None:
        """Register a callback to be triggered on config reload"""
        with self._lock:
            self._callbacks.append(ConfigReloadCallback(name, callback))
            logger.info(f"Registered config reload callback: {name}")
    
    def unregister_callback(self, name: str) -> bool:
        """Unregister a callback by name"""
        with self._lock:
            original_len = len(self._callbacks)
            self._callbacks = [cb for cb in self._callbacks if cb.name != name]
            removed = len(self._callbacks) < original_len
            if removed:
                logger.info(f"Unregistered config reload callback: {name}")
            return removed
    
    def _compute_file_hash(self, file_path: str) -> str:
        """Compute MD5 hash of file contents"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception as e:
            logger.error(f"Failed to compute hash for {file_path}: {e}")
            return ""
    
    def _load_config(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Load configuration from file"""
        try:
            path = Path(file_path)
            if not path.exists():
                return None
            
            with open(path, 'r') as f:
                if path.suffix in ('.json', ''):
                    return json.load(f)
                else:
                    # Try YAML if available
                    try:
                        import yaml
                        return yaml.safe_load(f)
                    except ImportError:
                        # Fall back to JSON
                        f.seek(0)
                        return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {file_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to load config from {file_path}: {e}")
            return None
    
    def _validate_config(
        self, 
        config: Dict[str, Any], 
        config_id: Optional[str] = None
    ) -> tuple[bool, List[str]]:
        """
        Validate configuration against registered schemas
        
        Returns:
            (is_valid, error_messages)
        """
        errors = []
        
        # If specific schema provided, validate against it
        if config_id and config_id in self._config_schemas:
            schema = self._config_schemas[config_id]
            is_valid, schema_errors = ConfigValidator.validate(config, schema)
            if not is_valid:
                errors.extend(schema_errors)
        
        # Basic structure validation
        if not isinstance(config, dict):
            errors.append("Configuration must be a dictionary")
            return False, errors
        
        # Validate all registered schemas that match
        for sid, schema in self._config_schemas.items():
            if sid in config:
                is_valid, schema_errors = ConfigValidator.validate(config[sid], schema)
                if not is_valid:
                    errors.extend([f"[{sid}] {e}" for e in schema_errors])
        
        return len(errors) == 0, errors
    
    def _apply_config(self, file_path: str, config: Dict[str, Any]) -> bool:
        """Apply new configuration and trigger callbacks"""
        try:
            # Trigger all registered callbacks
            with self._lock:
                callbacks = self._callbacks.copy()
            
            for callback in callbacks:
                callback.invoke(file_path, config)
            
            logger.info(f"Successfully applied config from {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to apply config from {file_path}: {e}")
            return False
    
    def _handle_file_change(self, file_path: str, change_type: str = 'modified') -> ConfigChangeEvent:
        """Handle a file change event"""
        event = ConfigChangeEvent(
            timestamp=datetime.now().isoformat(),
            file_path=file_path,
            change_type=change_type,
            old_hash=self._file_hashes.get(file_path)
        )
        
        # Compute new hash
        new_hash = self._compute_file_hash(file_path)
        event.new_hash = new_hash
        
        # Check if content actually changed
        if event.old_hash == new_hash:
            logger.debug(f"File {file_path} touched but content unchanged")
            return event
        
        # Load new config
        config = self._load_config(file_path)
        if config is None:
            event.validation_errors.append("Failed to load configuration")
            self._log_config_change(event)
            return event
        
        # Validate new config
        config_id = Path(file_path).stem
        is_valid, errors = self._validate_config(config, config_id)
        
        if not is_valid:
            event.validation_errors = errors
            logger.error(f"Config validation failed for {file_path}: {errors}")
            self._log_config_change(event)
            return event
        
        # Apply the new configuration
        if self._apply_config(file_path, config):
            event.applied_successfully = True
            self._file_hashes[file_path] = new_hash
        
        self._log_config_change(event)
        return event
    
    def _log_config_change(self, event: ConfigChangeEvent) -> None:
        """Log configuration change to audit log"""
        # Internal logging
        if event.applied_successfully:
            logger.info(f"Config reloaded: {event.file_path}")
        elif event.validation_errors:
            logger.warning(f"Config reload failed for {event.file_path}: {event.validation_errors}")
        
        # External audit logging
        if self.audit_logger:
            try:
                self.audit_logger.log_config_change(event)
            except Exception as e:
                logger.error(f"Failed to log config change to audit: {e}")
    
    def _polling_loop(self) -> None:
        """Polling-based file watching loop"""
        logger.info(f"Starting config polling loop (interval: {self.poll_interval}s)")
        
        while self._running:
            try:
                self._check_all_files()
                time.sleep(self.poll_interval)
            except Exception as e:
                logger.error(f"Error in polling loop: {e}")
                time.sleep(self.poll_interval)
    
    def _check_all_files(self) -> None:
        """Check all watched files for changes"""
        with self._lock:
            files_to_check = list(self._file_hashes.keys())
        
        for file_path in files_to_check:
            try:
                current_mtime = os.path.getmtime(file_path)
                last_mtime = self._file_timestamps.get(file_path, 0)
                
                if current_mtime > last_mtime:
                    self._file_timestamps[file_path] = current_mtime
                    self._handle_file_change(file_path)
            except FileNotFoundError:
                # File was deleted
                self._handle_file_change(file_path, change_type='deleted')
                with self._lock:
                    self._file_hashes.pop(file_path, None)
                    self._file_timestamps.pop(file_path, None)
    
    def watch_file(self, file_path: str) -> bool:
        """Add a file to watch list"""
        path = Path(file_path)
        if not path.exists():
            logger.warning(f"Cannot watch non-existent file: {file_path}")
            return False
        
        with self._lock:
            self._file_hashes[str(path)] = self._compute_file_hash(str(path))
            self._file_timestamps[str(path)] = path.stat().st_mtime
        
        logger.info(f"Now watching config file: {file_path}")
        return True
    
    def watch_directory(self, directory: str, pattern: str = "*.json") -> int:
        """Watch all matching files in a directory"""
        dir_path = Path(directory)
        if not dir_path.exists():
            logger.warning(f"Directory does not exist: {directory}")
            return 0
        
        count = 0
        for file_path in dir_path.glob(pattern):
            if self.watch_file(str(file_path)):
                count += 1
        
        logger.info(f"Watching {count} config files in {directory}")
        return count
    
    def start(self) -> bool:
        """Start watching for config changes"""
        if self._running:
            logger.warning("Config watcher already running")
            return False
        
        self._running = True
        
        if self.use_watchdog and WATCHDOG_AVAILABLE:
            return self._start_watchdog()
        else:
            return self._start_polling()
    
    def _start_watchdog(self) -> bool:
        """Start watchdog-based file watching"""
        try:
            handler = _WatchdogHandler(self)
            self._observer = Observer()
            
            # Watch individual files and directories
            watched_paths: Set[str] = set()
            for file_path in self._file_hashes.keys():
                dir_path = str(Path(file_path).parent)
                if dir_path not in watched_paths:
                    self._observer.schedule(handler, dir_path, recursive=False)
                    watched_paths.add(dir_path)
            
            self._observer.start()
            logger.info("Config watcher started (watchdog mode)")
            return True
        except Exception as e:
            logger.error(f"Failed to start watchdog: {e}")
            self._running = False
            return False
    
    def _start_polling(self) -> bool:
        """Start polling-based file watching"""
        self._polling_thread = threading.Thread(target=self._polling_loop, daemon=True)
        self._polling_thread.start()
        logger.info("Config watcher started (polling mode)")
        return True
    
    def stop(self) -> None:
        """Stop watching for config changes"""
        self._running = False
        
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join()
            except Exception as e:
                logger.error(f"Error stopping watchdog: {e}")
            self._observer = None
        
        if self._polling_thread and self._polling_thread.is_alive():
            self._polling_thread.join(timeout=5.0)
        
        logger.info("Config watcher stopped")
    
    def force_reload(self, file_path: str) -> ConfigChangeEvent:
        """Force reload of a specific config file"""
        return self._handle_file_change(file_path)
    
    def get_watched_files(self) -> List[str]:
        """Get list of currently watched files"""
        with self._lock:
            return list(self._file_hashes.keys())


class _WatchdogHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    """Watchdog event handler for config file changes"""
    
    def __init__(self, watcher: ConfigFileWatcher):
        self.watcher = watcher
    
    def on_modified(self, event):
        if not event.is_directory:
            file_path = str(event.src_path)
            if file_path in self.watcher._file_hashes:
                logger.debug(f"Watchdog detected modification: {file_path}")
                self.watcher._handle_file_change(file_path, 'modified')
    
    def on_created(self, event):
        if not event.is_directory:
            file_path = str(event.src_path)
            logger.debug(f"Watchdog detected creation: {file_path}")
            # Auto-watch new config files
            if file_path.endswith(('.json', '.yaml', '.yml', '.conf')):
                self.watcher.watch_file(file_path)
    
    def on_deleted(self, event):
        if not event.is_directory:
            file_path = str(event.src_path)
            if file_path in self.watcher._file_hashes:
                logger.debug(f"Watchdog detected deletion: {file_path}")
                self.watcher._handle_file_change(file_path, 'deleted')


class ConfigWatcherManager:
    """
    Singleton manager for config watcher instances
    
    Provides global access to the config watcher and integrates
    with the detector framework.
    """
    
    _instance: Optional['ConfigWatcherManager'] = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._watcher: Optional[ConfigFileWatcher] = None
                    cls._instance._initialized = False
        return cls._instance
    
    def initialize(
        self,
        config_dir: Optional[str] = None,
        poll_interval: float = 2.0,
        use_watchdog: bool = True,
        audit_logger: Optional[Any] = None
    ) -> ConfigFileWatcher:
        """Initialize the global config watcher"""
        if not self._initialized:
            self._watcher = ConfigFileWatcher(
                config_dir=config_dir,
                poll_interval=poll_interval,
                use_watchdog=use_watchdog,
                audit_logger=audit_logger
            )
            self._initialized = True
            logger.info("ConfigWatcherManager initialized")
        return self._watcher
    
    def get_watcher(self) -> Optional[ConfigFileWatcher]:
        """Get the global config watcher instance"""
        return self._watcher
    
    def start(self) -> bool:
        """Start the global config watcher"""
        if self._watcher:
            return self._watcher.start()
        logger.warning("ConfigWatcherManager not initialized")
        return False
    
    def stop(self) -> None:
        """Stop the global config watcher"""
        if self._watcher:
            self._watcher.stop()
    
    def register_detector_callback(
        self, 
        detector_id: str,
        detector_instance: Any
    ) -> None:
        """Register a detector for config reload callbacks"""
        if not self._watcher:
            return
        
        def callback(config_file: str, new_config: Dict[str, Any]):
            """Callback to update detector configuration"""
            try:
                # Check if this config applies to this detector
                if detector_id in new_config:
                    detector_config = new_config[detector_id]
                else:
                    detector_config = new_config
                
                # Update detector configuration
                if hasattr(detector_instance, 'configure'):
                    detector_instance.configure(detector_config)
                    logger.info(f"Updated configuration for detector: {detector_id}")
            except Exception as e:
                logger.error(f"Failed to update detector {detector_id}: {e}")
        
        self._watcher.register_callback(f"detector:{detector_id}", callback)


# Global functions for easy access
def get_config_watcher() -> Optional[ConfigFileWatcher]:
    """Get the global config watcher instance"""
    return ConfigWatcherManager().get_watcher()


def initialize_config_watcher(
    config_dir: Optional[str] = None,
    poll_interval: float = 2.0,
    use_watchdog: bool = True,
    audit_logger: Optional[Any] = None
) -> ConfigFileWatcher:
    """Initialize and return the global config watcher"""
    manager = ConfigWatcherManager()
    watcher = manager.initialize(
        config_dir=config_dir,
        poll_interval=poll_interval,
        use_watchdog=use_watchdog,
        audit_logger=audit_logger
    )
    manager.start()
    return watcher


def stop_config_watcher() -> None:
    """Stop the global config watcher"""
    ConfigWatcherManager().stop()


__all__ = [
    "ConfigFileWatcher",
    "ConfigWatcherManager",
    "ConfigReloadCallback",
    "ConfigChangeEvent",
    "get_config_watcher",
    "initialize_config_watcher",
    "stop_config_watcher",
]