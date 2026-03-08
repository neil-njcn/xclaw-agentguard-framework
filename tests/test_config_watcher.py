"""
Tests for Config Hot-Reload Module
"""

import os
import json
import time
import tempfile
import shutil
from pathlib import Path
from unittest import TestCase, mock

from xclaw_agentguard.config_watcher import (
    ConfigFileWatcher,
    ConfigWatcherManager,
    ConfigReloadCallback,
    ConfigChangeEvent,
    get_config_watcher,
    initialize_config_watcher,
    stop_config_watcher,
)
from xclaw_agentguard.core.config_schema import DetectorConfig, ConfigSchema, CommonConfigs


class TestConfigFileWatcher(TestCase):
    """Test ConfigFileWatcher functionality"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.watcher = ConfigFileWatcher(
            config_dir=self.temp_dir,
            poll_interval=0.1,
            use_watchdog=False  # Use polling for tests
        )
    
    def tearDown(self):
        self.watcher.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_compute_file_hash(self):
        """Test file hash computation"""
        test_file = Path(self.temp_dir) / "test.json"
        test_file.write_text('{"test": true}')
        
        hash1 = self.watcher._compute_file_hash(str(test_file))
        hash2 = self.watcher._compute_file_hash(str(test_file))
        
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 32)  # MD5 hash length
    
    def test_load_config_json(self):
        """Test loading JSON config"""
        test_file = Path(self.temp_dir) / "config.json"
        config_data = {"enabled": True, "threshold": 0.5}
        test_file.write_text(json.dumps(config_data))
        
        loaded = self.watcher._load_config(str(test_file))
        self.assertEqual(loaded, config_data)
    
    def test_load_config_nonexistent(self):
        """Test loading non-existent config"""
        loaded = self.watcher._load_config("/nonexistent/file.json")
        self.assertIsNone(loaded)
    
    def test_validate_config_basic(self):
        """Test basic config validation"""
        config = {"enabled": True, "threshold": 0.5}
        is_valid, errors = self.watcher._validate_config(config)
        
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)
    
    def test_validate_config_invalid_type(self):
        """Test config validation with wrong type"""
        # Register a schema
        schema = DetectorConfig(
            detector_id="test_detector",
            version="1.0.0",
            schema=[
                ConfigSchema(
                    name="threshold",
                    type=float,
                    description="Test threshold",
                    default=0.5
                )
            ]
        )
        self.watcher.register_schema("test_detector", schema)
        
        # Test with nested config
        config = {"test_detector": {"threshold": "invalid"}}
        is_valid, errors = self.watcher._validate_config(config, "test_detector")
        
        self.assertFalse(is_valid)
        self.assertTrue(len(errors) > 0)
    
    def test_register_callback(self):
        """Test callback registration"""
        callback_invoked = [False]
        
        def test_callback(file_path, config):
            callback_invoked[0] = True
        
        self.watcher.register_callback("test", test_callback)
        self.assertEqual(len(self.watcher._callbacks), 1)
        
        # Unregister
        self.watcher.unregister_callback("test")
        self.assertEqual(len(self.watcher._callbacks), 0)
    
    def test_watch_file(self):
        """Test watching a file"""
        test_file = Path(self.temp_dir) / "watch_test.json"
        test_file.write_text('{"test": true}')
        
        result = self.watcher.watch_file(str(test_file))
        self.assertTrue(result)
        self.assertIn(str(test_file), self.watcher._file_hashes)
    
    def test_watch_nonexistent_file(self):
        """Test watching non-existent file"""
        result = self.watcher.watch_file("/nonexistent/file.json")
        self.assertFalse(result)
    
    def test_watch_directory(self):
        """Test watching a directory"""
        # Create multiple config files
        for i in range(3):
            test_file = Path(self.temp_dir) / f"config_{i}.json"
            test_file.write_text(json.dumps({"id": i}))
        
        count = self.watcher.watch_directory(self.temp_dir, "*.json")
        self.assertEqual(count, 3)
    
    def test_force_reload(self):
        """Test force reload functionality"""
        test_file = Path(self.temp_dir) / "reload_test.json"
        test_file.write_text('{"version": 1}')
        
        # Don't watch file first - force_reload should handle unwatched files
        # Add callback
        callback_data = [None]
        def test_callback(file_path, config):
            callback_data[0] = config
        
        self.watcher.register_callback("test", test_callback)
        
        # Force reload
        event = self.watcher.force_reload(str(test_file))
        
        # File is not being watched, so it won't apply (no hash comparison)
        # But it should load and validate
        self.assertEqual(event.file_path, str(test_file))
        self.assertEqual(len(event.validation_errors), 0)
    
    def test_config_change_detection(self):
        """Test detecting config changes"""
        test_file = Path(self.temp_dir) / "change_test.json"
        test_file.write_text('{"version": 1}')
        
        self.watcher.watch_file(str(test_file))
        initial_hash = self.watcher._file_hashes[str(test_file)]
        
        # Modify file
        time.sleep(0.1)
        test_file.write_text('{"version": 2}')
        
        # Handle change
        event = self.watcher._handle_file_change(str(test_file))
        
        self.assertTrue(event.applied_successfully)
        self.assertEqual(event.old_hash, initial_hash)
        self.assertNotEqual(event.new_hash, initial_hash)


class TestConfigWatcherManager(TestCase):
    """Test ConfigWatcherManager singleton"""
    
    def tearDown(self):
        stop_config_watcher()
    
    def test_singleton(self):
        """Test manager is a singleton"""
        manager1 = ConfigWatcherManager()
        manager2 = ConfigWatcherManager()
        
        self.assertIs(manager1, manager2)
    
    def test_initialize(self):
        """Test initialization"""
        temp_dir = tempfile.mkdtemp()
        
        try:
            watcher = initialize_config_watcher(
                config_dir=temp_dir,
                poll_interval=1.0,
                use_watchdog=False
            )
            
            self.assertIsNotNone(watcher)
            self.assertIs(watcher, get_config_watcher())
            
        finally:
            stop_config_watcher()
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    def test_get_watcher_before_init(self):
        """Test getting watcher before initialization"""
        watcher = get_config_watcher()
        self.assertIsNone(watcher)


class TestConfigChangeEvent(TestCase):
    """Test ConfigChangeEvent dataclass"""
    
    def test_to_dict(self):
        """Test conversion to dict"""
        event = ConfigChangeEvent(
            timestamp="2024-01-01T00:00:00",
            file_path="/test/config.json",
            change_type="modified",
            old_hash="abc123",
            new_hash="def456",
            validation_errors=[],
            applied_successfully=True
        )
        
        data = event.to_dict()
        
        self.assertEqual(data["timestamp"], "2024-01-01T00:00:00")
        self.assertEqual(data["file_path"], "/test/config.json")
        self.assertEqual(data["change_type"], "modified")
        self.assertTrue(data["applied_successfully"])


if __name__ == "__main__":
    import unittest
    unittest.main()