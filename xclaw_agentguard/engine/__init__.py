"""
XClaw AgentGuard - Protection Engine (Optional)

Background daemon that provides automatic protection for AI agent systems.
This is an optional enhancement layer - the framework works independently.

Usage:
    # Framework mode (always works)
    from xclaw_agentguard import PromptInjectionDetector
    detector = PromptInjectionDetector()
    result = detector.detect(content)
    
    # Engine mode (optional enhancement)
    from xclaw_agentguard.engine import start_engine_daemon
    start_engine_daemon()
"""

import os
import sys
import time
import signal
import socket
import json
import threading
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
import logging

logger = logging.getLogger('agentguard-engine')


@dataclass
class EngineConfig:
    """Configuration for the protection engine"""
    daemon_mode: bool = True
    pid_file: str = "/tmp/xclaw_agentguard.pid"
    socket_path: str = "/tmp/xclaw_agentguard.sock"
    log_level: str = "INFO"
    scan_interval: int = 60
    protected_directories: List[str] = None
    
    def __post_init__(self):
        if self.protected_directories is None:
            self.protected_directories = [os.path.expanduser("~/.openclaw")]


class ProtectionEngine:
    """Optional background protection engine"""
    
    def __init__(self, config: Optional[EngineConfig] = None):
        self.config = config or EngineConfig()
        self._running = False
        self._shutdown_event = threading.Event()
        self._detectors: Dict[str, Any] = {}
        self._integrity_monitor: Optional[Any] = None
        
    def initialize(self):
        """Initialize engine (imports from framework)"""
        from ..detectors.prompt_injection.detector import PromptInjectionDetector
        from ..detectors.jailbreak.detector import JailbreakDetector
        from ..anti_jacked import get_integrity_monitor
        
        self._detectors = {
            'prompt_injection': PromptInjectionDetector(),
            'jailbreak': JailbreakDetector(),
        }
        self._integrity_monitor = get_integrity_monitor()
        
        for directory in self.config.protected_directories:
            if os.path.exists(directory):
                self._integrity_monitor.add_watch_directory(directory)
    
    def start(self):
        """Start engine"""
        if self._running:
            return
        self.initialize()
        self._running = True
        self._write_pid()
        
        # Start monitor thread
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        self._start_socket_server()
        
        try:
            while self._running:
                self._shutdown_event.wait(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
    
    def stop(self):
        """Stop engine"""
        self._running = False
        self._shutdown_event.set()
        self._remove_pid()
    
    def _write_pid(self):
        with open(self.config.pid_file, 'w') as f:
            f.write(str(os.getpid()))
    
    def _remove_pid(self):
        if os.path.exists(self.config.pid_file):
            os.remove(self.config.pid_file)
    
    def _monitor_loop(self):
        while self._running:
            try:
                if self._integrity_monitor:
                    result = self._integrity_monitor.check_integrity()
                    if result.get('modified'):
                        logger.warning(f"Integrity violation: {result}")
                self._shutdown_event.wait(self.config.scan_interval)
            except Exception as e:
                logger.error(f"Monitor error: {e}")
    
    def _start_socket_server(self):
        """Start Unix socket for IPC"""
        try:
            if os.path.exists(self.config.socket_path):
                os.remove(self.config.socket_path)
            
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(self.config.socket_path)
            sock.listen(5)
            sock.settimeout(1)
            
            threading.Thread(target=self._accept_connections, args=(sock,), daemon=True).start()
        except Exception as e:
            logger.error(f"Socket error: {e}")
    
    def _accept_connections(self, sock):
        while self._running:
            try:
                conn, _ = sock.accept()
                threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
    
    def _handle_client(self, conn):
        try:
            data = conn.recv(65536).decode()
            request = json.loads(data)
            action = request.get('action')
            
            if action == 'scan':
                result = self._scan_content(request.get('content', ''))
                response = {'status': 'ok', 'result': result}
            elif action == 'status':
                response = {'status': 'ok', 'engine': 'running'}
            else:
                response = {'status': 'error', 'message': 'Unknown action'}
            
            conn.send(json.dumps(response).encode())
        except Exception as e:
            logger.error(f"Client error: {e}")
        finally:
            conn.close()
    
    def _scan_content(self, content: str) -> Dict:
        """Scan content with detectors"""
        from ..detection_result import DetectionResultBuilder, ThreatLevel
        
        highest_threat = ThreatLevel.NONE
        detections = []
        
        for name, detector in self._detectors.items():
            try:
                result = detector.detect(content)
                if result.detected:
                    detections.append({'detector': name, 'threat_level': result.threat_level.name})
                    if result.threat_level.value > highest_threat.value:
                        highest_threat = result.threat_level
            except Exception as e:
                logger.error(f"Detector {name} error: {e}")
        
        return {
            'detected': len(detections) > 0,
            'threat_level': highest_threat.name,
            'detections': detections
        }


def start_engine_daemon(config: Optional[EngineConfig] = None):
    """Start engine as daemon"""
    engine = ProtectionEngine(config)
    
    def signal_handler(signum, frame):
        engine.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    engine.start()