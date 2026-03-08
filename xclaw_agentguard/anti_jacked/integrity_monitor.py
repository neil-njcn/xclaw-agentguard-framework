"""
XClaw AgentGuard - Anti-Jacked Security Base
File Integrity Monitoring System

This module provides the core security foundation for AgentGuard v2.3.0,
protecting against CVE-2026-25253 and similar agent hijacking attacks.
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
import threading


@dataclass
class FileIntegrityRecord:
    """Record of a file's integrity state"""
    path: str
    sha256: str
    size: int
    mtime: float
    checked_at: str
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'FileIntegrityRecord':
        return cls(**data)


class IntegrityMonitor:
    """
    File Integrity Monitoring System
    
    Monitors critical files for unauthorized changes using SHA256 hashing.
    Detects tampering attempts and triggers alerts.
    """
    
    def __init__(self, baseline_path: Optional[str] = None):
        self.baseline_path = baseline_path or "memory/genomes/anti-jacked-baseline.json"
        self.baseline: Dict[str, FileIntegrityRecord] = {}
        self.watched_files: Set[str] = set()
        self.check_interval = 300  # 5 minutes default
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._callbacks: List[Callable] = []
        self._load_baseline()
    
    def _load_baseline(self):
        """Load integrity baseline from disk"""
        if os.path.exists(self.baseline_path):
            try:
                with open(self.baseline_path, 'r') as f:
                    data = json.load(f)
                    self.baseline = {
                        k: FileIntegrityRecord.from_dict(v) 
                        for k, v in data.get('files', {}).items()
                    }
                    self.watched_files = set(self.baseline.keys())
            except Exception as e:
                print(f"Warning: Could not load baseline: {e}")
                self.baseline = {}
    
    def _save_baseline(self):
        """Save integrity baseline to disk"""
        os.makedirs(os.path.dirname(self.baseline_path), exist_ok=True)
        data = {
            'baseline_id': f"anti-jacked-v2.3.1-baseline-{datetime.now().isoformat()}",
            'created': datetime.now().isoformat(),
            'algorithm': 'sha256',
            'files': {k: v.to_dict() for k, v in self.baseline.items()}
        }
        with open(self.baseline_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    @staticmethod
    def calculate_sha256(file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def add_watch(self, file_path: str) -> bool:
        """Add a file to integrity monitoring"""
        if not os.path.exists(file_path):
            return False
        
        abs_path = os.path.abspath(file_path)
        if abs_path in self.watched_files:
            return True
        
        try:
            stat = os.stat(abs_path)
            record = FileIntegrityRecord(
                path=abs_path,
                sha256=self.calculate_sha256(abs_path),
                size=stat.st_size,
                mtime=stat.st_mtime,
                checked_at=datetime.now().isoformat()
            )
            self.baseline[abs_path] = record
            self.watched_files.add(abs_path)
            return True
        except Exception as e:
            print(f"Error adding watch for {file_path}: {e}")
            return False
    
    def add_watch_directory(self, directory: str, pattern: str = '*.py') -> int:
        """Add all matching files in a directory"""
        count = 0
        path = Path(directory)
        for file_path in path.rglob(pattern):
            if self.add_watch(str(file_path)):
                count += 1
        return count
    
    def check_integrity(self, file_path: Optional[str] = None) -> Dict[str, any]:
        """
        Check file integrity against baseline
        
        Returns:
            Dict with 'verified', 'modified', 'missing', 'errors' lists
        """
        result = {
            'verified': [],
            'modified': [],
            'missing': [],
            'errors': [],
            'checked_at': datetime.now().isoformat()
        }
        
        files_to_check = [file_path] if file_path else list(self.watched_files)
        
        for path in files_to_check:
            if not path:
                continue
                
            if not os.path.exists(path):
                result['missing'].append({
                    'path': path,
                    'baseline': self.baseline.get(path, {}).to_dict() if path in self.baseline else None
                })
                continue
            
            try:
                current_hash = self.calculate_sha256(path)
                baseline_record = self.baseline.get(path)
                
                if baseline_record is None:
                    result['errors'].append({
                        'path': path,
                        'error': 'No baseline record'
                    })
                    continue
                
                if current_hash != baseline_record.sha256:
                    result['modified'].append({
                        'path': path,
                        'expected_hash': baseline_record.sha256,
                        'actual_hash': current_hash,
                        'expected_mtime': baseline_record.mtime,
                        'actual_mtime': os.stat(path).st_mtime
                    })
                else:
                    result['verified'].append({
                        'path': path,
                        'hash': current_hash,
                        'status': 'ok'
                    })
                    
            except Exception as e:
                result['errors'].append({
                    'path': path,
                    'error': str(e)
                })
        
        return result
    
    def generate_baseline(self, directories: List[str]) -> Dict:
        """Generate new baseline from directories"""
        self.baseline = {}
        self.watched_files = set()
        
        critical_dirs = [
            'xclaw_agentguard/core',
            'xclaw_agentguard/detectors',
            'xclaw_agentguard/config',
            'xclaw_agentguard/plugins'
        ]
        
        for directory in directories:
            self.add_watch_directory(directory, '*.py')
            self.add_watch_directory(directory, '*.json')
        
        self._save_baseline()
        
        return {
            'total_files': len(self.watched_files),
            'baseline_path': self.baseline_path,
            'files': list(self.watched_files)
        }
    
    def register_callback(self, callback: Callable):
        """Register callback for tamper alerts"""
        self._callbacks.append(callback)
    
    def _notify_callbacks(self, alert: Dict):
        """Notify all registered callbacks"""
        for callback in self._callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"Callback error: {e}")
    
    def start_monitoring(self, interval: Optional[int] = None):
        """Start continuous integrity monitoring"""
        if self._running:
            return
        
        self.check_interval = interval or self.check_interval
        self._running = True
        
        def monitor_loop():
            while self._running:
                result = self.check_integrity()
                
                if result['modified'] or result['missing']:
                    alert = {
                        'type': 'tamper_detected',
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'CRITICAL',
                        'details': result
                    }
                    self._notify_callbacks(alert)
                
                time.sleep(self.check_interval)
        
        self._monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self._monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
    
    def get_status(self) -> Dict:
        """Get current integrity status"""
        return {
            'baseline_loaded': len(self.baseline) > 0,
            'watched_files': len(self.watched_files),
            'monitoring_active': self._running,
            'check_interval': self.check_interval,
            'baseline_path': self.baseline_path
        }


# Global instance
_integrity_monitor: Optional[IntegrityMonitor] = None


def get_integrity_monitor() -> IntegrityMonitor:
    """Get or create global integrity monitor instance"""
    global _integrity_monitor
    if _integrity_monitor is None:
        _integrity_monitor = IntegrityMonitor()
    return _integrity_monitor