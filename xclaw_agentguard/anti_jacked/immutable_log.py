"""
XClaw AgentGuard - Anti-Jacked Security Base
Immutable Log Chain

Provides tamper-evident audit logging using cryptographic chaining.
Each log entry contains the hash of the previous entry, making it
impossible to modify historical records without detection.
"""

import hashlib
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict


@dataclass
class LogEntry:
    """Single immutable log entry"""
    timestamp: str
    sequence: int
    event_type: str
    severity: str
    message: str
    details: Dict[str, Any]
    previous_hash: str
    entry_hash: str
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'LogEntry':
        return cls(**data)
    
    def compute_hash(self) -> str:
        """Compute hash of this entry (excluding entry_hash field)"""
        data = {
            'timestamp': self.timestamp,
            'sequence': self.sequence,
            'event_type': self.event_type,
            'severity': self.severity,
            'message': self.message,
            'details': self.details,
            'previous_hash': self.previous_hash
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


class ImmutableLogChain:
    """
    Immutable Audit Log Chain
    
    Provides append-only, cryptographically chained logging.
    Each entry references the hash of the previous entry,
    making tampering with historical records detectable.
    """
    
    def __init__(self, log_path: str = "logs/audit/immutable_chain.jsonl"):
        self.log_path = log_path
        self._sequence = 0
        self._last_hash = "0" * 64  # Genesis hash
        self._load_existing_chain()
    
    def _load_existing_chain(self):
        """Load existing log chain and verify integrity"""
        if not os.path.exists(self.log_path):
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            return
        
        try:
            with open(self.log_path, 'r') as f:
                lines = f.readlines()
                if not lines:
                    return
                
                last_entry = None
                for i, line in enumerate(lines):
                    entry = LogEntry.from_dict(json.loads(line.strip()))
                    
                    # Verify sequence
                    if entry.sequence != i:
                        raise ValueError(f"Sequence mismatch at line {i}: expected {i}, got {entry.sequence}")
                    
                    # Verify hash chain (skip first entry)
                    if i > 0:
                        expected_prev = last_entry.entry_hash if last_entry else "0" * 64
                        if entry.previous_hash != expected_prev:
                            raise ValueError(f"Hash chain broken at line {i}")
                    
                    # Verify entry hash
                    computed = entry.compute_hash()
                    if computed != entry.entry_hash:
                        raise ValueError(f"Entry hash mismatch at line {i}")
                    
                    last_entry = entry
                
                if last_entry:
                    self._sequence = last_entry.sequence + 1
                    self._last_hash = last_entry.entry_hash
                    
        except Exception as e:
            print(f"Warning: Log chain verification failed: {e}")
            print("Starting new chain...")
            self._sequence = 0
            self._last_hash = "0" * 64
    
    def append(self, event_type: str, severity: str, message: str, 
               details: Optional[Dict] = None) -> LogEntry:
        """
        Append a new entry to the immutable log
        
        Args:
            event_type: Type of event (e.g., 'tamper_detected', 'config_changed')
            severity: Severity level ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
            message: Human-readable message
            details: Additional structured data
            
        Returns:
            The created LogEntry
        """
        entry = LogEntry(
            timestamp=datetime.now().isoformat(),
            sequence=self._sequence,
            event_type=event_type,
            severity=severity,
            message=message,
            details=details or {},
            previous_hash=self._last_hash,
            entry_hash=""  # Will be computed
        )
        
        # Compute and set the entry hash
        entry.entry_hash = entry.compute_hash()
        
        # Append to file
        with open(self.log_path, 'a') as f:
            f.write(json.dumps(entry.to_dict()) + '\n')
        
        # Update chain state
        self._last_hash = entry.entry_hash
        self._sequence += 1
        
        return entry
    
    def verify_chain(self) -> Dict[str, any]:
        """
        Verify the entire log chain integrity
        
        Returns:
            Dict with 'valid', 'entries_count', 'broken_at', 'error'
        """
        if not os.path.exists(self.log_path):
            return {'valid': True, 'entries_count': 0, 'broken_at': None, 'error': None}
        
        try:
            with open(self.log_path, 'r') as f:
                lines = f.readlines()
            
            last_entry = None
            for i, line in enumerate(lines):
                entry = LogEntry.from_dict(json.loads(line.strip()))
                
                # Check sequence
                if entry.sequence != i:
                    return {
                        'valid': False,
                        'entries_count': i,
                        'broken_at': i,
                        'error': f'Sequence mismatch: expected {i}, got {entry.sequence}'
                    }
                
                # Check previous hash (skip genesis)
                if i > 0 and last_entry:
                    if entry.previous_hash != last_entry.entry_hash:
                        return {
                            'valid': False,
                            'entries_count': i,
                            'broken_at': i,
                            'error': f'Hash chain broken at entry {i}'
                        }
                
                # Check entry hash
                computed = entry.compute_hash()
                if computed != entry.entry_hash:
                    return {
                        'valid': False,
                        'entries_count': i,
                        'broken_at': i,
                        'error': f'Hash mismatch at entry {i}'
                    }
                
                last_entry = entry
            
            return {
                'valid': True,
                'entries_count': len(lines),
                'broken_at': None,
                'error': None
            }
            
        except Exception as e:
            return {
                'valid': False,
                'entries_count': 0,
                'broken_at': None,
                'error': str(e)
            }
    
    def get_entries(self, count: Optional[int] = None, 
                   severity: Optional[str] = None) -> List[LogEntry]:
        """Retrieve log entries with optional filtering"""
        if not os.path.exists(self.log_path):
            return []
        
        entries = []
        with open(self.log_path, 'r') as f:
            for line in f:
                entry = LogEntry.from_dict(json.loads(line.strip()))
                if severity and entry.severity != severity:
                    continue
                entries.append(entry)
        
        if count:
            entries = entries[-count:]
        
        return entries
    
    def get_statistics(self) -> Dict:
        """Get log statistics"""
        entries = self.get_entries()
        
        severity_counts = {}
        event_type_counts = {}
        
        for entry in entries:
            severity_counts[entry.severity] = severity_counts.get(entry.severity, 0) + 1
            event_type_counts[entry.event_type] = event_type_counts.get(entry.event_type, 0) + 1
        
        return {
            'total_entries': len(entries),
            'severity_distribution': severity_counts,
            'event_type_distribution': event_type_counts,
            'chain_valid': self.verify_chain()['valid']
        }


# Global instance
_log_chain: Optional[ImmutableLogChain] = None


def get_log_chain() -> ImmutableLogChain:
    """Get or create global immutable log chain"""
    global _log_chain
    if _log_chain is None:
        _log_chain = ImmutableLogChain()
    return _log_chain


def log_event(event_type: str, severity: str, message: str, 
              details: Optional[Dict] = None) -> LogEntry:
    """Convenience function to log an event"""
    return get_log_chain().append(event_type, severity, message, details)