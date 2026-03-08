"""
XClaw AgentGuard - Anti-Jacked Security Base

Provides protection against CVE-2026-25253 and similar agent hijacking attacks.
This is the core security foundation for AgentGuard v2.3.0.

Components:
- File Integrity Monitoring (SHA256-based)
- Immutable Log Chain (tamper-evident audit logging)
- Tamper Detection and Alerting
- Auto-Recovery Mechanism

Usage:
    from xclaw_agentguard.anti_jacked import (
        IntegrityMonitor,
        ImmutableLogChain,
        TamperDetector,
        AutoRecovery
    )
    
    # Initialize integrity monitoring
    monitor = IntegrityMonitor()
    monitor.add_watch_directory("xclaw_agentguard/core")
    monitor.generate_baseline(["xclaw_agentguard"])
    
    # Start continuous monitoring
    monitor.start_monitoring(interval=300)  # Check every 5 minutes
"""

from .integrity_monitor import IntegrityMonitor, get_integrity_monitor
from .immutable_log import ImmutableLogChain, LogEntry, get_log_chain, log_event
from .tamper_detector import TamperDetector, TamperAlert, get_tamper_detector
from .auto_recovery import AutoRecovery, get_auto_recovery

__all__ = [
    # Core components
    'IntegrityMonitor',
    'ImmutableLogChain',
    'TamperDetector',
    'AutoRecovery',
    
    # Data classes
    'LogEntry',
    'TamperAlert',
    
    # Global instances
    'get_integrity_monitor',
    'get_log_chain',
    'get_tamper_detector',
    'get_auto_recovery',
    'log_event',
]

__version__ = '1.0.0'
__author__ = 'XClaw AgentGuard Team'