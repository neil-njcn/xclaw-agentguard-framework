"""
XClaw AgentGuard - Anti-Jacked Security Base
Tamper Detection and Alert System

Detects unauthorized modifications to critical files and triggers
multi-channel alerts for security team notification.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict

from .immutable_log import log_event, get_log_chain


@dataclass
class TamperAlert:
    """Tamper detection alert"""
    timestamp: str
    severity: str
    alert_type: str
    file_path: str
    details: Dict
    acknowledged: bool = False
    
    def to_dict(self) -> Dict:
        return asdict(self)


class TamperDetector:
    """
    Tamper Detection and Alert System
    
    Monitors integrity check results and triggers alerts when
    tampering is detected. Supports multi-channel alerting.
    """
    
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    
    def __init__(self):
        self.alert_handlers: List[Callable] = []
        self.alert_history: List[TamperAlert] = []
        self.max_history = 1000
        self._setup_default_handlers()
    
    def _setup_default_handlers(self):
        """Setup default alert handlers"""
        # Console alert handler
        self.register_handler(self._console_alert_handler)
        
        # Immutable log handler
        self.register_handler(self._log_alert_handler)
    
    def _console_alert_handler(self, alert: TamperAlert):
        """Print alert to console"""
        severity_emoji = {
            self.SEVERITY_CRITICAL: "🚨",
            self.SEVERITY_HIGH: "⚠️",
            self.SEVERITY_MEDIUM: "⚡",
            self.SEVERITY_LOW: "ℹ️"
        }
        
        emoji = severity_emoji.get(alert.severity, "⚠️")
        print(f"\n{emoji} TAMPER DETECTED [{alert.severity}] {emoji}")
        print(f"   Time: {alert.timestamp}")
        print(f"   Type: {alert.alert_type}")
        print(f"   File: {alert.file_path}")
        print(f"   Details: {json.dumps(alert.details, indent=2)}")
        print("=" * 60)
    
    def _log_alert_handler(self, alert: TamperAlert):
        """Write alert to immutable log chain"""
        log_event(
            event_type='tamper_detected',
            severity=alert.severity,
            message=f"Tampering detected: {alert.alert_type}",
            details={
                'file_path': alert.file_path,
                'alert_type': alert.alert_type,
                'details': alert.details
            }
        )
    
    def register_handler(self, handler: Callable[[TamperAlert], None]):
        """Register a custom alert handler"""
        self.alert_handlers.append(handler)
    
    def _trigger_alert(self, alert: TamperAlert):
        """Trigger all registered alert handlers"""
        # Add to history
        self.alert_history.append(alert)
        if len(self.alert_history) > self.max_history:
            self.alert_history = self.alert_history[-self.max_history:]
        
        # Trigger handlers
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                print(f"Alert handler error: {e}")
    
    def check_integrity_result(self, result: Dict) -> List[TamperAlert]:
        """
        Process integrity check result and generate alerts
        
        Args:
            result: Output from IntegrityMonitor.check_integrity()
            
        Returns:
            List of generated alerts
        """
        alerts = []
        
        # Check for modified files
        for modified in result.get('modified', []):
            severity = self.SEVERITY_CRITICAL
            
            alert = TamperAlert(
                timestamp=datetime.now().isoformat(),
                severity=severity,
                alert_type='file_modified',
                file_path=modified['path'],
                details={
                    'expected_hash': modified.get('expected_hash'),
                    'actual_hash': modified.get('actual_hash'),
                    'expected_mtime': modified.get('expected_mtime'),
                    'actual_mtime': modified.get('actual_mtime')
                }
            )
            alerts.append(alert)
            self._trigger_alert(alert)
        
        # Check for missing files
        for missing in result.get('missing', []):
            alert = TamperAlert(
                timestamp=datetime.now().isoformat(),
                severity=self.SEVERITY_HIGH,
                alert_type='file_missing',
                file_path=missing['path'],
                details={
                    'baseline_info': missing.get('baseline')
                }
            )
            alerts.append(alert)
            self._trigger_alert(alert)
        
        # Check for errors
        for error in result.get('errors', []):
            alert = TamperAlert(
                timestamp=datetime.now().isoformat(),
                severity=self.SEVERITY_MEDIUM,
                alert_type='check_error',
                file_path=error['path'],
                details={
                    'error': error.get('error')
                }
            )
            alerts.append(alert)
            self._trigger_alert(alert)
        
        return alerts
    
    def get_active_alerts(self, severity: Optional[str] = None) -> List[TamperAlert]:
        """Get active (unacknowledged) alerts"""
        alerts = [a for a in self.alert_history if not a.acknowledged]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        return alerts
    
    def acknowledge_alert(self, index: int) -> bool:
        """Acknowledge an alert by index"""
        if 0 <= index < len(self.alert_history):
            self.alert_history[index].acknowledged = True
            return True
        return False
    
    def get_alert_statistics(self) -> Dict:
        """Get alert statistics"""
        stats = {
            'total_alerts': len(self.alert_history),
            'active_alerts': len([a for a in self.alert_history if not a.acknowledged]),
            'acknowledged_alerts': len([a for a in self.alert_history if a.acknowledged]),
            'by_severity': {}
        }
        
        for alert in self.alert_history:
            sev = alert.severity
            stats['by_severity'][sev] = stats['by_severity'].get(sev, 0) + 1
        
        return stats


# Global instance
_tamper_detector: Optional[TamperDetector] = None


def get_tamper_detector() -> TamperDetector:
    """Get or create global tamper detector"""
    global _tamper_detector
    if _tamper_detector is None:
        _tamper_detector = TamperDetector()
    return _tamper_detector