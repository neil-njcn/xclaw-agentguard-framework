"""
XClaw AgentGuard - Anti-Jacked Integration

Integrates the Anti-Jacked security base with the existing detection framework.
Provides seamless security monitoring alongside threat detection.
"""

from typing import Optional
from .anti_jacked import (
    get_integrity_monitor,
    get_tamper_detector,
    get_log_chain,
    IntegrityMonitor
)
from .detection_result import DetectionResult, ThreatLevel, DetectionResultBuilder


class SecurityContext:
    """
    Security context that integrates Anti-Jacked with detection framework
    
    This class provides a unified interface for:
    - Running detections with integrity verification
    - Checking system security state before operations
    - Logging security events to immutable chain
    """
    
    def __init__(self):
        self.integrity_monitor = get_integrity_monitor()
        self.tamper_detector = get_tamper_detector()
        self.log_chain = get_log_chain()
        self._initialized = False
    
    def initialize(self, watch_directories: Optional[list] = None):
        """
        Initialize security monitoring
        
        Args:
            watch_directories: Directories to monitor for integrity
        """
        if self._initialized:
            return
        
        # Set up default watch directories
        if watch_directories is None:
            watch_directories = [
                "xclaw_agentguard/core",
                "xclaw_agentguard/detectors",
                "xclaw_agentguard/config",
                "xclaw_agentguard/plugins"
            ]
        
        # Add watches
        for directory in watch_directories:
            self.integrity_monitor.add_watch_directory(directory, '*.py')
            self.integrity_monitor.add_watch_directory(directory, '*.json')
        
        self._initialized = True
    
    def check_system_integrity(self) -> DetectionResult:
        """
        Check system integrity and return as DetectionResult
        
        Returns:
            DetectionResult indicating if system is tampered
        """
        if not self._initialized:
            self.initialize()
        
        result = self.integrity_monitor.check_integrity()
        
        # Check if any tampering detected
        if result['modified'] or result['missing']:
            # Process through tamper detector
            alerts = self.tamper_detector.check_integrity_result(result)
            
            return DetectionResultBuilder()\
                .detected(True)\
                .threat_level(ThreatLevel.CRITICAL)\
                .confidence(1.0)\
                .metadata("anti_jacked", "system_integrity", 100.0,
                        alerts=[a.to_dict() for a in alerts],
                        modified_count=len(result['modified']),
                        missing_count=len(result['missing']))\
                .build()
        
        return DetectionResultBuilder()\
            .detected(False)\
            .threat_level(ThreatLevel.NONE)\
            .metadata("anti_jacked", "system_integrity", 100.0,
                    verified_count=len(result['verified']))\
            .build()
    
    def is_system_secure(self) -> bool:
        """Quick check if system is secure (no tampering detected)"""
        if not self._initialized:
            self.initialize()
        
        result = self.integrity_monitor.check_integrity()
        return len(result['modified']) == 0 and len(result['missing']) == 0
    
    def verify_before_detection(self) -> bool:
        """
        Verify system integrity before running detection
        
        Returns:
            True if system is secure, False if tampered
        """
        if not self.is_system_secure():
            # Log the security violation
            self.log_chain.append(
                event_type='detection_blocked',
                severity='CRITICAL',
                message='Detection blocked due to system integrity violation',
                details={'action': 'blocked_detection'}
            )
            return False
        return True


# Global security context instance
_security_context: Optional[SecurityContext] = None


def get_security_context() -> SecurityContext:
    """Get or create global security context"""
    global _security_context
    if _security_context is None:
        _security_context = SecurityContext()
    return _security_context


def check_integrity_before_detection(func):
    """
    Decorator to check system integrity before running detection
    
    Usage:
        @check_integrity_before_detection
        def detect(self, content):
            # Detection logic
            pass
    """
    def wrapper(*args, **kwargs):
        context = get_security_context()
        if not context.verify_before_detection():
            # Return critical alert instead of running detection
            from .detection_result import DetectionResultBuilder, ThreatLevel
            return DetectionResultBuilder()\
                .detected(True)\
                .threat_level(ThreatLevel.CRITICAL)\
                .confidence(1.0)\
                .metadata("anti_jacked", "integrity_check", 100.0,
                        error="System integrity compromised")\
                .build()
        return func(*args, **kwargs)
    return wrapper