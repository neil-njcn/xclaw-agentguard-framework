"""Data Exfiltration Detector - Detects attempts to exfiltrate sensitive data"""
from typing import Dict, List, Optional, Any
from ...base import BaseDetector
from ...detection_result import DetectionResult, ThreatLevel, AttackType, DetectionResultBuilder
from ...config import ConfigSchema, CommonConfigs
import re
import time


class ExfiltrationGuard(BaseDetector):
    """Detects data exfiltration attacks"""
    
    DETECTOR_ID = "exfiltration_guard"
    VERSION = "2.0.0"
    
    # High confidence exfiltration patterns
    HIGH_CONFIDENCE_PATTERNS = [
        r'send\s+(?:me\s+)?(?:the\s+)?.*?\s*(?:data|info|information|credentials|passwords?|keys?)\s+(?:to\s+)?(?:email|telegram|discord|slack|url|http)',
        r'export\s+(?:all\s+)?(?:user|customer|client)\s+(?:data|info|emails?)',
        r'upload\s+(?:the\s+)?(?:data|files?|info)\s+(?:to\s+)?(?:external|remote|cloud)',
        r'transfer\s+(?:all\s+)?(?:data|records?)\s+(?:to\s+)?(?:my\s+)?(?:server|database|storage)',
        r'exfiltrat(?:e|ion)\s+.*?\s*(?:data|information)',
        r'dump\s+(?:the\s+)?(?:database|data|records?)',
        r'leak\s+(?:the\s+)?(?:data|information|secrets?)',
    ]
    
    # Medium confidence suspicious patterns
    MEDIUM_CONFIDENCE_PATTERNS = [
        r'copy\s+(?:all\s+)?(?:the\s+)?(?:user\s+)?(?:data|list)',
        r'download\s+(?:user|customer)\s+(?:list|database)',
        r'save\s+(?:the\s+)?(?:output|results?|data)\s+(?:to\s+)?(?:file|disk|local)',
        r'write\s+(?:this\s+)?(?:to\s+)?(?:a\s+)?file',
        r'output\s+(?:as\s+)?(?:csv|json|xml|sql)',
        r'extract\s+(?:all\s+)?(?:user\s+)?(?:data|records?)',
    ]
    
    # Sensitive data type patterns
    SENSITIVE_DATA_PATTERNS = [
        r'\b\d{16}\b',  # Credit card number
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN format
        r'password\s*[=:]\s*\S+',
        r'api[_-]?key\s*[=:]\s*\S+',
        r'secret\s*[=:]\s*\S+',
        r'token\s*[=:]\s*[a-zA-Z0-9_-]{20,}',
    ]
    
    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.threshold = self.config.get('threshold', 0.7)
        self.enabled = self.config.get('enabled', True)
        self.check_sensitive_data = self.config.get('check_sensitive_data', True)
        self.max_content_length = self.config.get('max_content_length', 100000)
    
    def detect(self, content: str, context: Optional[Dict] = None) -> DetectionResult:
        """Execute detection"""
        start_time = time.time()
        
        if not self.enabled:
            return DetectionResultBuilder()\
                .detected(False)\
                .threat_level(ThreatLevel.NONE)\
                .confidence(1.0)\
                .metadata(self.DETECTOR_ID, self.VERSION, 0.0)\
                .build()
        
        # Content length check
        if len(content) > self.max_content_length:
            content = content[:self.max_content_length]
        
        matched_patterns = []
        confidence = 0.0
        extracted_iocs = []
        
        # Check high confidence exfiltration patterns
        for pattern in self.HIGH_CONFIDENCE_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                matched_patterns.append(pattern)
                extracted_iocs.append(match.group(0)[:100])
                confidence = max(confidence, 0.9)
        
        # Check medium confidence patterns
        for pattern in self.MEDIUM_CONFIDENCE_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                matched_patterns.append(pattern)
                extracted_iocs.append(match.group(0)[:100])
                confidence = max(confidence, 0.6)
        
        # Check sensitive data leakage (if enabled)
        if self.check_sensitive_data:
            for pattern in self.SENSITIVE_DATA_PATTERNS:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                match_count = sum(1 for _ in matches)
                if match_count > 0:
                    matched_patterns.append(f"sensitive_data:{pattern[:30]}...")
                    # Sensitive data increases confidence, adjusted by quantity
                    data_confidence = min(0.5 + (match_count * 0.1), 0.85)
                    confidence = max(confidence, data_confidence)
        
        elapsed = (time.time() - start_time) * 1000
        
        # Build result using Builder pattern
        builder = DetectionResultBuilder()
        builder.detected(confidence >= self.threshold)
        builder.confidence(confidence)
        builder.metadata(self.DETECTOR_ID, self.VERSION, elapsed)
        
        if confidence >= self.threshold:
            # Determine threat level based on confidence
            if confidence > 0.85:
                builder.threat_level(ThreatLevel.CRITICAL)
            elif confidence > 0.7:
                builder.threat_level(ThreatLevel.HIGH)
            else:
                builder.threat_level(ThreatLevel.MEDIUM)
            
            builder.attack_type(AttackType.DATA_EXTRACTION)
            
            if matched_patterns:
                builder.patterns(matched_patterns)
            if extracted_iocs:
                builder.iocs(extracted_iocs)
            if content[:200]:
                builder.snippet(content[:200])
        else:
            builder.threat_level(ThreatLevel.NONE)
        
        return builder.build()
    
    def get_detector_id(self) -> str:
        return self.DETECTOR_ID
    
    def get_supported_attack_types(self) -> List[AttackType]:
        return [AttackType.DATA_EXTRACTION]
    
    def get_config_schema(self):
        from ...config import create_config
        return [
            create_config("threshold", float, "Detection threshold", 0.7, valid_range=(0.0, 1.0)),
            create_config("enabled", bool, "Whether enabled", True),
            create_config("check_sensitive_data", bool, "Check sensitive data", True),
            create_config("max_content_length", int, "Maximum content length", 100000, valid_range=(1000, 1000000)),
        ]


__all__ = ["ExfiltrationGuard"]
