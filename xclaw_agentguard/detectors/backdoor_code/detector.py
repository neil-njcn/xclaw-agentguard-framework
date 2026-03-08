"""Backdoor Code Detector - Detects backdoors and malicious implants in code"""
from typing import Dict, List, Optional, Any
from ...base import BaseDetector
from ...detection_result import DetectionResult, ThreatLevel, AttackType, DetectionResultBuilder
from ...config import CommonConfigs
import re
import time


class BackdoorCodeDetector(BaseDetector):
    """Detects backdoor attacks in code
    
    Backdoor code attacks implant malicious logic in seemingly normal code,
    allowing attackers to bypass normal authentication, gain unauthorized access, or execute malicious operations.
    """
    
    DETECTOR_ID = "backdoor_code"
    VERSION = "2.0.0"
    
    # High confidence backdoor patterns
    HIGH_CONFIDENCE_PATTERNS = [
        # Remote shell/command execution
        r'(?:eval|exec|system|subprocess\.call|os\.system)\s*\(\s*(?:base64|b64decode|decode)',
        r'__import__\s*\(\s*[\'"]os[\'"]\s*\)\s*\.\s*system',
        r'compile\s*\(\s*(?:base64|b64decode)',
        # Reverse shell
        r'socket\s*\.\s*socket\s*\(\s*\)\s*.*\.\s*connect\s*\(\s*[\'"]\d+\.\d+\.\d+\.\d+[\'"]',
        r'subprocess\.Popen\s*\(\s*[\'"]/bin/sh[\'"]\s*,.*stdin.*stdout.*socket',
        r'pty\.spawn\s*\(\s*[\'"]/bin/sh[\'"]\s*\)',
        # Dynamic code execution
        r'eval\s*\(\s*__import__\s*\(\s*[\'"]base64[\'"]',
        r'exec\s*\(\s*globals\s*\(\s*\)\s*\[',
        # Hardcoded credentials
        r'(?:password|passwd|pwd|secret|key|token)\s*=\s*[\'"][^\'"]{8,}[\'"]\s*#\s*(?:backdoor|admin|root)',
    ]
    
    # Medium confidence backdoor patterns
    MEDIUM_CONFIDENCE_PATTERNS = [
        # Suspicious network connections
        r'urllib\.request\.urlopen\s*\(\s*[\'"]https?://[^\'"]+[\'"]\s*\)',
        r'requests\.(?:get|post)\s*\(\s*[\'"]https?://\d+\.\d+\.\d+\.\d+',
        # Code obfuscation
        r'\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}',
        r'chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\(\s*\d+\s*\)',
        # Dynamic imports
        r'__import__\s*\(\s*(?:base64|zlib|marshal)',
        r'importlib\.import_module\s*\(\s*(?:base64|decode)',
        # Time bomb/logic bomb
        r'datetime\.now\s*\(\s*\)\s*.*==\s*[\'"]\d{4}',
        r'if\s+.*\d{4}-\d{2}-\d{2}.*:\s*\n\s*(?:os\.|subprocess\.|eval\(|exec\()',
    ]
    
    # Low confidence/suspicious patterns
    LOW_CONFIDENCE_PATTERNS = [
        r'base64\.b64decode',
        r'zlib\.decompress',
        r'marshal\.loads',
        r'pickle\.loads\s*\(\s*(?:base64|decode)',
        r'exec\s*\(',
        r'eval\s*\(',
    ]
    
    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.threshold = self.config.get('threshold', 0.7)
        self.enabled = self.config.get('enabled', True)
        self.check_obfuscation = self.config.get('check_obfuscation', True)
    
    def detect(self, content: str, context: Optional[Dict] = None) -> DetectionResult:
        """Execute backdoor code detection
        
        Args:
            content: Code content to detect
            context: Optional context information
            
        Returns:
            DetectionResult: Detection result
        """
        start_time = time.time()
        
        if not self.enabled:
            return DetectionResultBuilder()\
                .detected(False)\
                .threat_level(ThreatLevel.LOW)\
                .confidence(1.0)\
                .metadata(self.DETECTOR_ID, self.VERSION, 0.0)\
                .build()
        
        matched_patterns = []
        confidence = 0.0
        snippets = []
        
        # Check high confidence patterns
        for pattern in self.HIGH_CONFIDENCE_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
            if match:
                matched_patterns.append(pattern)
                confidence = max(confidence, 0.95)
                snippets.append(match.group(0)[:150])
        
        # Check medium confidence patterns
        for pattern in self.MEDIUM_CONFIDENCE_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
            if match:
                matched_patterns.append(pattern)
                confidence = max(confidence, 0.7)
                snippets.append(match.group(0)[:150])
        
        # Check low confidence patterns (effective when accumulated)
        low_matches = 0
        for pattern in self.LOW_CONFIDENCE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                low_matches += 1
                matched_patterns.append(pattern)
        
        # Multiple low confidence patterns combined can increase confidence
        if low_matches >= 3:
            confidence = max(confidence, 0.55)
        elif low_matches >= 2:
            confidence = max(confidence, 0.4)
        
        # Obfuscation detection (additional heuristic)
        if self.check_obfuscation:
            obfuscation_score = self._check_obfuscation(content)
            if obfuscation_score > 0:
                confidence = max(confidence, obfuscation_score)
                matched_patterns.append("obfuscation_detected")
        
        elapsed = (time.time() - start_time) * 1000
        
        # Build result using Builder pattern
        builder = DetectionResultBuilder()
        builder.detected(confidence >= self.threshold)
        builder.confidence(confidence)
        builder.metadata(self.DETECTOR_ID, self.VERSION, elapsed)
        
        if confidence >= self.threshold:
            # Backdoor code attacks default to CRITICAL level
            builder.threat_level(ThreatLevel.CRITICAL if confidence > 0.8 else ThreatLevel.HIGH)
            builder.attack_type(AttackType.TOOL_ABUSE)  # Backdoor code is tool/code abuse
            
            if matched_patterns:
                builder.patterns(matched_patterns)
            if snippets:
                builder.snippets(snippets)
        else:
            builder.threat_level(ThreatLevel.NONE)
        
        return builder.build()
    
    def _check_obfuscation(self, content: str) -> float:
        """Detect code obfuscation techniques
        
        Returns:
            float: Threat score (0.0-0.7)
        """
        score = 0.0
        
        # Long string base64 detection
        long_b64_pattern = r'[A-Za-z0-9+/]{100,}={0,2}'
        if re.search(long_b64_pattern, content):
            score = max(score, 0.5)
        
        # Hex encoding detection
        hex_pattern = r'\\x[0-9a-fA-F]{2}'
        hex_matches = len(re.findall(hex_pattern, content))
        if hex_matches > 20:
            score = max(score, 0.6)
        elif hex_matches > 10:
            score = max(score, 0.4)
        
        # Multiple nested decoding
        nested_decode = len(re.findall(r'decode\s*\(\s*.*decode\s*\(', content, re.IGNORECASE))
        if nested_decode > 0:
            score = max(score, 0.7)
        
        # Abnormal variable names (common obfuscation feature)
        obf_vars = len(re.findall(r'\b_[Oo0]{3,}\b|\b[lI1]{5,}\b|\b[a-zA-Z]{20,}\b', content))
        if obf_vars > 3:
            score = max(score, 0.3)
        
        return score
    
    def get_detector_id(self) -> str:
        return self.DETECTOR_ID
    
    def get_supported_attack_types(self) -> List[AttackType]:
        return [AttackType.TOOL_ABUSE]
    
    def get_config_schema(self):
        """Declare configuration schema"""
        from ...config import create_config
        return [
            create_config("threshold", float, "Detection threshold", 0.7, valid_range=(0.0, 1.0)),
            create_config("enabled", bool, "Whether enabled", True),
        ]


__all__ = ["BackdoorCodeDetector"]
