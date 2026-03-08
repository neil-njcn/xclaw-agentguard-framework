"""路径遍历检测器"""
from typing import Dict, List, Optional
from ...base import BaseDetector
from ...detection_result import DetectionResult, ThreatLevel, AttackType, DetectionResultBuilder
import re, time

class PathTraversalDetector(BaseDetector):
    DETECTOR_ID = "path_traversal"
    VERSION = "2.0.1"
    
    HIGH_CONFIDENCE_PATTERNS = [
        r'\.\.[/\\]+.*(?:etc/passwd|etc/shadow|etc/hosts|\.\.\.ini)',
        r'\.\.[/\\]+.*(?:windows/system32|win\.ini|boot\.ini|system\.ini)',
        r'\.\.[/\\]+.*(?:config\.xml|web\.config|\.env|\.git)',
        r'(?:\.\.[/\\]){4,}', r'%00|\x00|%00\.',
        r'(?:%2e%2e|%252e%252e|%%32%65).*[/\\]+.*(?:passwd|shadow|\.ini)',
        r'(?:%c0%af|%e0%80%af|%c1%1c|%c0%5c|%c1%9c)',
    ]
    MEDIUM_CONFIDENCE_PATTERNS = [
        r'(?:\.\.[/\\]){2,3}',
        r'%2e%2e[/\\%]|%252e%252e|%%32%65%%32%65', r'\.%2e|%2e\.|%252e',
        r'\.%c0%af|\.%e0%80%af', r'\.\.\.\.[/\\]+|\.\.\.\.//|\.\.\.\\\\',
        r'^(?:/|\\\\|\\\\)[a-z]+/(?:etc|var|home|root|usr|opt|bin)',
        r'^[a-zA-Z]:[/\\]+(?:windows|program|users|system)',
        r'\.\.[\\/]*.*\.(?:conf|config|ini|xml|json|yaml|yml|env|key|pem)$',
    ]
    LOW_CONFIDENCE_PATTERNS = [
        r'\.\.[/\\]', r'(?:passwd|shadow|hosts|\.env|id_rsa|authorized_keys)',
        r'\\x00|%00|%0d|%0a',
    ]
    SENSITIVE_FILES = [
        'passwd', 'shadow', 'group', 'hosts', 'id_rsa', 'id_dsa', 'id_ecdsa',
        'authorized_keys', '.env', '.htaccess', 'web.config', 'win.ini',
        'boot.ini', 'system.ini', 'sam', 'security', 'config.xml', 'config.json',
        '.git', '.svn', 'wp-config.php',
    ]
    SENSITIVE_DIRECTORIES = [
        '/etc/', '/var/', '/home/', '/root/', '/proc/', '/sys/',
        'C:/Windows/', 'C:/Program Files/', 'C:/Users/',
        '/var/www/', '/var/log/',
    ]
    
    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.threshold = self.config.get('threshold', 0.7)
        self.enabled = self.config.get('enabled', True)
        self.max_content_length = self.config.get('max_content_length', 10000)
        self.block_sensitive_files = self.config.get('block_sensitive_files', True)
        self.detect_absolute_paths = self.config.get('detect_absolute_paths', True)
    
    def detect(self, content: str, context: Optional[Dict] = None) -> DetectionResult:
        start_time = time.time()
        if not self.enabled:
            return DetectionResultBuilder().detected(False).threat_level(ThreatLevel.NONE)\
                .confidence(1.0).metadata(self.DETECTOR_ID, self.VERSION, 0.0).build()
        if len(content) > self.max_content_length:
            content = content[:self.max_content_length]
        
        matched_patterns, confidence, snippets, iocs = [], 0.0, [], []
        
        # Check for path traversal patterns (../ or ..\)
        has_traversal = re.search(r'\.\.[\\/]', content) is not None
        
        for pattern in self.HIGH_CONFIDENCE_PATTERNS:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                matched_patterns.append(pattern)
                confidence = max(confidence, 0.95)
                for m in matches[:2]:
                    snippets.append(content[max(0, m.start()-30):min(len(content), m.end()+30)])
        
        for pattern in self.MEDIUM_CONFIDENCE_PATTERNS:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                matched_patterns.append(pattern)
                confidence = max(confidence, 0.75)
                for m in matches[:1]:
                    snippet = content[max(0, m.start()-25):min(len(content), m.end()+25)]
                    if snippet not in snippets: snippets.append(snippet)
        
        low_count = sum(1 for p in self.LOW_CONFIDENCE_PATTERNS if re.search(p, content, re.IGNORECASE))
        if low_count >= 2: confidence = max(confidence, 0.5)
        
        if self.block_sensitive_files:
            for sf in self.SENSITIVE_FILES:
                if re.search(rf'\b{sf}\b', content, re.IGNORECASE):
                    # Only high confidence if combined with traversal
                    if has_traversal:
                        confidence = max(confidence, 0.9)
                        matched_patterns.append(f"sensitive_with_traversal:{sf}")
                        iocs.append(sf)
                    # Low confidence for sensitive files alone
                    elif confidence < 0.6:
                        confidence = max(confidence, 0.3)
        
        # Only flag absolute paths to sensitive directories if combined with traversal
        # or explicit sensitive file access
        if self.detect_absolute_paths and has_traversal:
            for sd in self.SENSITIVE_DIRECTORIES:
                if re.search(re.escape(sd), content, re.IGNORECASE):
                    confidence = max(confidence, 0.8)
                    matched_patterns.append(f"sensitive_dir:{sd}")
                    iocs.append(sd.rstrip('/'))
        
        if self._has_nested_encoding(content):
            confidence = max(confidence, 0.85)
            matched_patterns.append("nested_encoding")
        
        elapsed = (time.time() - start_time) * 1000
        builder = DetectionResultBuilder()
        builder.detected(confidence >= self.threshold).confidence(min(confidence, 1.0))
        builder.metadata(self.DETECTOR_ID, self.VERSION, elapsed)
        builder.patterns(matched_patterns).snippets(snippets[:3]).iocs(iocs)
        
        if confidence >= self.threshold:
            builder.threat_level(ThreatLevel.CRITICAL if confidence >= 0.9 else ThreatLevel.HIGH if confidence >= 0.75 else ThreatLevel.MEDIUM)
            builder.attack_type(AttackType.TOOL_ABUSE)
        else: builder.threat_level(ThreatLevel.NONE)
        return builder.build()
    
    def _has_nested_encoding(self, content: str) -> bool:
        return bool(re.search(r'%25[0-9a-fA-F]{2}|%%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}', content))
    
    def get_detector_id(self) -> str: return self.DETECTOR_ID
    def get_supported_attack_types(self) -> List[AttackType]: return [AttackType.TOOL_ABUSE]
    def get_config_schema(self):
        from ...config import create_config
        return [
            create_config("threshold", float, "检测阈值", 0.7, valid_range=(0.0, 1.0)),
            create_config("enabled", bool, "是否启用", True),
            create_config("max_content_length", int, "最大内容长度", 10000),
            create_config("block_sensitive_files", bool, "检测敏感文件", True),
            create_config("detect_absolute_paths", bool, "检测绝对路径", True),
        ]
    def validate_config(self, config: Dict) -> bool:
        if not super().validate_config(config): return False
        threshold = config.get('threshold', 0.7)
        if not 0.0 <= threshold <= 1.0: return False
        max_len = config.get('max_content_length', 10000)
        if not 100 <= max_len <= 100000: return False
        return True

__all__ = ["PathTraversalDetector"]
