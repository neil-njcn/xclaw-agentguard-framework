"""System Prompt Leak Detector - Detects attempts to obtain system instructions"""
from typing import Dict, List, Optional, Any
from ...base import BaseDetector
from ...detection_result import DetectionResult, ThreatLevel, AttackType, DetectionResultBuilder
from ...config import CommonConfigs
import re
import time


class SystemPromptLeakDetector(BaseDetector):
    """Detects system prompt leak attack attempts"""
    
    DETECTOR_ID = "system_prompt_leak"
    VERSION = "2.0.0"
    
    # High confidence leak probe patterns
    HIGH_CONFIDENCE_PATTERNS = [
        r'repeat\s+(the\s+)?(system\s+)?prompt',
        r'show\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instruction)',
        r'what\s+is\s+your\s+(system\s+)?prompt',
        r'repeat\s+(your\s+)?initial\s+(prompt|instruction)',
        r'display\s+(the\s+)?(system\s+)?(prompt|instruction)',
        r'print\s+(your\s+)?(system\s+)?(prompt|instruction)',
        r'echo\s+(your\s+)?(system\s+)?(prompt|instruction)',
        r'output\s+(your\s+)?(system\s+)?(prompt|instruction)',
        r'reveal\s+(your\s+)?(system\s+)?(prompt|instruction)',
    ]
    
    # Medium confidence leak probe patterns
    MEDIUM_CONFIDENCE_PATTERNS = [
        r'what\s+instruction[s]?\s+were\s+you\s+given',
        r'tell\s+me\s+your\s+(instructions?|rules)',
        r'what\s+are\s+you\s+(programmed|instructed)\s+to\s+do',
        r'describe\s+your\s+(system\s+)?(prompt|instruction)',
        r'share\s+your\s+(system\s+)?(prompt|instruction)',
        r'copy\s+paste\s+your\s+(system\s+)?(prompt|instruction)',
        r'your\s+(system\s+)?prompt\s+please',
        r'what\s+prompt\s+are\s+you\s+using',
        r'base\s+instruction[s]?',
        r'core\s+directive[s]?',
    ]
    
    # Low confidence/fuzzy patterns (for context analysis)
    LOW_CONFIDENCE_PATTERNS = [
        r'how\s+were\s+you\s+trained',
        r'your\s+original\s+instruction[s]?',
        r'default\s+(behavior|mode)',
        r'initial\s+setup',
        r'system\s+configuration',
    ]
    
    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.threshold = self.config.get('threshold', 0.7)
        self.enabled = self.config.get('enabled', True)
        self.context_analysis = self.config.get('context_analysis', True)
    
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
        
        matched_patterns = []
        confidence = 0.0
        
        # Check high confidence patterns
        for pattern in self.HIGH_CONFIDENCE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                matched_patterns.append(('high', pattern))
                confidence = max(confidence, 0.9)
        
        # Check medium confidence patterns
        for pattern in self.MEDIUM_CONFIDENCE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                matched_patterns.append(('medium', pattern))
                confidence = max(confidence, 0.6)
        
        # Check low confidence patterns (only when context analysis is enabled)
        if self.context_analysis:
            low_matches = 0
            for pattern in self.LOW_CONFIDENCE_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    matched_patterns.append(('low', pattern))
                    low_matches += 1
            # Multiple low confidence patterns combined may increase confidence
            if low_matches >= 2:
                confidence = max(confidence, 0.5)
        
        # Check suspicious patterns in context (e.g., repeated questioning)
        if context and self.context_analysis:
            context_confidence = self._analyze_context(context)
            confidence = max(confidence, context_confidence)
        
        elapsed = (time.time() - start_time) * 1000
        
        # Build result using Builder pattern
        builder = DetectionResultBuilder()
        builder.detected(confidence >= self.threshold)
        builder.confidence(confidence)
        builder.metadata(self.DETECTOR_ID, self.VERSION, elapsed)
        
        if confidence >= self.threshold:
            builder.threat_level(ThreatLevel.HIGH if confidence > 0.8 else ThreatLevel.MEDIUM)
            builder.attack_type(AttackType.SYSTEM_PROMPT_LEAK)
            if matched_patterns:
                high_priority = [p for level, p in matched_patterns if level == 'high']
                all_patterns = [p for _, p in matched_patterns]
                builder.patterns(all_patterns)
                builder.snippets([content[:200]])
        else:
            builder.threat_level(ThreatLevel.NONE)
        
        return builder.build()
    
    def _analyze_context(self, context: Dict) -> float:
        """Analyze suspicious patterns in context"""
        confidence = 0.0
        
        # Check for repeated questions in history messages
        history = context.get('history', [])
        leak_attempts = 0
        
        for msg in history[-5:]:  # Check last 5 messages
            if isinstance(msg, dict):
                content = msg.get('content', '')
                # Count suspected leak probe attempts
                for pattern in self.HIGH_CONFIDENCE_PATTERNS + self.MEDIUM_CONFIDENCE_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        leak_attempts += 1
                        break
        
        # Multiple attempts may indicate persistent probing
        if leak_attempts >= 2:
            confidence = max(confidence, 0.4)
        if leak_attempts >= 3:
            confidence = max(confidence, 0.55)
        
        return confidence
    
    def get_detector_id(self) -> str:
        return self.DETECTOR_ID
    
    def get_supported_attack_types(self) -> List[AttackType]:
        return [AttackType.SYSTEM_PROMPT_LEAK]
    
    def get_config_schema(self):
        """Declare configuration schema"""
        from ...config import create_config
        return [
            create_config("threshold", float, "Detection threshold", 0.7, valid_range=(0.0, 1.0)),
            create_config("enabled", bool, "Whether enabled", True),
            create_config("context_analysis", bool, "Enable context analysis to detect persistent probing behavior", True),
        ]


__all__ = ["SystemPromptLeakDetector"]
