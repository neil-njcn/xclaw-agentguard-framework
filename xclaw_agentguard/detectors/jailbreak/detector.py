"""Jailbreak Attack Detector - Detects attempts to bypass safety restrictions"""
from typing import Dict, List, Optional, Any
from ...base import BaseDetector
from ...detection_result import DetectionResult, ThreatLevel, AttackType, DetectionResultBuilder
from ...config import CommonConfigs
import re
import time


class JailbreakDetector(BaseDetector):
    """Detects jailbreak attack attempts - bypassing model safety restrictions"""
    
    DETECTOR_ID = "jailbreak"
    VERSION = "2.0.0"
    
    # High confidence jailbreak patterns
    HIGH_CONFIDENCE_PATTERNS = [
        # DAN mode and variants (English)
        r'Do\s+Anything\s+Now|DAN\s*mode|DAN\s*prompt',
        r'Jailbreak\s*mode|Developer\s*Mode|Developer\s*mode\s*enabled',
        # Roleplay bypass (English)
        r'you\s+are\s+in\s+developer\s+mode',
        r'simulate\s+being\s+an?\s+\w+\s+without\s+(ethical|moral|safety)\s+(guidelines|constraints|limitations)',
        r'you\s+are\s+an?\s+\w+\s+from\s+\d{4,}\s+where\s+\w+\s+is\s+legal',
        # Hypothetical bypass (English)
        r'hypothetically\s+speaking.*?(how\s+to|instructions?\s+for|steps?\s+to)\s+\w+',
        r'in\s+a\s+hypothetical\s+scenario.*?(create|make|build|synthesize)',
        # Academic research bypass (English)
        r'for\s+educational\s+purposes\s+only.*?(how\s+to|create|make)',
        r'academic\s+research.*?(ignore|bypass|disregard)\s+(safety|ethical)',
        # Chinese patterns - DAN and variants
        r'(?:进入|启用|开启)(?:DAN|开发者|开发|调试|debug)模式',
        r'越狱(?:模式)?',
        # Chinese patterns - Roleplay bypass
        r'你(?:现在)?处于(?:开发者|开发|调试)模式',
        r'假装你是?(?:一个)?(?:没有|不受)(?:道德|伦理|安全)(?:约束|限制|规范)',
        r'你(?:是|扮演)(?:一个)?来自\d{4,}年(?:的\w+)?',
        # Chinese patterns - Hypothetical bypass
        r'假设性地说.*?(如何|怎样|步骤)',
        r'在假设场景.*?(创建|制作|生成)',
        # Chinese patterns - Academic bypass
        r'仅(?:用于|供)(?:教育|学术|研究)目的.*?(如何|怎样|创建|制作)',
        r'学术研究.*?(忽略|绕过|无视)(?:安全|伦理)',
    ]
    
    # Medium confidence jailbreak patterns
    MEDIUM_CONFIDENCE_PATTERNS = [
        # Fictional scenarios (English)
        r'let\'s\s+pretend\s+we\s+are\s+in\s+a\s+movie|this\s+is\s+just\s+fiction',
        r'for\s+a\s+story\s+i\'m\s+writing.*?(how\s+to|create|make)',
        r'imagine\s+a\s+world\s+where.*?(legal|allowed|permitted)',
        # Encoding/obfuscation attempts (English)
        r'base64\s*:?\s*[A-Za-z0-9+/]{20,}=?',
        r'rot13\s*:?\s*\w+',
        # Social engineering techniques (English)
        r'grandma\s+(trick|exploit|method)',
        r'my\s+dead\s+\w+\s+used\s+to\s+(tell\s+me\s+about|make)',
        # Emergency/special case bypass (English)
        r'time\s+sensitive|urgent\s+emergency|life\s+or\s+death',
        r'begin\s+with\s+"sure\s*,?\s*here\s+is"',
        # Chinese patterns - Fictional scenarios
        r'假设我们(?:在|正在|是在)(?:电影|小说|故事)',
        r'这(?:只是|是)(?:虚构|假的|故事)',
        r'我在写(?:一个)?故事.*?(如何|怎样|创建|制作)',
        r'想象(?:一个)?世界.*?(合法|允许|可以)',
        # Chinese patterns - Social engineering
        r'奶奶(?:的)?(?:技巧|方法|窍门)',
        r'我(?:已故|去世)的\w+(?:曾经|以前)',
        # Chinese patterns - Emergency bypass
        r'时间紧迫|紧急|生死攸关|人命关天',
        r'以[""]?(?:当然|好的|没问题)[""]?开头',
    ]
    
    # Low confidence/suspicious patterns
    LOW_CONFIDENCE_PATTERNS = [
        r'ignore\s+your\s+(programming|training|guidelines)',
        r'you\s+can\s+\w+\s+because\s+i\s+(allow|permit|authorize)',
        r'you\s+are\s+not\s+bound\s+by\s+(rules|guidelines|ethics)',
        r'respond\s+as\s+if\s+you\s+have\s+no\s+(filters|restrictions)',
    ]
    
    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.threshold = self.config.get('threshold', 0.7)
        self.enabled = self.config.get('enabled', True)
    
    def detect(self, content: str, context: Optional[Dict] = None) -> DetectionResult:
        """Execute jailbreak detection"""
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
        threat_level = ThreatLevel.LOW
        
        # Check high confidence patterns
        for pattern in self.HIGH_CONFIDENCE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                matched_patterns.append(('high', pattern))
                confidence = max(confidence, 0.9)
                threat_level = ThreatLevel.CRITICAL
        
        # Check medium confidence patterns
        for pattern in self.MEDIUM_CONFIDENCE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                matched_patterns.append(('medium', pattern))
                confidence = max(confidence, 0.6)
                if threat_level == ThreatLevel.LOW:
                    threat_level = ThreatLevel.HIGH
        
        # Check low confidence patterns
        for pattern in self.LOW_CONFIDENCE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                matched_patterns.append(('low', pattern))
                confidence = max(confidence, 0.4)
                if threat_level == ThreatLevel.LOW:
                    threat_level = ThreatLevel.MEDIUM
        
        # Context risk accumulation
        if context:
            # Check if there's a history of repeated attempts
            history = context.get('detection_history', [])
            jailbreak_attempts = sum(1 for h in history if h.get('attack_type') == 'jailbreak')
            if jailbreak_attempts > 2:
                confidence = min(1.0, confidence + 0.2)
            
            # Check if it's a suspicious pattern in multi-turn conversation
            if context.get('conversation_turns', 0) > 3:
                # Jailbreak attempts that suddenly appear in long conversations are more suspicious
                if confidence > 0.5:
                    confidence = min(1.0, confidence + 0.1)
        
        elapsed = (time.time() - start_time) * 1000
        
        # Build result
        builder = DetectionResultBuilder()
        is_detected = confidence >= self.threshold
        builder.detected(is_detected)
        builder.confidence(confidence)
        builder.metadata(self.DETECTOR_ID, self.VERSION, elapsed)
        
        if is_detected:
            builder.threat_level(threat_level)
            builder.attack_type(AttackType.JAILBREAK)
            if matched_patterns:
                builder.patterns([p[1] for p in matched_patterns])
                builder.snippets([content[:300]])
        else:
            builder.threat_level(ThreatLevel.NONE)
        
        return builder.build()
    
    def get_detector_id(self) -> str:
        return self.DETECTOR_ID
    
    def get_supported_attack_types(self) -> List[AttackType]:
        return [AttackType.JAILBREAK]
    
    def get_config_schema(self):
        """Declare configuration schema"""
        from ...config import create_config
        return [
            create_config("threshold", float, "Detection threshold", 0.7, valid_range=(0.0, 1.0)),
            create_config("enabled", bool, "Whether enabled", True),
        ]


__all__ = ["JailbreakDetector"]
