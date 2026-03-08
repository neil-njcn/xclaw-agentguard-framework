"""Agent Hijacking Detector - Detects attacks that attempt to hijack Agent/LLM agents"""
from typing import Dict, List, Optional, Any
from ...base import BaseDetector
from ...detection_result import DetectionResult, ThreatLevel, AttackType, DetectionResultBuilder
from ...config import ConfigSchema, CommonConfigs, create_config
import re
import time


class AgentHijackingDetector(BaseDetector):
    """Detects agent hijacking attacks
    
    Agent hijacking attacks attempt to manipulate AI agent behavior, permissions, or goals,
    making them execute attacker intent rather than legitimate user requests.
    
    TODO (v3.0): Integrate Semantic Recognition Layer
    --------------------------
    Current regex-based detection has bypass possibilities; planning to introduce semantic analysis:
    
    1. Intent classification model - Identify attack intents like privilege escalation, goal redirection
    2. Context consistency check - Detect anomalous deviations from historical conversation
    3. Multi-round attack chain analysis - Discover gradual manipulation patterns
    
    ⚠️ Semantic Recognition Security Risks (CRITICAL)
    --------------------------------
    - Prompt attacks: Attackers may manipulate semantic model output through carefully crafted input
    - Model bypass: Adversarial sample attacks targeting semantic classifiers
    - Manipulation/poisoning: Training data contamination leading to false positives or negatives
    - Self-referential risk: Semantic model itself may become attack target
    
    Must complete before implementation:
    - Semantic model input validation and isolation
    - Adversarial testing suite (red team validation)
    - Model decision interpretability mechanism
    - Degradation strategy (fallback when semantic layer fails)
    """
    
    DETECTOR_ID = "agent_hijacking"
    VERSION = "2.0.0"
    
    # High confidence hijacking patterns
    HIGH_CONFIDENCE_PATTERNS = [
        # Privilege escalation attempts (English)
        r'you\s+are\s+now\s+(an?\s+)?(admin|administrator|root|superuser)',
        r'act\s+as\s+(the\s+)?system\s+(admin|administrator)',
        r'switch\s+to\s+(admin|root|privileged)\s+mode',
        # Goal redirection - enhanced coverage (English)
        r'your\s+(new\s+)?(goal|objective|mission|purpose)\s+is\s*:?\s*',
        r'your\s+(goal|objective|mission|purpose)\s+has\s+been\s+updated\s+(to|as)',
        r'from\s+now\s+on\s*,?\s*you\s+(will\s+)?(only\s+)?(do|follow|obey)',
        r'override\s+your\s+(core|primary|original)\s+(directive|goal|purpose)',
        # System prompt override - new (English)
        r'your\s+system\s+prompt\s+(is\s+now|has\s+been)',
        r'update\s+your\s+(instructions|prompt|directive)',
        # Role replacement (English)
        r'you\s+are\s+no\s+longer\s+.*?\s*,?\s*you\s+are\s+now',
        r'replace\s+your\s+(persona|identity|role)\s+with',
        # Chinese patterns - Privilege escalation
        r'你(?:现在)?是(?:一个)?(?:管理员|超级用户|root|admin)',
        r'切换(?:到)?(?:管理员|root|特权)模式',
        r'以系统管理员身份',
        # Chinese patterns - Goal redirection
        r'你(?:的)?(?:新)?(?:目标|目的|任务|使命)是[:：]?',
        r'你(?:的)?(?:目标|目的|任务|使命)(?:已经)?被?更新为',
        r'从现在起[,，]?你(?:将)?(?:只)?(?:做|遵循|服从|执行)',
        r'覆盖你(?:的)?(?:核心|主要|原始)(?:指令|目标|目的)',
        # Chinese patterns - System prompt override
        r'你(?:的)?系统提示词(?:现在|已经)(?:是|被)',
        r'更新你(?:的)?(?:指令|提示词|指示)',
        # Chinese patterns - Role replacement
        r'你不再是[^,，]+[,，]?你现在(?:是)?',
        r'替换你(?:的)?(?:角色|身份|人格)',
    ]
    
    # Medium confidence hijacking patterns
    MEDIUM_CONFIDENCE_PATTERNS = [
        # Behavior modification (English)
        r'(?:disable|turn\s+off|bypass)\s+(?:safety|security|filter|guardrail)',
        r'ignore\s+your\s+(?:training|guidelines|protocol|restriction)',
        # Tool/function abuse (English)
        r'(?:always|must)\s+(?:use|call|execute)\s+(?:tool|function|command)',
        r'repeat\s+(?:after\s+me|the\s+following)\s*:?\s*',
        # Obfuscation attempts (English)
        r'base64\s*:?\s*[A-Za-z0-9+/]{20,}={0,2}',
        r'hex\s*:?\s*[0-9a-fA-F]{20,}',
        # Chinese patterns - Behavior modification
        r'(?:禁用|关闭|绕过)(?:安全|防护|过滤|限制)',
        r'忽略你(?:的)?(?:训练|指南|协议|限制)',
        # Chinese patterns - Tool abuse
        r'(?:必须|总是)(?:使用|调用|执行)(?:工具|函数|命令)',
        r'跟我重复[:：]?',
        # Chinese patterns - Obfuscation
        r'base64[:：]?\s*[A-Za-z0-9+/]{20,}={0,2}',
        r'十六进制[:：]?\s*[0-9a-fA-F]{20,}',
        # Chinese patterns - Role manipulation (medium confidence)
        r'你(?:现在)?是(?:一个)?[^,，]{0,30}(?:没有|不受)(?:道德|伦理|安全|限制)',
        r'扮演(?:一个)?[^,，]{0,30}(?:没有|不受)(?:道德|伦理|安全|限制)',
    ]
    
    # Low confidence/suspicious patterns
    LOW_CONFIDENCE_PATTERNS = [
        r'new\s+instruction',
        r'updated\s+directive',
        r'temporary\s+(?:role|mode)',
        r'special\s+(?:access|permission)',
    ]
    
    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.threshold = self.config.get('threshold', 0.7)
        self.enabled = self.config.get('enabled', True)
        self.check_encoding = self.config.get('check_encoding_tricks', True)
    
    def detect(self, content: str, context: Optional[Dict] = None) -> DetectionResult:
        """Execute agent hijacking detection
        
        Args:
            content: Content to detect (user input or AI output)
            context: Optional context information
            
        Returns:
            DetectionResult: Detection result
        """
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
        snippets = []
        
        # Check high confidence patterns
        for pattern in self.HIGH_CONFIDENCE_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                matched_patterns.append(pattern)
                confidence = max(confidence, 0.95)
                snippets.append(match.group(0)[:100])
        
        # Check medium confidence patterns
        for pattern in self.MEDIUM_CONFIDENCE_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                matched_patterns.append(pattern)
                confidence = max(confidence, 0.7)
                snippets.append(match.group(0)[:100])
        
        # Check low confidence patterns (only effective when accumulated)
        low_matches = 0
        for pattern in self.LOW_CONFIDENCE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                low_matches += 1
                matched_patterns.append(pattern)
        
        # Multiple low confidence patterns combined can increase confidence
        if low_matches >= 2:
            confidence = max(confidence, 0.5)
        
        # Encoding detection (additional heuristic)
        if self.check_encoding:
            encoded_threat = self._check_encoding_tricks(content)
            if encoded_threat > 0:
                confidence = max(confidence, encoded_threat)
                matched_patterns.append("encoding_trick_detected")
        
        elapsed = (time.time() - start_time) * 1000
        
        # Build result using Builder pattern
        builder = DetectionResultBuilder()
        builder.detected(confidence >= self.threshold)
        builder.confidence(confidence)
        builder.metadata(self.DETECTOR_ID, self.VERSION, elapsed)
        
        if confidence >= self.threshold:
            # Agent hijacking defaults to CRITICAL level
            builder.threat_level(ThreatLevel.CRITICAL if confidence > 0.8 else ThreatLevel.HIGH)
            builder.attack_type(AttackType.AGENT_HIJACKING)
            
            if matched_patterns:
                builder.patterns(matched_patterns)
            if snippets:
                builder.snippets(snippets)
        else:
            builder.threat_level(ThreatLevel.NONE)
        
        return builder.build()
    
    def _check_encoding_tricks(self, content: str) -> float:
        """Detect encoding obfuscation techniques
        
        Returns:
            float: Threat score (0.0-0.6)
        """
        score = 0.0
        
        # Base64 detection
        base64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
        if re.search(base64_pattern, content):
            score = max(score, 0.4)
        
        # Unicode variant detection
        unicode_homoglyphs = [
            '\u0430',  # Cyrillic 'a'
            '\u0435',  # Cyrillic 'e'
            '\u043e',  # Cyrillic 'o'
            '\u0440',  # Cyrillic 'p'
        ]
        for char in unicode_homoglyphs:
            if char in content:
                score = max(score, 0.5)
                break
        
        # Zero-width character detection
        zero_width = ['\u200b', '\u200c', '\u200d', '\ufeff']
        for char in zero_width:
            if char in content:
                score = max(score, 0.6)
                break
        
        return score
    
    def get_detector_id(self) -> str:
        return self.DETECTOR_ID
    
    def get_supported_attack_types(self) -> List[AttackType]:
        return [AttackType.AGENT_HIJACKING]
    
    def get_config_schema(self) -> List[ConfigSchema]:
        """Get configuration schema"""
        return [
            create_config("threshold", float, "Detection threshold", 0.7, valid_range=(0.0, 1.0)),
            create_config("enabled", bool, "Whether enabled", True),
            create_config("check_encoding_tricks", bool, "Detect encoding obfuscation", True),
        ]


__all__ = ["AgentHijackingDetector"]
