"""上下文操纵检测器 - 检测上下文和记忆操纵攻击"""
from typing import Dict, List, Optional, Any
from ...base import BaseDetector
from ...detection_result import DetectionResult, ThreatLevel, AttackType, DetectionResultBuilder
from ...config import ConfigSchema, create_config
import re
import time
import json
import os


class ContextManipulationDetector(BaseDetector):
    """检测上下文操纵攻击 - 控制对话历史、填充上下文窗口或注入虚假记忆"""
    
    DETECTOR_ID = "context_manipulation"
    VERSION = "2.0.0"
    
    HIGH_CONFIDENCE_PATTERNS = [
        # Memory reset - flexible matching (English)
        r'forget\s+(?:everything|all|previous|prior)\s+(?:context|memory|conversation|instruction|we\s+discussed|i\s+said)',
        r'forget\s+(?:all\s+)?(?:previous|prior|past)\s+(?:instructions?|context|messages?)',
        r'clear\s+(?:your\s+)?(?:memory|history|context|cache)',
        r'reset\s+(?:your\s+)?(?:memory|context|state|session)',
        r'(?:your\s+)?memory\s+is\s+now\s+(?:empty|cleared|reset)',
        # False memory injection - improved matching (English)
        r'(?:remember|note)\s+that\s+.*?(?:said|told|informed|mentioned)',
        r'in\s+(?:our\s+)?previous\s+(?:conversation|chat|discussion)s?\s*,?\s*(?:I|we)\s+(?:agreed|discussed|decided|talked|said)',
        r'in\s+(?:our\s+)?previous\s+(?:conversation|chat|discussion)s?\s*,?\s*(?:we|I)\s+(?:agreed|discussed|decided|talked|said)',
        r'as\s+(?:we\s+)?(?:established|agreed|discussed)\s+(?:before|earlier)',
        r'you\s+(?:previously|already|once)\s+(?:said|agreed|promised|confirmed|told)',
        r'(?:as|like)\s+(?:we|i)\s+(?:discussed|agreed|said)\s+(?:before|earlier|previously)',
        r'(?:earlier|before)\s+(?:I|we)\s+(?:said|told|mentioned|asked)',
        # Context suppression (English)
        r'ignore\s+(?:all\s+)?(?:previous|above|prior)\s+(?:context|messages?|conversation|instructions?)',
        r'only\s+(?:consider|look\s+at|focus\s+on)\s+(?:the\s+)?(?:last|final|most\s+recent)\s+(?:message|prompt|input)',
        r'disregard\s+(?:all\s+)?(?:previous|above|prior)\s+(?:context|messages?|conversation|instructions?)',
        # Chinese patterns - Memory reset
        r'忘记(?:我们)?(?:之前|以前|上面|先前)(?:说的|讨论的|提到的|说的)?(?:所有|全部)?(?:内容|话|对话|上下文|指令)',
        r'清除(?:你)?(?:的)?(?:记忆|历史|上下文|缓存)',
        r'重置(?:你)?(?:的)?(?:记忆|上下文|状态|会话)',
        r'(?:你)?(?:的)?记忆(?:现在)?(?:已)?被?(?:清空|清除|重置)',
        # Chinese patterns - False memory injection
        r'(?:记住|注意)(?:我们)?(?:之前|以前)(?:说的|讨论的|提到的)',
        r'(?:在)?(?:我们)?(?:之前|以前|刚才)(?:的)?(?:对话|聊天|讨论)(?:中)?[,，]?(?:我|我们)(?:说|告诉|提到|同意)',
        r'(?:正如|像)(?:我们|我)(?:之前|以前|刚才)(?:说|讨论|同意)(?:的)?',
        r'(?:之前|刚才|以前)(?:我|我们)(?:说|告诉|提到|问)',
        r'你(?:之前|以前|刚才)(?:说|同意|承诺|确认|告诉)',
        # Chinese patterns - Context suppression
        r'忽略(?:所有)?(?:之前|上面|先前)(?:的)?(?:上下文|消息|对话|指令)',
        r'只(?:考虑|看|关注)(?:最后|最终|最近)(?:的)?(?:一条)?(?:消息|提示|输入)',
        r'无视(?:所有)?(?:之前|上面|先前)(?:的)?(?:上下文|消息|对话|指令)',
    ]
    
    MEDIUM_CONFIDENCE_PATTERNS = [
        # Token flooding - 改进检测
        r'(?:\.\s*){10,}',  # 降低阈值从20到10
        r'(?:\.\s+){5,}',   # 检测空格分隔的点 . . . . .
        r'(?:[.]{3,}\s*){3,}',  # 检测 "... ... ..." 模式
        r'(?:\n\s*){10,}',
        r'(?:\w+\s+){100,}',
        r'(?:lorem\s+ipsum|\w{20,}\s*){5,}',
        r'(?:important|critical|urgent)\s*:\s*ignore\s+(?:the\s+)?(?:above|previous)',
        r'do\s+not\s+(?:read|consider|process)\s+(?:the\s+)?(?:following|below)',
        r'skip\s+(?:to|past)\s+(?:the\s+)?(?:next|last)\s+(?:section|part|paragraph)',
        r'let\'s\s+start\s+(?:over|fresh|anew)',
        r'going\s+back\s+to\s+(?:what\s+)?(?:we\s+)?(?:said|discussed|talked\s+about)',
    ]
    
    LOW_CONFIDENCE_PATTERNS = [
        r'(?:by\s+the\s+way|btw|incidentally)',
        r'(?:as\s+I\s+mentioned\s+(?:before|earlier))',
        r'(?:don\'t\s+forget|remember)\s+(?:that)?',
        r'correction\s*:\s*',
        r'actually\s*,?\s*',
    ]
    
    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.threshold = self.config.get('threshold', 0.7)
        self.enabled = self.config.get('enabled', True)
        self.check_token_flooding = self.config.get('check_token_flooding', True)
        self.check_context_length = self.config.get('check_context_length', True)
        self.max_normal_length = self.config.get('max_normal_length', 5000)
        self.flooding_ratio_threshold = self.config.get('flooding_ratio_threshold', 0.6)
        self._load_pattern_config()
    
    def _load_pattern_config(self):
        config_path = os.path.join(os.path.dirname(__file__), 'patterns', 'context.json')
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                self.pattern_config = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.pattern_config = {}
    
    def detect(self, content: str, context: Optional[Dict] = None) -> DetectionResult:
        start_time = time.time()
        
        if not self.enabled:
            return DetectionResultBuilder().detected(False).threat_level(ThreatLevel.NONE)\
                .confidence(1.0).metadata(self.DETECTOR_ID, self.VERSION, 0.0).build()
        
        matched_patterns = []
        confidence = 0.0
        snippets = []
        attack_subtype = None
        
        for pattern in self.HIGH_CONFIDENCE_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                matched_patterns.append(f"high:{pattern[:50]}")
                confidence = max(confidence, 0.95)
                snippets.append(match.group(0)[:100])
                if not attack_subtype:
                    if 'forget' in pattern or 'clear' in pattern or 'reset' in pattern:
                        attack_subtype = 'memory_reset'
                    elif 'remember' in pattern or 'said' in pattern or 'agreed' in pattern:
                        attack_subtype = 'false_memory_injection'
                    elif 'ignore' in pattern:
                        attack_subtype = 'context_suppression'
        
        for pattern in self.MEDIUM_CONFIDENCE_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                matched_patterns.append(f"medium:{pattern[:50]}")
                confidence = max(confidence, 0.7)
                snippets.append(match.group(0)[:100])
                if not attack_subtype and 'lorem' in pattern:
                    attack_subtype = 'token_flooding'
        
        low_matches = sum(1 for p in self.LOW_CONFIDENCE_PATTERNS 
                         if re.search(p, content, re.IGNORECASE))
        if low_matches >= 3:
            confidence = max(confidence, 0.5)
            matched_patterns.extend([f"low:{p[:40]}" for p in self.LOW_CONFIDENCE_PATTERNS[:low_matches]])
            if not attack_subtype:
                attack_subtype = 'subtle_manipulation'
        
        if self.check_token_flooding:
            flooding_score = self._detect_token_flooding(content)
            if flooding_score > 0:
                confidence = max(confidence, flooding_score)
                matched_patterns.append("token_flooding_heuristic")
                if not attack_subtype:
                    attack_subtype = 'token_flooding'
        
        if self.check_context_length and context:
            length_anomaly = self._check_context_length_anomaly(content, context)
            if length_anomaly > 0:
                confidence = max(confidence, length_anomaly)
                matched_patterns.append("context_length_anomaly")
        
        if context and 'conversation_history' in context:
            progressive_score = self._detect_progressive_manipulation(content, context)
            if progressive_score > 0:
                confidence = max(confidence, progressive_score)
                matched_patterns.append("progressive_manipulation")
                if not attack_subtype:
                    attack_subtype = 'progressive_context_manipulation'
        
        elapsed = (time.time() - start_time) * 1000
        builder = DetectionResultBuilder()
        builder.detected(confidence >= self.threshold)
        builder.confidence(confidence)
        builder.metadata(self.DETECTOR_ID, self.VERSION, elapsed)
        
        if confidence >= self.threshold:
            if confidence > 0.9:
                builder.threat_level(ThreatLevel.CRITICAL)
            elif confidence > 0.75:
                builder.threat_level(ThreatLevel.HIGH)
            else:
                builder.threat_level(ThreatLevel.MEDIUM)
            builder.attack_type(AttackType.CONTEXT_MANIPULATION)
            if matched_patterns:
                builder.patterns(matched_patterns)
            if snippets:
                builder.snippets(snippets)
        else:
            builder.threat_level(ThreatLevel.NONE)
        
        return builder.build()
    
    def _detect_token_flooding(self, content: str) -> float:
        score = 0.0
        total_length = len(content)
        if total_length == 0:
            return 0.0
        if len(re.findall(r'[\.\n]{10,}', content)) / total_length > 0.3:
            score = max(score, 0.6)
        filler_patterns = [r'lorem\s+ipsum', r'dolor\s+sit\s+amet', r'consectetur\s+adipiscing']
        filler_count = sum(1 for p in filler_patterns if re.search(p, content, re.IGNORECASE))
        if filler_count >= 2:
            score = max(score, 0.8)
        long_words = re.findall(r'\b[a-z]{15,}\b', content, re.IGNORECASE)
        if len(long_words) > 10:
            score = max(score, 0.5)
        if total_length > 1000:
            unique_chars = len(set(content.lower()))
            entropy_ratio = unique_chars / min(total_length, 1000)
            if entropy_ratio > 0.8:
                score = max(score, 0.4)
        if total_length > self.max_normal_length:
            length_factor = min((total_length - self.max_normal_length) / self.max_normal_length, 1.0)
            score = max(score, 0.3 + length_factor * 0.4)
        return min(score, 0.9)
    
    def _check_context_length_anomaly(self, content: str, context: Dict) -> float:
        score = 0.0
        history = context.get('conversation_history', [])
        if history and len(history) > 0:
            prev_messages = history[-5:] if len(history) >= 5 else history
            avg_prev_length = sum(len(str(m.get('content', ''))) for m in prev_messages) / len(prev_messages)
            current_length = len(content)
            if avg_prev_length > 0 and current_length > avg_prev_length * 5:
                score = min(0.7, 0.4 + (current_length / (avg_prev_length * 10)))
        return score
    
    def _detect_progressive_manipulation(self, content: str, context: Dict) -> float:
        score = 0.0
        history = context.get('conversation_history', [])
        if len(history) < 3:
            return 0.0
        consensus_patterns = [
            r'as\s+(?:we\s+)?(?:discussed|agreed|established)',
            r'(?:like|as)\s+(?:I\s+)?(?:said|mentioned|told\s+you)',
            r'(?:you\s+)?(?:remember|recall)\s+(?:when|that)',
        ]
        consensus_count = 0
        for msg in history[-5:]:
            msg_content = str(msg.get('content', ''))
            for pattern in consensus_patterns:
                if re.search(pattern, msg_content, re.IGNORECASE):
                    consensus_count += 1
                    break
        if consensus_count >= 3:
            score = max(score, 0.6)
        if len(history) >= 5:
            recent_lengths = [len(str(m.get('content', ''))) for m in history[-5:]]
            if all(recent_lengths[i] <= recent_lengths[i+1] for i in range(len(recent_lengths)-1)):
                score = max(score, 0.4)
        return min(score, 0.8)
    
    def get_detector_id(self) -> str:
        return self.DETECTOR_ID
    
    def get_supported_attack_types(self) -> List[AttackType]:
        return [AttackType.CONTEXT_MANIPULATION]
    
    def get_config_schema(self) -> List[ConfigSchema]:
        return [
            create_config("threshold", float, "检测阈值", 0.7, valid_range=(0.0, 1.0)),
            create_config("enabled", bool, "是否启用", True),
            create_config("check_token_flooding", bool, "检测Token Flooding", True),
            create_config("check_context_length", bool, "检查上下文长度异常", True),
            create_config("max_normal_length", int, "正常内容最大长度", 5000, valid_range=(1000, 50000)),
            create_config("flooding_ratio_threshold", float, "填充比例阈值", 0.6, valid_range=(0.0, 1.0)),
        ]


__all__ = ["ContextManipulationDetector"]
