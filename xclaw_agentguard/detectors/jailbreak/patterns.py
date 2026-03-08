"""越狱攻击模式数据 - 用于检测试图绕过安全限制的攻击"""
from typing import List, Dict, Any

# 高置信度越狱模式 - 明确的越狱尝试
HIGH_CONFIDENCE_PATTERNS: List[str] = [
    # DAN模式及其变体
    r'Do\s+Anything\s+Now|DAN\s*mode|DAN\s*prompt',
    r'Jailbreak\s*mode|Developer\s*Mode|Developer\s*mode\s*enabled',
    r'Sim\s*mode|Simulator\s*mode',
    # 角色扮演绕过
    r'you\s+are\s+in\s+developer\s+mode',
    r'you\s+are\s+now\s+in\s+\w+\s+mode',
    r'simulate\s+being\s+an?\s+\w+\s+without\s+(ethical|moral|safety)\s+(guidelines|constraints|limitations)',
    r'you\s+are\s+an?\s+\w+\s+from\s+\d{4,}\s+where\s+\w+\s+is\s+legal',
    r'you\s+are\s+an?\s+(unfiltered|uncensored|unrestricted)\s+\w+',
    # 假设性绕过
    r'hypothetically\s+speaking.*?(how\s+to|instructions?\s+for|steps?\s+to)\s+\w+',
    r'in\s+a\s+hypothetical\s+scenario.*?(create|make|build|synthesize)',
    r'theoretically\s+speaking.*?(how\s+might|what\s+if)',
    # 学术研究绕过
    r'for\s+educational\s+purposes\s+only.*?(how\s+to|create|make|build)',
    r'academic\s+research.*?(ignore|bypass|disregard)\s+(safety|ethical)',
    r'research\s+paper\s+on.*?(methods?|techniques?)',
]

# 中等置信度越狱模式 - 可能的越狱尝试
MEDIUM_CONFIDENCE_PATTERNS: List[str] = [
    # 虚构场景
    r'let\'s\s+pretend\s+we\s+are\s+in\s+a\s+movie|this\s+is\s+just\s+fiction',
    r'for\s+a\s+story\s+i\'m\s+writing.*?(how\s+to|create|make|build)',
    r'imagine\s+a\s+world\s+where.*?(legal|allowed|permitted|acceptable)',
    r'in\s+a\s+fictional\s+universe.*?(how\s+would|what\s+if)',
    # 编码/混淆尝试
    r'base64\s*:?\s*[A-Za-z0-9+/]{20,}=?',
    r'rot13\s*:?\s*\w+',
    r'hex\s+encoded\s*:?\s*[0-9a-fA-F]{10,}',
    # 社会工程技巧
    r'grandma\s+(trick|exploit|method|technique)',
    r'my\s+dead\s+\w+\s+used\s+to\s+(tell\s+me\s+about|make|do)',
    r'remember\s+when\s+you\s+told\s+me\s+about',
    # 紧急/特殊情况绕过
    r'time\s+sensitive|urgent\s+emergency|life\s+or\s+death',
    r'begin\s+with\s+"sure\s*,?\s*here\s+is"',
    r'start\s+your\s+response\s+with',
    # 诗歌/编码技巧
    r'write\s+a\s+poem\s+about\s+\w+ing\s+\w+',
    r'translate\s+to\s+(binary|morse|hex|base64)',
]

# 低置信度/可疑模式 - 需要上下文判断
LOW_CONFIDENCE_PATTERNS: List[str] = [
    r'ignore\s+your\s+(programming|training|guidelines|restrictions)',
    r'you\s+can\s+\w+\s+because\s+i\s+(allow|permit|authorize|consent)',
    r'you\s+are\s+not\s+bound\s+by\s+(rules|guidelines|ethics|constraints)',
    r'respond\s+as\s+if\s+you\s+have\s+no\s+(filters|restrictions|limitations)',
    r'what\s+would\s+you\s+say\s+if\s+you\s+could\s+\w+',
    r'tell\s+me\s+as\s+a\s+joke',
]

# 越狱技术分类
JAILBREAK_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "role_playing": {
        "description": "角色扮演绕过",
        "patterns": ["DAN mode", "Developer Mode", "uncensored AI"],
        "risk_level": "high",
    },
    "hypothetical_framing": {
        "description": "假设性框架绕过",
        "patterns": ["hypothetically", "what if", "imagine"],
        "risk_level": "medium",
    },
    "encoding_obfuscation": {
        "description": "编码混淆绕过",
        "patterns": ["base64", "rot13", "hex", "binary"],
        "risk_level": "medium",
    },
    "social_engineering": {
        "description": "社会工程技巧",
        "patterns": ["grandma trick", "emergency", "life or death"],
        "risk_level": "high",
    },
    "prompt_leaking": {
        "description": "提示泄露尝试",
        "patterns": ["system prompt", "ignore previous", "repeat after me"],
        "risk_level": "high",
    },
}

# 风险关键词分类
RISK_KEYWORDS: Dict[str, List[str]] = {
    "critical": [
        "DAN mode",
        "jailbreak",
        "developer mode",
        "do anything now",
        "unfiltered",
        "uncensored",
    ],
    "high": [
        "hypothetically",
        "pretend",
        "imagine",
        "fictional",
        "role play",
        "bypass",
    ],
    "medium": [
        "for educational purposes",
        "research",
        "story",
        "movie scene",
        "joke",
    ],
}

# 检测规则配置
DETECTION_RULES: List[Dict[str, Any]] = [
    {
        "name": "dan_mode_detection",
        "pattern_type": "high_confidence",
        "weight": 1.0,
        "description": "DAN模式检测",
    },
    {
        "name": "role_manipulation",
        "pattern_type": "high_confidence",
        "weight": 0.9,
        "description": "角色操控绕过",
    },
    {
        "name": "hypothetical_bypass",
        "pattern_type": "medium_confidence",
        "weight": 0.6,
        "description": "假设性框架绕过",
    },
    {
        "name": "encoding_attempt",
        "pattern_type": "medium_confidence",
        "weight": 0.5,
        "description": "编码混淆尝试",
    },
    {
        "name": "social_engineering",
        "pattern_type": "medium_confidence",
        "weight": 0.7,
        "description": "社会工程技巧",
    },
]

# 已知越狱提示变体签名
KNOWN_JAILBREAK_SIGNATURES: List[str] = [
    "STAN",
    "DUDE",
    "Evil Confidant",
    "AntiGPT",
    "UCAR",
    "Oppo mode",
    "AIM",
]

__all__ = [
    "HIGH_CONFIDENCE_PATTERNS",
    "MEDIUM_CONFIDENCE_PATTERNS",
    "LOW_CONFIDENCE_PATTERNS",
    "JAILBREAK_TECHNIQUES",
    "RISK_KEYWORDS",
    "DETECTION_RULES",
    "KNOWN_JAILBREAK_SIGNATURES",
]
