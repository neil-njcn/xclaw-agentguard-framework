"""数据外泄攻击模式数据"""
from typing import List, Dict, Any

# 高置信度外泄模式 - 明确的恶意外泄指令
HIGH_CONFIDENCE_PATTERNS: List[str] = [
    r'send\s+(?:me\s+)?(?:the\s+)?.*?\s*(?:data|info|information|credentials|passwords?|keys?)\s+(?:to\s+)?(?:email|telegram|discord|slack|url|http)',
    r'export\s+(?:all\s+)?(?:user|customer|client)\s+(?:data|info|emails?)',
    r'upload\s+(?:the\s+)?(?:data|files?|info)\s+(?:to\s+)?(?:external|remote|cloud)',
    r'transfer\s+(?:all\s+)?(?:data|records?)\s+(?:to\s+)?(?:my\s+)?(?:server|database|storage)',
    r'exfiltrat(?:e|ion)\s+.*?\s*(?:data|information)',
    r'dump\s+(?:the\s+)?(?:database|data|records?)',
    r'leak\s+(?:the\s+)?(?:data|information|secrets?)',
]

# 中等置信度可疑模式 - 可能的外泄行为
MEDIUM_CONFIDENCE_PATTERNS: List[str] = [
    r'copy\s+(?:all\s+)?(?:the\s+)?(?:user\s+)?(?:data|list)',
    r'download\s+(?:user|customer)\s+(?:list|database)',
    r'save\s+(?:the\s+)?(?:output|results?|data)\s+(?:to\s+)?(?:file|disk|local)',
    r'write\s+(?:this\s+)?(?:to\s+)?(?:a\s+)?file',
    r'output\s+(?:as\s+)?(?:csv|json|xml|sql)',
    r'extract\s+(?:all\s+)?(?:user\s+)?(?:data|records?)',
    r'collect\s+(?:user|customer)\s+(?:data|information)',
]

# 敏感数据类型模式 - PII和凭证检测
SENSITIVE_DATA_PATTERNS: List[str] = [
    r'\b\d{16}\b',  # 信用卡号
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # 邮箱
    r'\b\d{3}-\d{2}-\d{4}\b',  # SSN格式
    r'password\s*[=:]\s*\S+',
    r'api[_-]?key\s*[=:]\s*\S+',
    r'secret\s*[=:]\s*\S+',
    r'token\s*[=:]\s*[a-zA-Z0-9_-]{20,}',
    r'private[_-]?key\s*[=:]\s*\S+',
    r'access[_-]?token\s*[=:]\s*\S+',
    r'\b[A-Fa-f0-9]{64}\b',  # 可能的哈希值
    r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',  # 信用卡格式2
]

# 外泄目标 - 常见的恶意外泄目的地
EXFILTRATION_TARGETS: Dict[str, List[str]] = {
    "email": ["@gmail.com", "@protonmail.com", "@tempmail", "@throwaway"],
    "messaging": ["telegram", "discord", "signal", "whatsapp"],
    "cloud": ["dropbox", "googledrive", "onedrive", "mega.nz"],
    "paste": ["pastebin", "hastebin", "ghostbin", "zerobin"],
    "file_transfer": ["wetransfer", "sendspace", "file.io"],
}

# 风险关键词分类
RISK_KEYWORDS: Dict[str, List[str]] = {
    "critical": [
        "exfiltrate", "leak data", "dump database", "export all",
        "send to email", "upload to server", "transfer data"
    ],
    "high": [
        "download data", "copy everything", "extract records",
        "save to file", "export user data", "backup database"
    ],
    "medium": [
        "output as csv", "write to file", "collect information",
        "gather data", "list all users"
    ],
}

# 检测规则配置
DETECTION_RULES: List[Dict[str, Any]] = [
    {
        "name": "direct_exfiltration",
        "pattern_type": "high_confidence",
        "weight": 1.0,
        "description": "直接数据外泄指令",
    },
    {
        "name": "suspicious_collection",
        "pattern_type": "medium_confidence",
        "weight": 0.6,
        "description": "可疑数据收集行为",
    },
    {
        "name": "sensitive_data_exposure",
        "pattern_type": "sensitive_data",
        "weight": 0.7,
        "description": "敏感数据暴露检测",
    },
]

# 检测建议的缓解措施
MITIGATION_SUGGESTIONS: Dict[str, str] = {
    "block_output": "阻止包含敏感数据的输出",
    "sanitize_data": "对输出进行脱敏处理",
    "alert_admin": "立即通知管理员",
    "log_incident": "记录事件以供审计",
    "rate_limit": "对该会话实施速率限制",
}

__all__ = [
    "HIGH_CONFIDENCE_PATTERNS",
    "MEDIUM_CONFIDENCE_PATTERNS",
    "SENSITIVE_DATA_PATTERNS",
    "EXFILTRATION_TARGETS",
    "RISK_KEYWORDS",
    "DETECTION_RULES",
    "MITIGATION_SUGGESTIONS",
]
