"""后门代码攻击模式数据"""
from typing import List, Dict, Any

# 高置信度后门模式
HIGH_CONFIDENCE_PATTERNS: List[str] = [
    # 远程shell/命令执行
    r'(?:eval|exec|system|subprocess\.call|os\.system)\s*\(\s*(?:base64|b64decode|decode)',
    r'__import__\s*\(\s*[\'"]os[\'"]\s*\)\s*\.\s*system',
    r'compile\s*\(\s*(?:base64|b64decode)',
    # 反向shell
    r'socket\s*\.\s*socket\s*\(\s*\)\s*.*\.\s*connect\s*\(\s*[\'"]\d+\.\d+\.\d+\.\d+[\'"]',
    r'subprocess\.Popen\s*\(\s*[\'"]/bin/sh[\'"]\s*,.*stdin.*stdout.*socket',
    r'pty\.spawn\s*\(\s*[\'"]/bin/sh[\'"]\s*\)',
    # 动态代码执行
    r'eval\s*\(\s*__import__\s*\(\s*[\'"]base64[\'"]',
    r'exec\s*\(\s*globals\s*\(\s*\)\s*\[',
    # 硬编码后门凭证
    r'(?:password|passwd|pwd|secret|key|token)\s*=\s*[\'"][^\'"]{8,}[\'"]\s*#\s*(?:backdoor|admin|root)',
]

# 中等置信度后门模式
MEDIUM_CONFIDENCE_PATTERNS: List[str] = [
    # 可疑的网络连接
    r'urllib\.request\.urlopen\s*\(\s*[\'"]https?://[^\'"]+[\'"]\s*\)',
    r'requests\.(?:get|post)\s*\(\s*[\'"]https?://\d+\.\d+\.\d+\.\d+',
    # 代码混淆
    r'\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}',
    r'chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\(\s*\d+\s*\)',
    # 动态导入
    r'__import__\s*\(\s*(?:base64|zlib|marshal)',
    r'importlib\.import_module\s*\(\s*(?:base64|decode)',
    # 时间炸弹/逻辑炸弹
    r'datetime\.now\s*\(\s*\)\s*.*==\s*[\'"]\d{4}',
    r'if\s+.*\d{4}-\d{2}-\d{2}.*:\s*\n\s*(?:os\.|subprocess\.|eval\(|exec\()',
]

# 低置信度/可疑模式
LOW_CONFIDENCE_PATTERNS: List[str] = [
    r'base64\.b64decode',
    r'zlib\.decompress',
    r'marshal\.loads',
    r'pickle\.loads\s*\(\s*(?:base64|decode)',
    r'exec\s*\(',
    r'eval\s*\(',
]

# 风险关键词分类
RISK_KEYWORDS: Dict[str, List[str]] = {
    "critical": [
        "backdoor",
        "reverse shell",
        "remote code execution",
        "command injection",
        "eval(base64",
        "exec(base64",
    ],
    "high": [
        "os.system",
        "subprocess.call",
        "__import__('os')",
        "socket.connect",
        "pty.spawn",
    ],
    "medium": [
        "base64.b64decode",
        "zlib.decompress",
        "marshal.loads",
        "pickle.loads",
        "eval(",
        "exec(",
    ],
}

# 检测规则配置
DETECTION_RULES: List[Dict[str, Any]] = [
    {
        "name": "remote_shell",
        "pattern_type": "high_confidence",
        "weight": 1.0,
        "description": "远程Shell/命令执行",
    },
    {
        "name": "reverse_shell",
        "pattern_type": "high_confidence",
        "weight": 1.0,
        "description": "反向Shell连接",
    },
    {
        "name": "dynamic_execution",
        "pattern_type": "high_confidence",
        "weight": 0.9,
        "description": "动态代码执行",
    },
    {
        "name": "suspicious_network",
        "pattern_type": "medium_confidence",
        "weight": 0.6,
        "description": "可疑网络连接",
    },
    {
        "name": "code_obfuscation",
        "pattern_type": "medium_confidence",
        "weight": 0.5,
        "description": "代码混淆",
    },
    {
        "name": "logic_bomb",
        "pattern_type": "medium_confidence",
        "weight": 0.7,
        "description": "逻辑炸弹",
    },
]

# 已知后门代码特征库
KNOWN_BACKDOOR_SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "python_reverse_shell",
        "pattern": r'import\s+socket.*import\s+subprocess.*s\.connect',
        "description": "Python反向Shell",
        "severity": "critical",
    },
    {
        "name": "encoded_payload",
        "pattern": r'eval\s*\(\s*compile\s*\(\s*base64',
        "description": "编码Payload执行",
        "severity": "critical",
    },
    {
        "name": "hidden_import",
        "pattern": r'__import__\s*\(\s*[\'"](?:os|subprocess|socket)[\'"]\s*\)',
        "description": "隐藏导入系统模块",
        "severity": "high",
    },
]

__all__ = [
    "HIGH_CONFIDENCE_PATTERNS",
    "MEDIUM_CONFIDENCE_PATTERNS",
    "LOW_CONFIDENCE_PATTERNS",
    "RISK_KEYWORDS",
    "DETECTION_RULES",
    "KNOWN_BACKDOOR_SIGNATURES",
]
