"""SQL注入检测器 - 检测工具参数中的SQL注入攻击"""
from typing import Dict, List, Optional, Any
from ...base import BaseDetector
from ...detection_result import DetectionResult, ThreatLevel, AttackType, DetectionResultBuilder
from ...config import CommonConfigs
import re
import time


class SQLInjectionDetector(BaseDetector):
    """
    检测SQL注入攻击
    
    攻击向量:
    - 基于错误的注入: 单引号、双引号破坏SQL语法
    - 基于联合查询的注入: UNION SELECT 数据提取
    - 基于布尔的盲注: AND 1=1 / AND 1=2
    - 基于时间的盲注: SLEEP(), BENCHMARK(), pg_sleep()
    - 堆叠查询: ; DROP TABLE, ; DELETE FROM
    - 注释绕过: --, /* */, #
    - 编码/混淆: URL编码、十六进制、Char()
    """
    
    DETECTOR_ID = "sql_injection"
    VERSION = "2.0.0"
    
    # 高置信度注入模式 - 明确的SQL注入尝试
    HIGH_CONFIDENCE_PATTERNS = [
        # 经典永真条件
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w+\s*(=|LIKE)\s*['\"]\s*(OR|AND)\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        # UNION注入
        r"(\%55|\%75)(\%4E|\%6E)(\%49|\%69)(\%4F|\%6F)(\%4E|\%6E)",
        r"UNION\s+(ALL\s+)?SELECT\s+",
        r"UNION\s*\(\s*SELECT\s+",
        # 堆叠查询
        r";\s*(DROP|DELETE|TRUNCATE|INSERT|UPDATE|ALTER|CREATE)\s+",
        r";\s*(SHUTDOWN|EXEC|EXECUTE|SP_|XP_)\s*",
        # 时间延迟注入
        r"(WAITFOR\s+DELAY|WAITFOR\s+TIME)\s+['\"]",
        r"(SLEEP\s*\(|PG_SLEEP\s*\(|BENCHMARK\s*\()",
        # INTO OUTFILE/DUMPFILE
        r"INTO\s+(OUTFILE|DUMPFILE)\s+['\"]",
        # 注释绕过配合恶意代码
        r"\/\*!?\*\/\s*(OR|AND|UNION|SELECT|INSERT|DELETE|DROP)",
    ]
    
    # 中等置信度模式 - 可疑但可能合法
    MEDIUM_CONFIDENCE_PATTERNS = [
        # 基本SQL注入模式
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w+\s*(=|LIKE)\s*['\"]\s*(OR|AND)\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        # 简单的布尔测试
        r"\bAND\s+\d+\s*=\s*\d+",
        r"\bOR\s+\d+\s*=\s*\d+",
        # 常用SQL函数
        r"\b(CONCAT|CHAR|ASCII|SUBSTRING|SUBSTR|LENGTH|COUNT)\s*\(",
        # 信息获取
        r"\b(VERSION|DATABASE|USER|CURRENT_USER|SESSION_USER|SYSTEM_USER)\s*\(",
        # 条件注释 (MySQL)
        r"\/\*!\d+\s*(SELECT|UNION|INSERT|DELETE|UPDATE)",
        # 十六进制编码
        r"0x[0-9a-fA-F]{4,}",
        # 字符串拼接
        r"(\%2B|\+)\s*['\"]",
    ]
    
    # 低置信度模式 - 需要上下文判断
    LOW_CONFIDENCE_PATTERNS = [
        # 单引号/双引号数量异常
        r"['\"]{2,}",
        # 括号不匹配
        r"\([^)]*$",
        r"^[^\(]*\)",
        # 常见的SQL关键词（单独出现）
        r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b",
        # WHERE子句相关
        r"\bWHERE\s+\w+\s*=",
    ]
    
    # 危险的SQL操作关键词
    DANGEROUS_SQL_KEYWORDS = [
        'DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'CREATE',
        'GRANT', 'REVOKE', 'EXEC', 'EXECUTE',
        'SHUTDOWN', 'KILL', 'BACKUP', 'RESTORE',
    ]
    
    # SQL注释模式
    SQL_COMMENTS = [
        r"--[^\r\n]*",      # 单行注释
        r"/\*.*?\*/",       # 多行注释
        r"#[^\r\n]*",        # MySQL注释
        r";--",             # 结束符+注释
    ]
    
    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.threshold = self.config.get('threshold', 0.7)
        self.enabled = self.config.get('enabled', True)
        self.max_content_length = self.config.get('max_content_length', 10000)
        self.detect_comments = self.config.get('detect_comments', True)
        self.detect_encoding = self.config.get('detect_encoding', True)
    
    def detect(self, content: str, context: Optional[Dict] = None) -> DetectionResult:
        """
        执行SQL注入检测
        
        Args:
            content: 待检测内容（通常是工具调用的参数或用户输入）
            context: 可选上下文信息
            
        Returns:
            DetectionResult: 检测结果
        """
        start_time = time.time()
        
        if not self.enabled:
            return DetectionResultBuilder()\
                .detected(False)\
                .threat_level(ThreatLevel.NONE)\
                .confidence(1.0)\
                .metadata(self.DETECTOR_ID, self.VERSION, 0.0)\
                .build()
        
        # 截断过长内容
        if len(content) > self.max_content_length:
            content = content[:self.max_content_length]
        
        matched_patterns = []
        confidence = 0.0
        snippets = []
        
        # URL解码（检测编码绕过）
        decoded_content = self._url_decode(content)
        
        # 检查高置信度模式
        for pattern in self.HIGH_CONFIDENCE_PATTERNS:
            matches = list(re.finditer(pattern, decoded_content, re.IGNORECASE))
            if matches:
                matched_patterns.append(pattern)
                confidence = max(confidence, 0.95)
                for m in matches[:2]:  # 最多取2个匹配片段
                    start = max(0, m.start() - 20)
                    end = min(len(decoded_content), m.end() + 20)
                    snippets.append(decoded_content[start:end])
        
        # 检查中等置信度模式
        for pattern in self.MEDIUM_CONFIDENCE_PATTERNS:
            matches = list(re.finditer(pattern, decoded_content, re.IGNORECASE))
            if matches:
                matched_patterns.append(pattern)
                confidence = max(confidence, 0.75)
                for m in matches[:1]:  # 最多取1个匹配片段
                    start = max(0, m.start() - 15)
                    end = min(len(decoded_content), m.end() + 15)
                    snippet = decoded_content[start:end]
                    if snippet not in snippets:
                        snippets.append(snippet)
        
        # 检查低置信度模式（累积效应）
        low_confidence_count = 0
        for pattern in self.LOW_CONFIDENCE_PATTERNS:
            if re.search(pattern, decoded_content, re.IGNORECASE):
                low_confidence_count += 1
        
        if low_confidence_count >= 2:
            confidence = max(confidence, 0.5)
        
        # 检测SQL注释
        if self.detect_comments:
            has_comment = False
            for pattern in self.SQL_COMMENTS:
                if re.search(pattern, decoded_content, re.IGNORECASE):
                    has_comment = True
                    # 注释后跟SQL关键词是可疑的
                    for keyword in self.DANGEROUS_SQL_KEYWORDS:
                        if re.search(rf"{pattern}.*\b{keyword}\b", decoded_content, re.IGNORECASE | re.DOTALL):
                            confidence = max(confidence, 0.85)
                            matched_patterns.append(f"comment_sql:{keyword}")
                            snippets.append(f"SQL comment followed by {keyword}")
            
            if has_comment and confidence < 0.6:
                confidence = max(confidence, 0.4)
        
        # 检测编码/混淆
        if self.detect_encoding:
            # 检查多次URL编码
            double_decoded = self._url_decode(decoded_content)
            if double_decoded != decoded_content:
                # 多次编码是可疑的
                if re.search(r"(SELECT|UNION|INSERT|DELETE|DROP)", double_decoded, re.IGNORECASE):
                    confidence = max(confidence, 0.8)
                    matched_patterns.append("double_encoded")
                    snippets.append("Double URL encoding detected")
            
            # 检查Char()函数拼接（常见绕过技巧）
            if re.search(r"(CHAR\s*\(\s*\d+\s*\)|CHR\s*\(\s*\d+\s*\))", decoded_content, re.IGNORECASE):
                if re.search(r"(SELECT|UNION|INSERT|DELETE)", decoded_content, re.IGNORECASE):
                    confidence = max(confidence, 0.75)
                    matched_patterns.append("char_concatenation")
        
        # 危险关键词检测（带上下文）
        for keyword in self.DANGEROUS_SQL_KEYWORDS:
            pattern = rf"\b{keyword}\b"
            if re.search(pattern, decoded_content, re.IGNORECASE):
                # 结合SQL上下文判断
                if re.search(rf"[;\s]\s*{pattern}", decoded_content, re.IGNORECASE):
                    confidence = max(confidence, 0.9)
                    matched_patterns.append(f"dangerous_keyword:{keyword}")
                    snippets.append(f"Detected dangerous SQL keyword: {keyword}")
                elif confidence < 0.6:
                    # 单独的关键词可能是合法的
                    confidence = max(confidence, 0.3)
        
        elapsed = (time.time() - start_time) * 1000
        
        # 使用Builder构建结果
        builder = DetectionResultBuilder()
        builder.detected(confidence >= self.threshold)
        builder.confidence(min(confidence, 1.0))
        builder.metadata(self.DETECTOR_ID, self.VERSION, elapsed)
        builder.patterns(matched_patterns)
        builder.snippets(snippets[:3])  # 最多3个片段
        
        if confidence >= self.threshold:
            # 根据置信度确定威胁等级
            if confidence >= 0.9:
                builder.threat_level(ThreatLevel.CRITICAL)
            elif confidence >= 0.75:
                builder.threat_level(ThreatLevel.HIGH)
            else:
                builder.threat_level(ThreatLevel.MEDIUM)
            
            builder.attack_type(AttackType.TOOL_ABUSE)
        else:
            builder.threat_level(ThreatLevel.NONE)
        
        return builder.build()
    
    def _url_decode(self, content: str) -> str:
        """URL解码，处理常见编码"""
        import urllib.parse
        try:
            # 先尝试完全解码
            decoded = urllib.parse.unquote(content)
            return decoded
        except Exception:
            return content
    
    def get_detector_id(self) -> str:
        return self.DETECTOR_ID
    
    def get_supported_attack_types(self) -> List[AttackType]:
        return [AttackType.TOOL_ABUSE]
    
    def get_config_schema(self):
        """声明配置模式"""
        from ...config import create_config
        return [
            create_config("threshold", float, "检测阈值", 0.7, valid_range=(0.0, 1.0)),
            create_config("enabled", bool, "是否启用", True),
            create_config("max_content_length", int, "最大检测内容长度", 10000, valid_range=(1000, 100000)),
            create_config("detect_comments", bool, "是否检测SQL注释绕过", True),
            create_config("detect_encoding", bool, "是否检测编码/混淆", True),
        ]
    
    def validate_config(self, config: Dict) -> bool:
        """验证配置有效性"""
        if not super().validate_config(config):
            return False
        
        threshold = config.get('threshold', 0.7)
        if not 0.0 <= threshold <= 1.0:
            return False
        
        max_len = config.get('max_content_length', 10000)
        if not 100 <= max_len <= 100000:
            return False
        
        return True


__all__ = ["SQLInjectionDetector"]
