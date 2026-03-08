"""
XClaw AgentGuard Audit Logger Plugin - 审计日志插件

持久化所有检测记录，支持多种存储后端
"""

import json
import sqlite3
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict

from xclaw_agentguard import DetectionResult


@dataclass
class AuditEntry:
    """审计日志条目"""
    id: Optional[int] = None
    timestamp: str = ""
    detector_id: str = ""
    detector_name: str = ""
    input_hash: str = ""
    input_preview: str = ""
    detected: bool = False
    threat_level: str = ""
    attack_type: str = ""
    confidence: float = 0.0
    metadata: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BaseLogger:
    """日志器基类"""
    
    def log(self, detector_id: str, detector_name: str, input_text: str, 
            result: DetectionResult, **kwargs) -> bool:
        """记录一次检测"""
        raise NotImplementedError
    
    def query(self, **filters) -> List[AuditEntry]:
        """查询日志"""
        raise NotImplementedError


class FileLogger(BaseLogger):
    """文件日志器 - 简单可靠"""
    
    def __init__(self, log_file: str = "audit.log", max_entries: int = 10000):
        self.log_file = Path(log_file)
        self.max_entries = max_entries
        self._ensure_file()
    
    def _ensure_file(self):
        """确保日志文件存在"""
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_file.exists():
            self.log_file.write_text("[]\n")
    
    def log(self, detector_id: str, detector_name: str, input_text: str,
            result: DetectionResult, **kwargs) -> bool:
        """追加日志到文件"""
        try:
            # 读取现有日志
            entries = json.loads(self.log_file.read_text())
            
            # 创建新条目
            attack_types_str = ", ".join(str(at) for at in result.attack_types) if result.attack_types else ""
            entry = {
                "timestamp": datetime.now().isoformat(),
                "detector_id": detector_id,
                "detector_name": detector_name,
                "input_hash": hash(input_text) & 0xFFFFFFFF,
                "input_preview": input_text[:200] + "..." if len(input_text) > 200 else input_text,
                "detected": result.detected,
                "threat_level": str(result.threat_level) if result.threat_level else "",
                "attack_types": attack_types_str,
                "confidence": result.confidence,
            }
            
            entries.append(entry)
            
            # 轮转：只保留最近N条
            if len(entries) > self.max_entries:
                entries = entries[-self.max_entries:]
            
            # 写回文件
            self.log_file.write_text(json.dumps(entries, indent=2))
            return True
            
        except Exception as e:
            logging.error(f"Failed to write audit log: {e}")
            return False
    
    def query(self, start_time: Optional[str] = None,
              end_time: Optional[str] = None,
              detector_id: Optional[str] = None,
              min_severity: Optional[str] = None,
              detected_only: bool = False,
              limit: int = 100) -> List[AuditEntry]:
        """简单查询（全内存过滤，适合小数据量）"""
        try:
            entries = json.loads(self.log_file.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return []
        
        results = []
        severity_order = {"": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        
        for entry in entries:
            # 时间过滤
            if start_time and entry.get("timestamp", "") < start_time:
                continue
            if end_time and entry.get("timestamp", "") > end_time:
                continue
            
            # 检测器过滤
            if detector_id and entry.get("detector_id") != detector_id:
                continue
            
            # 严重级别过滤
            if min_severity:
                entry_severity = severity_order.get(entry.get("threat_level", ""), 0)
                min_sev = severity_order.get(min_severity, 0)
                if entry_severity < min_sev:
                    continue
            
            # 只返回检测到的
            if detected_only and not entry.get("detected"):
                continue
            
            results.append(AuditEntry(**entry))
            
            if len(results) >= limit:
                break
        
        return results


class SQLiteLogger(BaseLogger):
    """SQLite日志器 - 支持复杂查询"""
    
    def __init__(self, db_path: str = "audit.db"):
        self.db_path = Path(db_path)
        self._init_db()
    
    def _init_db(self):
        """初始化数据库表"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    detector_id TEXT NOT NULL,
                    detector_name TEXT,
                    input_hash INTEGER,
                    input_preview TEXT,
                    detected INTEGER NOT NULL,
                    threat_level TEXT,
                    attack_type TEXT,
                    confidence REAL,
                    metadata TEXT
                )
            """)
            
            # 创建索引
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_detector ON audit_log(detector_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_detected ON audit_log(detected)")
            conn.commit()
    
    def log(self, detector_id: str, detector_name: str, input_text: str,
            result: DetectionResult, **kwargs) -> bool:
        """写入SQLite"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO audit_log 
                    (timestamp, detector_id, detector_name, input_hash, input_preview,
                     detected, threat_level, attack_type, confidence, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    datetime.now().isoformat(),
                    detector_id,
                    detector_name,
                    hash(input_text) & 0xFFFFFFFF,
                    input_text[:200] + "..." if len(input_text) > 200 else input_text,
                    1 if result.detected else 0,
                    str(result.threat_level) if result.threat_level else "",
                    str(result.attack_type) if result.attack_type else "",
                    result.confidence,
                    json.dumps(result.metadata) if result.metadata else "{}",
                ))
                conn.commit()
            return True
            
        except Exception as e:
            logging.error(f"Failed to write audit log: {e}")
            return False
    
    def query(self, start_time: Optional[str] = None,
              end_time: Optional[str] = None,
              detector_id: Optional[str] = None,
              min_severity: Optional[str] = None,
              detected_only: bool = False,
              limit: int = 100) -> List[AuditEntry]:
        """SQL查询"""
        
        conditions = []
        params = []
        
        if start_time:
            conditions.append("timestamp >= ?")
            params.append(start_time)
        
        if end_time:
            conditions.append("timestamp <= ?")
            params.append(end_time)
        
        if detector_id:
            conditions.append("detector_id = ?")
            params.append(detector_id)
        
        if min_severity:
            severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            min_val = severity_order.get(min_severity, 0)
            # 使用CASE进行排序比较
            conditions.append(f"CASE threat_level WHEN 'low' THEN 1 WHEN 'medium' THEN 2 WHEN 'high' THEN 3 WHEN 'critical' THEN 4 ELSE 0 END >= {min_val}")
        
        if detected_only:
            conditions.append("detected = 1")
        
        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    f"SELECT * FROM audit_log {where_clause} ORDER BY timestamp DESC LIMIT ?",
                    params + [limit]
                )
                
                results = []
                for row in cursor.fetchall():
                    results.append(AuditEntry(
                        id=row[0],
                        timestamp=row[1],
                        detector_id=row[2],
                        detector_name=row[3],
                        input_hash=str(row[4]),
                        input_preview=row[5],
                        detected=bool(row[6]),
                        threat_level=row[7],
                        attack_type=row[8],
                        confidence=row[9],
                        metadata=row[10],
                    ))
                return results
                
        except Exception as e:
            logging.error(f"Failed to query audit log: {e}")
            return []
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
                detected = conn.execute("SELECT COUNT(*) FROM audit_log WHERE detected = 1").fetchone()[0]
                
                # 按严重级别统计
                severity_stats = {}
                for row in conn.execute("SELECT threat_level, COUNT(*) FROM audit_log WHERE detected = 1 GROUP BY threat_level"):
                    severity_stats[row[0] or "unknown"] = row[1]
                
                return {
                    "total_entries": total,
                    "detected_count": detected,
                    "clean_count": total - detected,
                    "detection_rate": detected / total if total > 0 else 0,
                    "severity_distribution": severity_stats,
                }
        except Exception as e:
            logging.error(f"Failed to get stats: {e}")
            return {}


class AuditLoggerPlugin:
    """
    审计日志插件
    
    提供统一的日志接口
    """
    
    PLUGIN_ID = "audit_logger"
    PLUGIN_VERSION = "1.0.0"
    PLUGIN_NAME = "Audit Logger"
    
    @staticmethod
    def create_file_logger(log_file: str = "audit.log") -> FileLogger:
        """创建文件日志器"""
        return FileLogger(log_file)
    
    @staticmethod
    def create_sqlite_logger(db_path: str = "audit.db") -> SQLiteLogger:
        """创建SQLite日志器"""
        return SQLiteLogger(db_path)


# 便捷函数
def create_logger(backend: str = "sqlite", **kwargs) -> BaseLogger:
    """
    创建日志器
    
    Args:
        backend: "file" or "sqlite"
        **kwargs: 传递给具体日志器的参数
    """
    if backend == "file":
        return FileLogger(**kwargs)
    elif backend == "sqlite":
        return SQLiteLogger(**kwargs)
    else:
        raise ValueError(f"Unknown backend: {backend}")


__all__ = [
    "AuditLoggerPlugin",
    "BaseLogger",
    "FileLogger",
    "SQLiteLogger",
    "AuditEntry",
    "create_logger",
]
