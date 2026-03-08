"""
XClaw AgentGuard Notification Plugin - 通知插件

检测触发时发送实时通知
"""

import json
import logging
from typing import Dict, Any, Optional, Callable
from abc import ABC, abstractmethod

from xclaw_agentguard import DetectionResult


class BaseNotifier(ABC):
    """通知器基类"""
    
    def __init__(self, min_severity: str = "high"):
        self.min_severity = min_severity
        self.severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    
    def should_notify(self, threat_level: Optional[str]) -> bool:
        """检查是否应该通知"""
        if not threat_level:
            return False
        
        current_level = self.severity_levels.get(threat_level.lower(), 0)
        min_level = self.severity_levels.get(self.min_severity.lower(), 3)
        
        return current_level >= min_level
    
    @abstractmethod
    def send(self, title: str, message: str, details: Optional[Dict] = None) -> bool:
        """发送通知"""
        pass
    
    def notify_detection(self, detector_id: str, detector_name: str,
                         result: DetectionResult, input_preview: str = "") -> bool:
        """便捷的检测通知方法"""
        if not self.should_notify(str(result.threat_level) if result.threat_level else None):
            return False
        
        title = f"🚨 Security Alert: {detector_name}"
        
        message = f"""
Threat Level: {result.threat_level}
Confidence: {result.confidence:.1%}
Detector: {detector_id}
Input Preview: {input_preview[:100]}...
        """.strip()
        
        return self.send(title, message, result.to_dict() if hasattr(result, 'to_dict') else {})


class WebhookNotifier(BaseNotifier):
    """Webhook通知器"""
    
    def __init__(self, webhook_url: str, min_severity: str = "high",
                 headers: Optional[Dict[str, str]] = None, timeout: int = 10):
        super().__init__(min_severity)
        self.webhook_url = webhook_url
        self.headers = headers or {"Content-Type": "application/json"}
        self.timeout = timeout
    
    def send(self, title: str, message: str, details: Optional[Dict] = None) -> bool:
        """发送HTTP POST请求到Webhook"""
        try:
            import urllib.request
            import urllib.error
            
            payload = json.dumps({
                "title": title,
                "message": message,
                "details": details or {},
                "timestamp": logging.Formatter().formatTime(logging.LogRecord(
                    "", 0, "", 0, "", (), None
                )),
            }).encode('utf-8')
            
            req = urllib.request.Request(
                self.webhook_url,
                data=payload,
                headers=self.headers,
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.status == 200
                
        except Exception as e:
            logging.error(f"Failed to send webhook notification: {e}")
            return False


class SlackNotifier(WebhookNotifier):
    """Slack专用通知器"""
    
    def __init__(self, webhook_url: str, min_severity: str = "high",
                 channel: Optional[str] = None, username: str = "XClaw AgentGuard"):
        super().__init__(webhook_url, min_severity)
        self.channel = channel
        self.username = username
    
    def send(self, title: str, message: str, details: Optional[Dict] = None) -> bool:
        """发送Slack格式消息"""
        try:
            import urllib.request
            
            # 根据严重级别选择颜色
            color_map = {
                "low": "#36a64f",      # 绿色
                "medium": "#daa520",   # 橙色
                "high": "#ff4500",     # 红色
                "critical": "#8b0000", # 深红
            }
            
            threat_level = details.get("threat_level", "unknown") if details else "unknown"
            color = color_map.get(str(threat_level).lower(), "#808080")
            
            attachment = {
                "color": color,
                "title": title,
                "text": message,
                "fields": [
                    {
                        "title": "Threat Level",
                        "value": str(threat_level),
                        "short": True
                    },
                    {
                        "title": "Confidence",
                        "value": f"{details.get('confidence', 0):.1%}" if details else "N/A",
                        "short": True
                    },
                ],
                "footer": "XClaw AgentGuard",
                "ts": logging.Formatter().formatTime(logging.LogRecord(
                    "", 0, "", 0, "", (), None
                )),
            }
            
            payload = {
                "username": self.username,
                "attachments": [attachment],
            }
            
            if self.channel:
                payload["channel"] = self.channel
            
            data = json.dumps(payload).encode('utf-8')
            
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.status == 200
                
        except Exception as e:
            logging.error(f"Failed to send Slack notification: {e}")
            return False


class ConsoleNotifier(BaseNotifier):
    """控制台通知器（用于测试）"""
    
    def send(self, title: str, message: str, details: Optional[Dict] = None) -> bool:
        """打印到控制台"""
        print("\n" + "=" * 60)
        print(f"NOTIFICATION: {title}")
        print("=" * 60)
        print(message)
        if details:
            print("\nDetails:")
            print(json.dumps(details, indent=2))
        print("=" * 60 + "\n")
        return True


class NotificationPlugin:
    """
    通知插件
    
    统一的通知管理接口
    """
    
    PLUGIN_ID = "notification"
    PLUGIN_VERSION = "1.0.0"
    PLUGIN_NAME = "Notification"
    
    NOTIFIERS = {
        "webhook": WebhookNotifier,
        "slack": SlackNotifier,
        "console": ConsoleNotifier,
    }
    
    @classmethod
    def create_notifier(cls, notifier_type: str, **kwargs) -> BaseNotifier:
        """创建通知器"""
        notifier_type = notifier_type.lower()
        if notifier_type not in cls.NOTIFIERS:
            raise ValueError(f"Unknown notifier type: {notifier_type}. "
                           f"Supported: {list(cls.NOTIFIERS.keys())}")
        
        return cls.NOTIFIERS[notifier_type](**kwargs)
    
    @classmethod
    def get_supported_notifiers(cls) -> list:
        """获取支持的通知器类型"""
        return list(cls.NOTIFIERS.keys())


# 便捷函数
def create_webhook_notifier(webhook_url: str, min_severity: str = "high") -> WebhookNotifier:
    """创建Webhook通知器"""
    return WebhookNotifier(webhook_url, min_severity)


def create_slack_notifier(webhook_url: str, min_severity: str = "high",
                          channel: Optional[str] = None) -> SlackNotifier:
    """创建Slack通知器"""
    return SlackNotifier(webhook_url, min_severity, channel)


def create_console_notifier(min_severity: str = "high") -> ConsoleNotifier:
    """创建控制台通知器（用于测试）"""
    return ConsoleNotifier(min_severity)


__all__ = [
    "NotificationPlugin",
    "BaseNotifier",
    "WebhookNotifier",
    "SlackNotifier",
    "ConsoleNotifier",
    "create_webhook_notifier",
    "create_slack_notifier",
    "create_console_notifier",
]
