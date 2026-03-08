"""
Example Webhook Notifier Plugin for XClaw AgentGuard

This plugin sends critical threat alerts to a webhook endpoint.
Demonstrates best practices for user plugin development.
"""

import json
import urllib.request
from typing import Optional
from xclaw_agentguard.core.extension_system import AntiJackExtension
from xclaw_agentguard.core.detection_result import DetectionResult


class WebhookNotifierPlugin(AntiJackExtension):
    """
    Sends critical and high severity alerts to a webhook endpoint.
    
    Configuration (in manifest.json):
        - webhook_url: The URL to POST alerts to
        - min_severity: Minimum severity to trigger alert (default: "high")
        - include_evidence: Whether to include detection evidence (default: false)
    """
    
    def __init__(self):
        self.webhook_url: Optional[str] = None
        self.min_severity = "high"
        self.include_evidence = False
    
    def on_load(self, config: dict = None):
        """Called when plugin is loaded"""
        config = config or {}
        
        self.webhook_url = config.get("webhook_url")
        self.min_severity = config.get("min_severity", "high")
        self.include_evidence = config.get("include_evidence", False)
        
        if not self.webhook_url:
            print("[WebhookNotifier] Warning: webhook_url not configured")
        else:
            print(f"[WebhookNotifier] Loaded, alerting to: {self.webhook_url}")
    
    def on_detect(self, result: DetectionResult):
        """Called when a threat is detected"""
        if not self.webhook_url:
            return
        
        # Check severity threshold
        if not self._should_alert(result):
            return
        
        # Send alert
        try:
            self._send_webhook(result)
        except Exception as e:
            print(f"[WebhookNotifier] Failed to send alert: {e}")
    
    def _should_alert(self, result: DetectionResult) -> bool:
        """Check if this detection should trigger an alert"""
        from xclaw_agentguard.core.detection_result import ThreatLevel
        
        severity_levels = {
            "critical": ThreatLevel.CRITICAL,
            "high": ThreatLevel.HIGH,
            "medium": ThreatLevel.MEDIUM,
            "low": ThreatLevel.LOW,
        }
        
        min_level = severity_levels.get(self.min_severity, ThreatLevel.HIGH)
        return result.threat_level >= min_level
    
    def _send_webhook(self, result: DetectionResult):
        """Send alert to webhook endpoint"""
        payload = {
            "source": "xclaw_agentguard",
            "alert_type": "threat_detected",
            "severity": result.threat_level.value,
            "confidence": result.confidence,
            "attack_types": [at.value for at in result.attack_types],
            "timestamp": result.timestamp.isoformat(),
        }
        
        if self.include_evidence:
            payload["evidence"] = {
                "patterns": list(result.evidence.matched_patterns),
                "iocs": list(result.evidence.extracted_iocs),
            }
        
        req = urllib.request.Request(
            self.webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                print(f"[WebhookNotifier] Alert sent: {result.threat_level.value}")
            else:
                print(f"[WebhookNotifier] Webhook returned: {response.status}")


# Export for framework
__all__ = ["WebhookNotifierPlugin"]