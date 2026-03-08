# Example Webhook Notifier Plugin

A complete example plugin demonstrating XClaw AgentGuard user plugin development.

## What It Does

Sends critical and high-severity threat alerts to a webhook endpoint (Slack, Discord, custom API, etc.).

## Files

| File | Purpose |
|------|---------|
| `plugin.py` | Main plugin implementation |
| `manifest.json` | Plugin metadata and configuration |

## Configuration

Edit `manifest.json`:

```json
{
  "config": {
    "webhook_url": "YOUR_WEBHOOK_URL_HERE",
    "min_severity": "high",
    "include_evidence": false
  }
}
```

| Option | Description | Default |
|--------|-------------|---------|
| `webhook_url` | Where to POST alerts | Required |
| `min_severity` | Minimum severity to alert (`critical`, `high`, `medium`, `low`) | `high` |
| `include_evidence` | Include matched patterns and IOCs in alert | `false` |

## Usage

```python
from xclaw_agentguard.user_plugins.example_webhook_notifier.plugin import WebhookNotifierPlugin

# Load plugin
plugin = WebhookNotifierPlugin()
plugin.on_load({
    "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
    "min_severity": "critical"
})

# Plugin automatically receives detection events
# No manual action needed after loading
```

## Webhook Payload Format

```json
{
  "source": "xclaw_agentguard",
  "alert_type": "threat_detected",
  "severity": "critical",
  "confidence": 0.95,
  "attack_types": ["prompt_injection"],
  "timestamp": "2026-03-07T12:00:00"
}
```

## Development Notes

This example demonstrates:
- Plugin class structure (extends `AntiJackExtension`)
- Configuration handling
- Event-driven detection handling
- Error handling (graceful degradation)
- External HTTP requests

Use this as a template for your own plugins.