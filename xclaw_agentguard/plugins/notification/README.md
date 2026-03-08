# Notification Plugin

Send real-time notifications when threats are detected.

## Usage

```python
from xclaw_agentguard.plugins.notification import (
    create_webhook_notifier,
    create_slack_notifier,
    create_console_notifier,
)

# Webhook notification
webhook = create_webhook_notifier(
    webhook_url="https://hooks.example.com/...",
    min_severity="high"
)

# Slack notification
slack = create_slack_notifier(
    webhook_url="https://hooks.slack.com/...",
    min_severity="critical",
    channel="#security-alerts"
)

# Console notification (for testing)
console = create_console_notifier(min_severity="low")

# Send notification
from xclaw_agentguard import PromptInjectionDetector

detector = PromptInjectionDetector()
result = detector.detect(user_input)

if result.detected:
    slack.notify_detection(
        detector_id=detector.get_detector_id(),
        detector_name=detector.PLUGIN_NAME,
        result=result,
        input_preview=user_input[:100]
    )
```

## Supported Notifiers

- `webhook` - Generic HTTP webhook
- `slack` - Slack incoming webhook
- `console` - Console output (for testing)

## Severity Filtering

Notifications are only sent when the threat level meets or exceeds the configured minimum:
- `low` - All detections
- `medium` - Medium and above
- `high` - High and above (recommended)
- `critical` - Critical only
