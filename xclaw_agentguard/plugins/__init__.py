"""
XClaw XClaw AgentGuard Plugins - Built-in Plugin Directory

Standard structure for each plugin:
    plugin_name/
    ├── __init__.py      # Package entry
    ├── manifest.json    # Plugin manifest
    ├── plugin.py        # Main implementation
    └── README.md        # Documentation (optional)

## Essential Plugins

- report_formatter    # Report formatting (JSON/Markdown/CSV)
- custom_rules        # Custom rules (YAML configuration)
- audit_logger        # Audit logging (file/SQLite)
- notification        # Real-time notifications (Webhook/Slack/Console)

## Example Plugins

- example_plugin      # Basic example
- versioned_example   # Version management example
"""

# Report Formatter Plugin
from .report_formatter import (
    ReportFormatterPlugin,
    JSONFormatter,
    MarkdownFormatter,
    CSVFormatter,
    format_json,
    format_markdown,
    format_csv,
    format_batch,
)

# Custom Rules Plugin
from .custom_rules import (
    CustomRulesPlugin,
    CustomRulesDetector,
    CustomRule,
    load_rules,
    create_rule,
)

# Audit Logger Plugin
from .audit_logger import (
    AuditLoggerPlugin,
    FileLogger,
    SQLiteLogger,
    AuditEntry,
    create_logger,
)

# Notification Plugin
from .notification import (
    NotificationPlugin,
    BaseNotifier,
    WebhookNotifier,
    SlackNotifier,
    ConsoleNotifier,
    create_webhook_notifier,
    create_slack_notifier,
    create_console_notifier,
)

# Example Plugins
from .example_plugin import ExamplePlugin
from .versioned_example import VersionedExamplePlugin, UpgradablePlugin

__all__ = [
    # Report Formatter
    "ReportFormatterPlugin",
    "JSONFormatter",
    "MarkdownFormatter",
    "CSVFormatter",
    "format_json",
    "format_markdown",
    "format_csv",
    "format_batch",
    # Custom Rules
    "CustomRulesPlugin",
    "CustomRulesDetector",
    "CustomRule",
    "load_rules",
    "create_rule",
    # Audit Logger
    "AuditLoggerPlugin",
    "FileLogger",
    "SQLiteLogger",
    "AuditEntry",
    "create_logger",
    # Notification
    "NotificationPlugin",
    "BaseNotifier",
    "WebhookNotifier",
    "SlackNotifier",
    "ConsoleNotifier",
    "create_webhook_notifier",
    "create_slack_notifier",
    "create_console_notifier",
    # Examples
    "ExamplePlugin",
    "VersionedExamplePlugin",
    "UpgradablePlugin",
]
