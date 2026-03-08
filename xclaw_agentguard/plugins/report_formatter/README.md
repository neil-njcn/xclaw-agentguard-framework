# Report Formatter Plugin

Format detection results to multiple output formats.

## Usage

```python
from xclaw_agentguard.plugins.report_formatter import (
    ReportFormatterPlugin,
    format_json,
    format_markdown,
    format_csv,
)

from xclaw_agentguard import PromptInjectionDetector

detector = PromptInjectionDetector()
result = detector.detect("user input")

# JSON format
json_output = format_json(result, indent=2)

# Markdown format
md_output = format_markdown(result)

# CSV format
csv_output = format_csv(result)

# Batch formatting
results = [
    ("prompt_injection", "input1", result1),
    ("jailbreak", "input2", result2),
]
report = ReportFormatterPlugin.format_batch(results, "markdown")
```

## Supported Formats

- `json` - JSON format with optional indentation
- `markdown` - Markdown table format
- `csv` - Comma-separated values

## Configuration

```json
{
  "default_format": "json",
  "json_indent": 2,
  "csv_delimiter": ","
}
```
