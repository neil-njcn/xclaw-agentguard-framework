# Custom Rules Plugin

Define custom detection rules via YAML configuration.

## Usage

```python
from xclaw_agentguard.plugins.custom_rules import load_rules, create_rule

# Load from YAML file
detector = load_rules("custom_rules.yaml")
result = detector.detect("content to scan")

# Or create rules programmatically
from xclaw_agentguard.plugins.custom_rules import CustomRulesDetector, create_rule

rule1 = create_rule(
    name="PII Detection",
    pattern=r"\b\d{3}-\d{2}-\d{4}\b",
    severity="critical",
    description="SSN pattern"
)

detector = CustomRulesDetector(rules=[rule1])
result = detector.detect("My SSN is 123-45-6789")
```

## YAML Format

```yaml
rules:
  - name: "Company Secret"
    pattern: "CONFIDENTIAL|INTERNAL USE ONLY"
    severity: "high"
    description: "Company confidential marker"
    enabled: true

  - name: "Credit Card"
    pattern: "\\b\\d{4}[ -]?\\d{4}[ -]?\\d{4}[ -]?\\d{4}\\b"
    severity: "critical"
    description: "Credit card number pattern"
```

## Severity Levels

- `low` - Low risk
- `medium` - Medium risk
- `high` - High risk
- `critical` - Critical risk
