# Audit Logger Plugin

Persistent audit logging for all detection results.

## Usage

```python
from xclaw_agentguard.plugins.audit_logger import create_logger
from xclaw_agentguard import PromptInjectionDetector

# Create logger
logger = create_logger("sqlite", db_path="audit.db")
# or
logger = create_logger("file", log_file="audit.log")

# Use with detector
detector = PromptInjectionDetector()
result = detector.detect(user_input)

# Log the detection
logger.log(
    detector_id=detector.get_detector_id(),
    detector_name=detector.PLUGIN_NAME,
    input_text=user_input,
    result=result
)

# Query logs
entries = logger.query(
    start_time="2026-03-01",
    min_severity="high",
    limit=100
)

# Get statistics (SQLite only)
stats = logger.get_stats()
print(f"Detection rate: {stats['detection_rate']:.2%}")
```

## Backends

- `file` - JSON file storage (simple, human-readable)
- `sqlite` - SQLite database (fast queries, statistics)

## Configuration

```json
{
  "backend": "sqlite",
  "db_path": "audit.db",
  "log_file": "audit.log"
}
```
