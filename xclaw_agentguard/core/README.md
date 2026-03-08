# Core Module

Foundation infrastructure for XClaw AgentGuard - types, schemas, and extension system.

## Overview

The core module provides the foundational building blocks used by all other modules: type definitions, configuration schemas, base classes, and the extension system.

## Components

| File | Purpose |
|------|---------|
| `base_detector.py` | Abstract base class for all detectors |
| `detection_result.py` | Type-safe result types with Builder pattern |
| `config_schema.py` | Declarative configuration system |
| `extension_system.py` | Plugin architecture and sandboxing |
| `version_management.py` | Plugin versioning and compatibility |
| `canary_controller.py` | Canary release mechanism |
| `canary_registry.py` | Canary deployment tracking |
| `anti_jacked_ext_core.py` | Extension security integration |

## BaseDetector

All detectors inherit from this abstract base:

```python
from xclaw_agentguard.core.base_detector import BaseDetector

class MyDetector(BaseDetector):
    def detect(self, content: str) -> DetectionResult:
        # Implementation
        pass
    
    def get_metadata(self) -> Dict[str, Any]:
        return {
            "name": "my_detector",
            "version": "1.0.0",
            "description": "Detects specific threats"
        }
```

### Template Method Pattern

BaseDetector defines the detection workflow:
1. **Pre-processing**: Input normalization
2. **Detection**: Pattern matching / analysis
3. **Post-processing**: Result validation
4. **Logging**: Audit trail

## DetectionResult

Immutable, type-safe result container:

```python
from xclaw_agentguard.core.detection_result import (
    DetectionResult,
    ThreatLevel,
    AttackType,
    DetectionResultBuilder
)

# Builder pattern
result = DetectionResult.builder() \
    .detected(True) \
    .threat_level(ThreatLevel.HIGH) \
    .attack_type(AttackType.PROMPT_INJECTION) \
    .confidence(0.95) \
    .metadata("detector_1", "1.0.0", 42.0) \
    .build()
```

### Key Features

- **Immutable**: Frozen dataclass - results can't be tampered with
- **Type-safe**: Enums for all categorical values
- **Serializable**: Full JSON support
- **Validated**: Consistency checks in `__post_init__`

## ConfigSchema

Declarative configuration with validation:

```python
from xclaw_agentguard.core.config_schema import ConfigSchema, ConfigValidator

schema = ConfigSchema({
    "threshold": {"type": "float", "min": 0.0, "max": 1.0, "default": 0.5},
    "enabled": {"type": "bool", "default": True}
})

is_valid, errors = ConfigValidator.validate(config, schema)
```

## Extension System

Plugin architecture with security sandboxing:

```python
from xclaw_agentguard.core.extension_system import AntiJackExtension

class MyPlugin(AntiJackExtension):
    def on_load(self):
        # Plugin initialization
        pass
    
    def on_detect(self, result: DetectionResult):
        # React to detections
        pass
```

### Security Features

- **Sandboxing**: Plugins run in restricted environment
- **Capability model**: Explicit permission declarations
- **Version constraints**: Compatibility checking
- **Violation handling**: Automatic plugin disable on misbehavior

## Version Management

Semantic versioning for plugins:

```python
from xclaw_agentguard.core.version_management import (
    PluginVersion,
    VersionConstraint,
    check_version_constraint
)

version = PluginVersion.parse("2.3.1")
constraint = VersionConstraint.parse(">=2.0.0,<3.0.0")
is_compatible = check_version_constraint(version, constraint)
```

## Design Principles

1. **Type Safety**: Pydantic + type hints throughout
2. **Immutability**: Results and configs are frozen after creation
3. **Extensibility**: Plugin system allows custom extensions
4. **Validation**: All inputs validated before use
5. **Documentation**: Self-documenting code with docstrings