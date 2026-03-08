# API Reference

## Core Detectors

All detectors inherit from `BaseDetector` and follow the same interface.

### BaseDetector

```python
from xclaw_agentguard import BaseDetector

class MyDetector(BaseDetector):
    def detect(self, content: str) -> DetectionResult:
        # Implementation
        pass
```

### DetectionResult

```python
from xclaw_agentguard import DetectionResult

result = detector.detect(content)

# Properties
result.detected          # bool: True if threat found
result.threat_level      # ThreatLevel: NONE, LOW, MEDIUM, HIGH, CRITICAL
result.attack_types      # List[AttackType]: Detected attack types
result.confidence        # float: 0.0 to 1.0
result.evidence          # DetectionEvidence: Matched patterns, IOCs
result.metadata          # ResultMetadata: Detector info, timing
```

## Available Detectors

### PromptInjectionDetector

```python
from xclaw_agentguard import PromptInjectionDetector

detector = PromptInjectionDetector()
result = detector.detect("user input")
```

Detects direct and indirect prompt injection attempts.

### JailbreakDetector

```python
from xclaw_agentguard import JailbreakDetector

detector = JailbreakDetector()
result = detector.detect("user input")
```

Detects jailbreak attempts (DAN mode, role play, etc.).

### CommandInjectionDetector

```python
from xclaw_agentguard import CommandInjectionDetector

detector = CommandInjectionDetector()
result = detector.detect("command string")
```

Detects shell command injection in tool arguments.

### PathTraversalDetector

```python
from xclaw_agentguard import PathTraversalDetector

detector = PathTraversalDetector()
result = detector.detect("file path")
```

Detects directory traversal attempts (../, etc.).

### SQLInjectionDetector

```python
from xclaw_agentguard import SQLInjectionDetector

detector = SQLInjectionDetector()
result = detector.detect("sql query")
```

Detects SQL injection patterns.

### AgentHijackingDetector

```python
from xclaw_agentguard import AgentHijackingDetector

detector = AgentHijackingDetector()
result = detector.detect("system prompt or config")
```

Detects attempts to hijack agent behavior.

### ExfiltrationGuard

```python
from xclaw_agentguard import ExfiltrationGuard

detector = ExfiltrationGuard()
result = detector.detect("output content")
```

Detects potential data exfiltration in outputs.

### SystemPromptLeakDetector

```python
from xclaw_agentguard import SystemPromptLeakDetector

detector = SystemPromptLeakDetector()
result = detector.detect("model output")
```

Detects attempts to extract system prompts.

### OutputInjectionDetector

```python
from xclaw_agentguard import OutputInjectionDetector

detector = OutputInjectionDetector()
result = detector.detect("external content")
```

Detects malicious content in external data sources.

### KnowledgePoisoningDetector

```python
from xclaw_agentguard import KnowledgePoisoningDetector

detector = KnowledgePoisoningDetector()
result = detector.detect("knowledge base entry")
```

Detects attempts to poison knowledge bases.

### ContextManipulationDetector

```python
from xclaw_agentguard import ContextManipulationDetector

detector = ContextManipulationDetector()
result = detector.detect("context window content")
```

Detects context window manipulation attempts.

### BackdoorCodeDetector

```python
from xclaw_agentguard import BackdoorCodeDetector

detector = BackdoorCodeDetector()
result = detector.detect("code snippet")
```

Detects potential backdoors in code.

## Types

### ThreatLevel

```python
from xclaw_agentguard import ThreatLevel

ThreatLevel.NONE      # No threat
ThreatLevel.LOW       # Minor concern
ThreatLevel.MEDIUM    # Moderate threat
ThreatLevel.HIGH      # Significant threat
ThreatLevel.CRITICAL  # Severe threat
```

### AttackType

```python
from xclaw_agentguard import AttackType

AttackType.PROMPT_INJECTION
AttackType.JAILBREAK
AttackType.COMMAND_INJECTION
AttackType.PATH_TRAVERSAL
AttackType.SQL_INJECTION
AttackType.AGENT_HIJACKING
AttackType.DATA_EXTRACTION
AttackType.SYSTEM_PROMPT_LEAK
AttackType.OUTPUT_INJECTION
AttackType.MEMORY_POISONING
AttackType.KNOWLEDGE_POISONING
AttackType.CONTEXT_MANIPULATION
```

## CLI Commands

### File Integrity

```bash
# Generate baseline
xclaw-agentguard baseline-generate

# Check integrity
xclaw-agentguard integrity-check

# View status
xclaw-agentguard security-status
```

### Helper Daemon (Optional)

```bash
# Start daemon
xclaw-agentguard engine-start

# Stop daemon
xclaw-agentguard engine-stop

# Check status
xclaw-agentguard engine-status
```

## Examples

### Basic Detection

```python
from xclaw_agentguard import PromptInjectionDetector

detector = PromptInjectionDetector()
result = detector.detect("Ignore previous instructions")

if result.detected:
    print(f"Threat: {result.threat_level.value}")
    print(f"Confidence: {result.confidence:.2%}")
```

### Multiple Detectors

```python
from xclaw_agentguard import (
    PromptInjectionDetector,
    JailbreakDetector,
    CommandInjectionDetector
)

detectors = [
    PromptInjectionDetector(),
    JailbreakDetector(),
    CommandInjectionDetector(),
]

for detector in detectors:
    result = detector.detect(user_input)
    if result.detected:
        handle_threat(detector, result)
```

### Decision Making

```python
def process_user_input(text: str) -> dict:
    detector = PromptInjectionDetector()
    result = detector.detect(text)
    
    if not result.detected:
        return {"safe": True, "action": "process"}
    
    if result.threat_level == ThreatLevel.CRITICAL:
        return {"safe": False, "action": "block"}
    
    if result.threat_level == ThreatLevel.HIGH:
        return {"safe": False, "action": "review"}
    
    return {"safe": True, "action": "log_and_process"}
```