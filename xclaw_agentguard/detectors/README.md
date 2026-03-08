# XClaw AgentGuard Detectors

This directory contains 12 specialized security detectors organized by threat category.

## Directory Structure

```
detectors/
├── agent_hijacking/          # CVE-2026-25253 protection
│   └── detector.py           # AgentHijackingDetector
├── backdoor_code/            # Backdoor detection
│   └── detector.py           # BackdoorCodeDetector
├── exfiltration_guard/       # Data exfiltration prevention
│   └── detector.py           # ExfiltrationGuard
├── jailbreak/                # Jailbreak attempt detection
│   └── detector.py           # JailbreakDetector
├── memory_poisoning/         # Memory/knowledge attacks
│   ├── knowledge_poisoning.py    # KnowledgePoisoningDetector
│   └── context_manipulation.py   # ContextManipulationDetector
├── output_injection/         # Output manipulation
│   └── detector.py           # OutputInjectionDetector
├── prompt_injection/         # Prompt injection attacks
│   └── detector.py           # PromptInjectionDetector
├── system_prompt_leak/       # Prompt extraction attempts
│   └── detector.py           # SystemPromptLeakDetector
└── tool_poisoning/           # Tool/command attacks
    ├── command_inj.py        # CommandInjectionDetector
    ├── path_traversal.py     # PathTraversalDetector
    └── sql_injection.py      # SQLInjectionDetector
```

## Design Rationale

Detectors are grouped into **9 directories** by threat category rather than having 12 separate directories:

| Category | Detectors | Rationale |
|----------|-----------|-----------|
| `tool_poisoning/` | 3 detectors | Command injection, path traversal, and SQL injection share similar input validation patterns and tool execution contexts |
| `memory_poisoning/` | 2 detectors | Knowledge poisoning and context manipulation both target agent memory/state systems |
| Others | 1 detector each | Unique threat vectors requiring specialized detection logic |

## Creating a New Detector

1. Create a new directory or add to an existing category
2. Inherit from `BaseDetector` in `xclaw_agentguard.base`
3. Implement required methods:
   - `detect(content: str) -> DetectionResult`
   - `get_metadata() -> Dict[str, Any]`
4. Add patterns to `patterns.py` or JSON files
5. Register in `xclaw_agentguard/__init__.py`
6. Add tests in `tests/test_attacks.py`

## Detector Interface

```python
from xclaw_agentguard import BaseDetector, DetectionResult

class MyDetector(BaseDetector):
    def detect(self, content: str) -> DetectionResult:
        # Detection logic
        if self._is_threat(content):
            return DetectionResult.threat(
                attack_type=AttackType.MY_ATTACK,
                metadata=self._create_metadata()
            )
        return DetectionResult.clean(metadata=self._create_metadata())
```

## Pattern Organization

- **Simple patterns**: Store in `patterns.py` as regex constants
- **Complex patterns**: Store in JSON files for easy updates
- **Dynamic patterns**: Load from threat intel feeds at runtime

## Testing

All detectors must pass:
- Unit tests in `tests/test_attacks.py`
- Integration tests in `tests/integration/`
- Performance benchmarks (target: <10ms per detection)
- False positive validation against benign inputs