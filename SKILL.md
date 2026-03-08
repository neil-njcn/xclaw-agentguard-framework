# XClaw AgentGuard Framework v2.3.1

Security detection library for AI agents. 12 detectors, you call them explicitly.

## Quick Start

```python
from xclaw_agentguard import PromptInjectionDetector, JailbreakDetector

detector = PromptInjectionDetector()
result = detector.detect("user input")

if result.detected:
    print(f"Threat: {result.threat_level}")
    # Your app decides: block, log, or continue
```

## The 12 Detectors

| Detector | Catches |
|----------|---------|
| PromptInjectionDetector | "ignore previous instructions" |
| JailbreakDetector | DAN mode, developer mode |
| AgentHijackingDetector | Tool misuse, privilege escalation |
| CommandInjectionDetector | Shell metacharacters |
| PathTraversalDetector | `../../etc/passwd` |
| SQLInjectionDetector | SQL escape attempts |
| BackdoorCodeDetector | Hidden malicious code |
| ExfiltrationGuard | API keys in output |
| OutputInjectionDetector | Phishing in responses |
| SystemPromptLeakDetector | System prompt extraction |
| KnowledgePoisoningDetector | False info injection |
| ContextManipulationDetector | Context tampering |

## Usage Pattern

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

for d in detectors:
    r = d.detect(content)
    if r.detected:
        handle_threat(r)  # Your implementation
```

## Self-Protection (Optional)

Protects against CVE-2026-25253 (ClawJacked) — detects unauthorized modifications to framework files:

```bash
xclaw-agentguard baseline-generate   # Create baseline
xclaw-agentguard integrity-check     # Verify files
xclaw-agentguard security-status     # View status
```

## Key Principle

> **This library detects. Your code decides.**

No automatic blocking. No transparent interception. You call `detect()`, you handle results.

## Install

**Recommended (OpenClaw):**
```bash
openclaw skills install https://github.com/neil-njcn/xclaw-agentguard-framework
```

**Alternative (pip):**
```bash
# Core library
pip install xclaw-agentguard-framework

# With helper daemon
pip install xclaw-agentguard-framework[engine]
```

## Full Docs

- [README.md](README.md) - Complete documentation
- [docs/API.md](docs/API.md) - API reference
- [docs/DEPLOYMENT.en.md](docs/DEPLOYMENT.en.md) - Integration guide

MIT License
