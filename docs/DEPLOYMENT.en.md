# XClaw AgentGuard Deployment Guide

## What This Is

XClaw AgentGuard is a Python library that gives you security detectors for AI applications. You call the detectors explicitly in your code. It doesn't do anything automatically.

**Key point**: This is a library you integrate, not a product that protects you out of the box.

---

## How It Works

| You Get | You Don't Get |
|---------|---------------|
| Functions to call for threat detection | Automatic request interception |
| Detection results to act on | Automatic blocking or decisions |
| Tools to build security into your app | A complete security solution |

**Two ways to use it:**

1. **Direct API** (recommended): Import detectors, call them in your code
2. **Helper daemon** (optional): Background process for convenience wrappers

---

## Install

**Best for OpenClaw agents:**
```bash
openclaw skills install https://github.com/neil-njcn/xclaw-agentguard-framework
```

**Or via pip:**
```bash
# Core library
pip install xclaw-agentguard-framework

# With optional helper daemon
pip install xclaw-agentguard-framework[engine]
```

---

## Direct API (Recommended)

### Basic usage

```python
from xclaw_agentguard import PromptInjectionDetector

detector = PromptInjectionDetector()
result = detector.detect("user input here")

if result.detected:
    print(f"Threat level: {result.threat_level}")
    # You decide what to do: block, log, flag, etc.
```

### Chain multiple detectors

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
    r = d.detect(user_input)
    if r.detected:
        handle_threat(r)  # Your logic here
```

### Example: Guarding an LLM client

```python
from xclaw_agentguard import PromptInjectionDetector

class GuardedLLM:
    def __init__(self):
        self.detector = PromptInjectionDetector()
    
    def generate(self, user_input: str):
        result = self.detector.detect(user_input)
        
        if result.detected and result.threat_level.value in ["high", "critical"]:
            return {"error": "Input blocked", "reason": result.threat_level.value}
        
        return self.call_llm(user_input)
```

---

## Helper Daemon (Optional)

The helper daemon is a convenience layer, not required.

**Install with daemon support:**
```bash
pip install xclaw-agentguard-framework[engine]
```

**Start the daemon:**
```bash
# Foreground
xclaw-agentguard engine-start

# Background
xclaw-agentguard engine-start --daemon
```

**Use the OpenAI interceptor:**
```python
from xclaw_agentguard.engine.interceptor import protect_openai

protect_openai()  # Wraps OpenAI calls with detection
```

If the daemon isn't running, calls fall through to the original client silently.

---

## Self-Protection (Anti-Jacked)

Monitors the framework's own files for tampering. Protects against CVE-2026-25253 where attackers modify security tools to disable them.

```bash
# Create integrity baseline
xclaw-agentguard baseline-generate

# Check for tampering
xclaw-agentguard integrity-check

# View status
xclaw-agentguard security-status
```

---

## The 12 Detectors

| Detector | What it catches |
|----------|-----------------|
| `PromptInjectionDetector` | "Ignore previous instructions" attacks |
| `JailbreakDetector` | DAN mode, developer mode, roleplay escapes |
| `AgentHijackingDetector` | Tool misuse, privilege escalation |
| `CommandInjectionDetector` | Shell command injection |
| `PathTraversalDetector` | `../../etc/passwd` attacks |
| `SQLInjectionDetector` | SQL injection in tool parameters |
| `BackdoorCodeDetector` | Hidden backdoor code |
| `ExfiltrationGuard` | API keys, passwords in output |
| `OutputInjectionDetector` | Phishing links, malicious content |
| `SystemPromptLeakDetector` | Attempts to extract system prompts |
| `KnowledgePoisoningDetector` | False facts injected into knowledge base |
| `ContextManipulationDetector` | Memory/context tampering |

**Import:**
```python
from xclaw_agentguard import PromptInjectionDetector, JailbreakDetector
# or
from xclaw_agentguard import *
```

---

## Requirements

- Python 3.12.x
- 512MB RAM minimum
- ~50MB disk
- Docker optional (for sandbox features)

---

## Configuration

**No config files needed.** The direct API works out of the box with sensible defaults.

Optional env vars:
```bash
export AGENTGUARD_LOG_LEVEL=INFO
export AGENTGUARD_SOCKET=/tmp/xclaw_agentguard.sock
```

---

## Troubleshooting

**Import fails:**
```bash
pip list | grep xclaw-agentguard-framework
```

**Daemon won't start:**
```bash
pip install xclaw-agentguard-framework[engine]  # Check deps
ls -la /tmp/  # Check permissions
```

**Detector throws:**
```python
result = detector.detect(str(user_input))  # Must be string
```

---

## Key Points

### Detection is not protection

The framework tells you if something looks suspicious. You decide what to do:

```python
result = detector.detect(input)

if result.detected:
    # Your call:
    # - Block it?
    # - Log and continue?
    # - Send to human review?
    # - Rate limit?
    handle(result)  # Your implementation
```

### Security has no silver bullet

- Expect false positives and false negatives
- New attacks get invented
- This is one tool in your security toolkit, not the whole toolkit

---

## Quick Reference

| Feature | Needs config? | Needs daemon? |
|---------|---------------|---------------|
| Basic detection | No | No |
| Multiple detectors | No | No |
| File integrity checks | Baseline only | No |
| OpenAI wrapper | No | Yes |

**Easiest way to start:** `pip install`, `import`, call `detect()`. No setup required.
