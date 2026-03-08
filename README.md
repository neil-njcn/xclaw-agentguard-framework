# XClaw AgentGuard Framework v2.3.1

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Python library providing security detection capabilities for AI agent applications. Includes 12 specialized detectors for identifying prompt injection, jailbreak attempts, command injection, and other threats.

## What This Is

**XClaw AgentGuard Framework** is a library, not a standalone security product. It provides:

- **Detection tools** that developers can integrate into their applications
- **Optional helper daemon** for convenience (not required for core functionality)
- **Self-protection utilities** for monitoring the framework's own integrity

**What it is not:**
- ❌ An automatic protection system that works without code changes
- ❌ A transparent security layer that intercepts all traffic
- ❌ A guarantee of security (no system can promise that)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Your Application                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ User Input  │  │ Tool Calls  │  │  External Data          │ │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘ │
│         │                │                      │               │
│         └────────────────┼──────────────────────┘               │
│                          ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  You call: detector.detect(input)                       │   │
│  │  (Explicit integration required)                        │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              XClaw AgentGuard Framework                         │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Detection Library (Always Available)                   │   │
│  │  • 12 threat detectors                                  │   │
│  │  • Pattern matching & analysis                          │   │
│  │  • Confidence scoring                                   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│  ┌───────────────────────────┴───────────────────────────┐     │
│  │  Optional: Helper Daemon (Requires [engine] extra)    │     │
│  │  • Convenience wrapper for common use cases           │     │
│  │  • Not required for core functionality                │     │
│  └───────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

### Recommended: OpenClaw

```bash
openclaw skills install https://github.com/neil-njcn/xclaw-agentguard-framework
```

Best for OpenClaw agents. Auto-registers detectors, integrates with agent lifecycle.

### Alternative: pip

**Basic installation:**
```bash
pip install xclaw-agentguard-framework
```

Includes: 12 detectors, self-protection, CLI tools.

**With helper daemon:**
```bash
pip install xclaw-agentguard-framework[engine]
```

Adds: background helper process, convenience interceptors.

## Quick Start

### Basic Detection (Framework Mode)

```python
from xclaw_agentguard import PromptInjectionDetector

# Create detector instance
detector = PromptInjectionDetector()

# Check user input
result = detector.detect(user_input)

if result.detected:
    print(f"Potential threat detected: {result.threat_level}")
    # Your application decides how to handle this
```

### Using Multiple Detectors

```python
from xclaw_agentguard import (
    PromptInjectionDetector,
    JailbreakDetector,
    CommandInjectionDetector
)

def security_check(text: str) -> dict:
    detectors = [
        PromptInjectionDetector(),
        JailbreakDetector(),
        CommandInjectionDetector(),
    ]
    
    threats = []
    for detector in detectors:
        result = detector.detect(text)
        if result.detected:
            threats.append({
                "type": result.attack_types[0].value,
                "confidence": result.confidence
            })
    
    return {
        "safe": len(threats) == 0,
        "threats": threats
    }
```

### Optional: Helper Daemon

The helper daemon is a convenience layer, not required for core functionality:

```bash
# Start helper daemon
xclaw-agentguard engine-start
```

```python
from xclaw_agentguard.engine.interceptor import protect_openai

# Enable convenience wrapper for OpenAI
protect_openai()

# Subsequent OpenAI calls are routed through detectors
# (Only works if daemon is running)
```

**Note:** If the daemon is not running, `protect_openai()` will log a warning and pass through to the original OpenAI client.

## Available Detectors

| Detector | Threat Type |
|----------|-------------|
| `PromptInjectionDetector` | Prompt injection |
| `JailbreakDetector` | Jailbreak attempts |
| `AgentHijackingDetector` | Agent hijacking |
| `CommandInjectionDetector` | Command injection |
| `PathTraversalDetector` | Path traversal |
| `SQLInjectionDetector` | SQL injection |
| `BackdoorCodeDetector` | Backdoor code |
| `ExfiltrationGuard` | Data exfiltration |
| `OutputInjectionDetector` | Output injection |
| `SystemPromptLeakDetector` | Prompt extraction |
| `KnowledgePoisoningDetector` | Knowledge poisoning |
| `ContextManipulationDetector` | Context manipulation |

All detectors can be imported directly from the package:

```python
from xclaw_agentguard import PromptInjectionDetector, JailbreakDetector
```

## Self-Protection (Anti-Jacked)

The framework includes utilities to monitor its own integrity:

```bash
# Generate baseline of critical files
xclaw-agentguard baseline-generate

# Check for unauthorized modifications
xclaw-agentguard integrity-check

# View current status
xclaw-agentguard security-status
```

This protects against CVE-2026-25253 (ClawJacked), a vulnerability where attackers modify agent files to disable security controls.

## Important Clarifications

### What This Framework Does

✅ Provides detection tools you can call from your code  
✅ Returns structured results with confidence scores  
✅ Offers optional helper utilities  
✅ Includes self-protection for its own files  

### What This Framework Does NOT Do

❌ Automatically protect your application without code changes  
❌ Transparently intercept all LLM calls (unless explicitly integrated)  
❌ Guarantee security (detection can have false negatives)  
❌ Replace proper security engineering practices  

### Detection vs. Protection

This framework **detects** potential threats. Your application must decide what to do with the results:

```python
result = detector.detect(input)

if result.detected:
    # You decide:
    # - Block the request?
    # - Log and continue?
    # - Escalate to human review?
    # - Apply additional constraints?
    handle_threat(result)  # Your implementation
```

## System Requirements

- Python 3.12.x
- 512MB RAM minimum
- ~50MB disk space
- Optional: Docker (for sandbox features)

## Platform Support

| Platform | Framework | Helper Daemon |
|----------|-----------|---------------|
| macOS | ✅ | ✅ |
| Linux | ✅ | ✅ |
| Windows | ⚠️ Not tested | ⚠️ Not tested |

## CLI Commands

```bash
# File integrity management
xclaw-agentguard baseline-generate   # Create integrity baseline
xclaw-agentguard integrity-check     # Verify file integrity
xclaw-agentguard security-status     # Show framework status

# Helper daemon (optional)
xclaw-agentguard engine-start        # Start helper daemon
xclaw-agentguard engine-stop         # Stop helper daemon
xclaw-agentguard engine-status       # Check daemon status
```

## Documentation

- [API Reference](docs/API.md) — Detailed detector documentation
- [Deployment Guide](docs/DEPLOYMENT.en.md) — English integration guide
- [Deployment Guide (中文)](docs/DEPLOYMENT.zh.md) — 中文部署指南

## License

MIT License - See [LICENSE](LICENSE) for details.

## Authors

XClaw AgentGuard Security Team

## Acknowledgments

This project wouldn't exist without [duru-memory](https://github.com/IanGYan/duru-memory) by IanGYan. Seeing a well-crafted OpenClaw skill in the open gave us both the technical reference and the push we needed to refine and release AgentGuard. Thanks for leading the way.

---

**Disclaimer:** This framework provides detection capabilities to assist with security. It does not guarantee protection against all threats. Security is a process, not a product. Use as part of a comprehensive security strategy including code review, testing, and monitoring.