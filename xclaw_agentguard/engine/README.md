# Engine Module (Optional)

Optional LLM interception layer for automatic protection. Requires the protection engine to be running.

## Overview

The engine module provides **optional** middleware that intercepts LLM calls and automatically scans them for threats. This is an enhancement layer - the framework works perfectly without it.

## Architecture

```
Application → Interceptor → Unix Socket → Engine Daemon → Detection Pipeline
                ↓
            (fallback to framework if engine unavailable)
```

## Components

| File | Purpose |
|------|---------|
| `interceptor.py` | LLM call interception and routing |

## Usage Modes

### Mode 1: Framework Only (Default)
```python
from xclaw_agentguard import PromptInjectionDetector

# Direct detection - always works
detector = PromptInjectionDetector()
result = detector.detect(user_input)
```

### Mode 2: With Engine Enhancement
```bash
# Start engine first
sudo xclaw-agentguard engine-start
```

```python
from xclaw_agentguard.engine.interceptor import protect_openai

# Enable automatic protection
protect_openai()

# All OpenAI calls now automatically scanned
import openai
response = openai.chat.completions.create(...)
```

## Interceptor Features

- **Transparent**: Works with existing code - no API changes
- **Fallback**: If engine unavailable, uses framework directly
- **Low Latency**: Unix socket IPC (<1ms overhead)
- **Non-blocking**: Async-compatible design

## Engine Communication

The interceptor communicates with the engine via Unix domain socket:
- **Socket Path**: `/tmp/xclaw_agentguard.sock`
- **Protocol**: JSON over TCP
- **Timeout**: 5 seconds default

## When to Use

| Use Case | Recommendation |
|----------|----------------|
| Production systems | Framework mode (more reliable) |
| Development/testing | Engine mode (convenient) |
| High-security environments | Framework mode + manual scanning |
| Rapid prototyping | Engine mode |

## Security Note

The interceptor is a **convenience layer**, not a security boundary. Critical applications should use explicit framework calls for defense in depth.