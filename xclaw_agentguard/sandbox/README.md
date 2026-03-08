# Sandbox Module

Isolated execution environment for MCP tools with resource limits and behavior monitoring.

## Overview

The sandbox module provides defense in depth for tool execution, preventing compromised or malicious tools from affecting the host system.

## Architecture

```
Tool Request → Sandbox Executor → Docker Container → Monitored Execution
                     ↓
              Behavior Analyzer → Anomaly Detection
```

## Components

| File | Purpose |
|------|---------|
| `sandbox_executor.py` | Main execution orchestrator |
| `docker_manager.py` | Docker container lifecycle |
| `behavior_analyzer.py` | Runtime behavior monitoring |

## Execution Modes

### Docker Mode (Preferred)
```python
from xclaw_agentguard.sandbox import SandboxExecutor

executor = SandboxExecutor()
result = executor.execute(
    tool_name="file_reader",
    command=["cat", "/etc/passwd"],
    sandbox_mode="docker"
)
```

### Fallback Mode
If Docker unavailable, uses subprocess with restrictions:
- Resource limits (CPU, memory)
- Network isolation
- Filesystem restrictions

## Security Features

| Feature | Implementation |
|---------|----------------|
| Container isolation | Docker with seccomp profiles |
| Resource limits | CPU, memory, disk quotas |
| Network isolation | No external network by default |
| Filesystem restrictions | Read-only root, tmpfs for writes |
| Timeout enforcement | Hard limits on execution time |
| Output sanitization | Prevents data exfiltration |

## Behavior Analysis

Monitors execution for anomalies:

```python
from xclaw_agentguard.sandbox import BehaviorAnalyzer

analyzer = BehaviorAnalyzer()
findings = analyzer.analyze(
    tool_execution=result,
    baseline=normal_behavior
)

if findings.has_anomalies:
    alert_security_team(findings)
```

### Detection Capabilities

- **File system anomalies**: Unexpected file access patterns
- **Network anomalies**: Unauthorized connection attempts
- **Resource anomalies**: Unusual CPU/memory consumption
- **Time anomalies**: Execution time deviations
- **Output anomalies**: Suspicious output patterns

## Configuration

```python
from xclaw_agentguard.sandbox import SandboxConfig

config = SandboxConfig(
    cpu_limit=1.0,          # 1 CPU core
    memory_limit="512m",    # 512 MB RAM
    timeout=30,             # 30 seconds
    network=False,          # No network access
    read_only=True          # Read-only filesystem
)
```

## Fallback Strategy

If Docker unavailable:
1. Attempt subprocess with restrictions
2. Apply resource limits via `ulimit`
3. Use temporary directories for isolation
4. Log warning about reduced security