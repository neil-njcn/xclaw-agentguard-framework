# Anti-Jacked Security Base

Self-protection system against CVE-2026-25253 (ClawJacked vulnerability) and other integrity attacks.

## Overview

The Anti-Jacked module provides tamper detection, immutable logging, and auto-recovery capabilities to protect XClaw AgentGuard itself from compromise.

## The Vulnerability

**CVE-2026-25253**: Critical agent hijacking vulnerability discovered February 2026

| Attribute | Value |
|-----------|-------|
| Severity | Critical |
| Type | Agent Hijacking / Integrity Bypass |
| Attack Vectors | Config tampering, script replacement, genome poisoning |

## Components

| File | Purpose |
|------|---------|
| `baseline_generator.py` | SHA256 integrity baselines for critical files |
| `immutable_log.py` | Tamper-evident append-only audit chain |
| `tamper_detector.py` | Real-time integrity verification |
| `auto_recovery.py` | Self-healing from detected compromise |
| `integrity_monitor.py` | Main coordination and scheduling |
| `cli.py` | Command-line interface for security operations |

## Architecture

```
File System → Baseline Generator → Integrity Monitor
                    ↓
            Immutable Log Chain
                    ↓
            Tamper Detector → Alert / Auto-Recovery
```

## Workflow

### 1. Baseline Generation
```bash
xclaw-agentguard baseline-generate
```

Creates cryptographic hashes of all critical files:
- All Python source files
- Configuration files
- JSON schemas
- Plugin manifests

### 2. Continuous Monitoring
```bash
xclaw-agentguard monitor-start
```

Options:
- **Scheduled**: Periodic scans (every 15 minutes)
- **Real-time**: File system event monitoring
- **On-demand**: Manual integrity checks

### 3. Tamper Detection
When unauthorized changes detected:
1. Log to immutable chain
2. Alert security team
3. Enter lockdown mode
4. Trigger auto-recovery (if enabled)

### 4. Auto-Recovery
```bash
xclaw-agentguard auto-recover
```

Restores compromised files from verified backups:
- Quarantine unauthorized files
- Restore from trusted baseline
- Verify recovery success
- Generate incident report

## Immutable Log Chain

Cryptographically chained audit log:

```
Entry 1: hash = SHA256(data)
Entry 2: hash = SHA256(data + Entry 1.hash)
Entry 3: hash = SHA256(data + Entry 2.hash)
...
```

Any tampering breaks the chain - immediately detectable.

## CLI Commands

| Command | Purpose |
|---------|---------|
| `baseline-generate` | Create integrity baseline |
| `integrity-check` | Verify current state |
| `monitor-start` | Start continuous monitoring |
| `auto-recover` | Restore from compromise |
| `security-status` | Show security overview |

## Critical Files Monitored

- `xclaw_agentguard/config/*.py`
- `xclaw_agentguard/core/*.py`
- `xclaw_agentguard/anti_jacked/*.py`
- `xclaw_agentguard/detectors/*/detector.py`
- All JSON configuration files

## Response Levels

| Level | Trigger | Action |
|-------|---------|--------|
| Info | Baseline updated | Log only |
| Warning | Validation failed | Alert |
| Critical | Tampering detected | Lockdown + Recovery |
| Emergency | Self-compromised | Full shutdown |

## Integration

Anti-Jacked integrates with:
- Plugin system (security event hooks)
- Dashboard (real-time status)
- Notification system (alerts)
- External SIEM (optional)