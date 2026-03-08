# Threat Intelligence Module

Continuous threat monitoring with CVE tracking, feed aggregation, and alert correlation.

## Overview

The threat intel module keeps XClaw AgentGuard current with emerging threats by monitoring security feeds and correlating alerts.

## Components

| File | Purpose |
|------|---------|
| `cve_fetcher.py` | CVE database monitoring |
| `feed_updater.py` | Threat feed aggregation |
| `intel_analyzer.py` | Intelligence analysis and prioritization |
| `alert_correlator.py` | Multi-source alert correlation |

## CVE Fetcher

Monitors CVE databases for agent-related vulnerabilities:

```python
from xclaw_agentguard.threat_intel import CVEFetcher

fetcher = CVEFetcher()
new_cves = fetcher.check_updates(
    keywords=["AI", "LLM", "agent", "prompt injection"]
)

for cve in new_cves:
    if cve.severity == "CRITICAL":
        immediate_response(cve)
```

### Data Sources

- NVD (National Vulnerability Database)
- GitHub Security Advisories
- Vendor security bulletins
- Research publications

## Feed Updater

Aggregates threat intelligence from multiple sources:

| Feed Type | Update Frequency |
|-----------|------------------|
| Attack patterns | Hourly |
| IOC lists | Every 4 hours |
| Research papers | Daily |
| Community reports | Real-time |

## Intel Analyzer

Processes and prioritizes threat intelligence:

```python
from xclaw_agentguard.threat_intel import IntelAnalyzer

analyzer = IntelAnalyzer()
priority_intel = analyzer.analyze(
    feeds=collected_feeds,
    context=my_environment
)
```

### Analysis Dimensions

- **Relevance**: Applicability to AI agents
- **Severity**: Potential impact assessment
- **Urgency**: Exploitation likelihood
- **Actionability**: Can we detect/prevent it?

## Alert Correlator

Connects disparate alerts to identify campaigns:

```
Alert A: Prompt injection attempt
Alert B: Unusual tool usage
Alert C: Data access anomaly
        ↓
Correlated: Coordinated attack campaign
```

### Correlation Rules

- **Temporal**: Alerts within time window
- **Source**: Same attacker indicators
- **Target**: Same protected resources
- **Pattern**: Attack chain progression

## Integration

Threat intelligence feeds into:
- Detector pattern updates
- Security dashboard
- Incident response workflows
- Executive briefings

## Privacy

All threat intel processing is local:
- No data sent to external services
- Optional anonymous statistics
- On-premise feed sources supported