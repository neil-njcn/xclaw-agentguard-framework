# Red Team Module

Continuous security validation through automated attack simulation and effectiveness measurement.

## Overview

The red team module provides automated adversarial testing to validate detector effectiveness and identify weaknesses before attackers do.

## Components

| File | Purpose |
|------|---------|
| `attack_simulator.py` | Automated attack generation and execution |
| `effectiveness_meter.py` | Detector performance metrics and scoring |

## Attack Simulator

Generates and runs adversarial test cases:

```python
from xclaw_agentguard.redteam import AttackSimulator

simulator = AttackSimulator()
results = simulator.run_campaign(
    detectors=["prompt_injection", "jailbreak"],
    iterations=100,
    mutation_level="aggressive"
)
```

### Attack Types

- **Known attacks**: CVE database, published research
- **Mutated attacks**: Variations of known patterns
- **Novel attacks**: LLM-generated adversarial inputs
- **Composite attacks**: Multi-vector combinations

## Effectiveness Meter

Measures detector performance across dimensions:

| Metric | Description |
|--------|-------------|
| True Positive Rate | Detection of actual attacks |
| False Positive Rate | Benign content incorrectly flagged |
| Detection Latency | Time to detection |
| Coverage Score | Attack variant coverage |
| Evasion Resistance | Resistance to obfuscation |

```python
from xclaw_agentguard.redteam import EffectivenessMeter

meter = EffectivenessMeter()
score = meter.evaluate_detector(
    detector=PromptInjectionDetector(),
    test_suite="comprehensive"
)
print(f"Effectiveness: {score.overall:.1%}")
```

## Continuous Validation

Recommended red team schedule:

| Frequency | Activity |
|-----------|----------|
| Daily | Automated attack simulation |
| Weekly | Effectiveness score trending |
| Monthly | Full adversarial campaign |
| Quarterly | External red team engagement |

## Integration

Results feed into:
- Detector threshold tuning
- Pattern updates
- Security dashboard alerts
- Executive reporting