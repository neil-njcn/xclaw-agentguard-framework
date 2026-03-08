"""
Red Team Simulation Package for XClaw AgentGuard

Provides attack simulation, effectiveness measurement, and gap analysis
to continuously improve security defenses.
"""

from .attack_simulator import AttackSimulator, SimulatedAttack, AttackOutcome
from .effectiveness_meter import EffectivenessMeter, DefenseMetrics, SecurityScore
from .gap_analyzer import GapAnalyzer, CoverageGap, ImprovementReport

__all__ = [
    # Attack Simulator
    "AttackSimulator",
    "SimulatedAttack",
    "AttackOutcome",
    # Effectiveness Meter
    "EffectivenessMeter",
    "DefenseMetrics",
    "SecurityScore",
    # Gap Analyzer
    "GapAnalyzer",
    "CoverageGap",
    "ImprovementReport",
]
