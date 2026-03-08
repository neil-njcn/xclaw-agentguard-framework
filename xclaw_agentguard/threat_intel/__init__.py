"""
Threat Intelligence Package for XClaw AgentGuard

Provides CVE data fetching, intelligence analysis, alert correlation,
and threat feed management capabilities.
"""

from .cve_fetcher import CVEFetcher, CVEData, CVECache
from .intel_analyzer import IntelAnalyzer, ThreatReport, VulnerabilityCheck
from .alert_correlator import AlertCorrelator, CorrelatedAlert, PriorityScore
from .feed_updater import FeedUpdater, FeedUpdateResult, UpdateSchedule

__all__ = [
    # CVE Fetcher
    "CVEFetcher",
    "CVEData", 
    "CVECache",
    # Intel Analyzer
    "IntelAnalyzer",
    "ThreatReport",
    "VulnerabilityCheck",
    # Alert Correlator
    "AlertCorrelator",
    "CorrelatedAlert",
    "PriorityScore",
    # Feed Updater
    "FeedUpdater",
    "FeedUpdateResult",
    "UpdateSchedule",
]
