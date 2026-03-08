"""
Alert Correlator Module

Matches detection alerts with CVE data, performs priority scoring,
and enriches alerts with threat context.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple, Callable
from collections import defaultdict

from ..core.detection_result import DetectionResult, AttackType, ThreatLevel
from .cve_fetcher import CVEData, Severity
from .intel_analyzer import IntelAnalyzer, VulnerabilityCheck


class CorrelationConfidence(Enum):
    """Confidence level of alert-CVE correlation."""
    HIGH = "high"       # Direct pattern match with CVE description
    MEDIUM = "medium"   # Partial match or related technique
    LOW = "low"         # Weak association
    NONE = "none"       # No correlation found


@dataclass
class ThreatContext:
    """Threat context for an alert."""
    related_cves: List[str]
    active_exploits: List[str]
    threat_actors: List[str]
    campaign_associations: List[str]
    mitre_techniques: List[str]
    iocs: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PriorityScore:
    """Priority scoring for correlated alerts."""
    base_score: float  # 0-100
    severity_multiplier: float
    exploit_multiplier: float
    asset_criticality: float
    temporal_score: float
    final_score: float
    
    priority_level: str  # critical, high, medium, low
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_score": self.base_score,
            "severity_multiplier": self.severity_multiplier,
            "exploit_multiplier": self.exploit_multiplier,
            "asset_criticality": self.asset_criticality,
            "temporal_score": self.temporal_score,
            "final_score": self.final_score,
            "priority_level": self.priority_level
        }


@dataclass
class CorrelatedAlert:
    """An alert enriched with CVE correlation and threat context."""
    alert_id: str
    timestamp: datetime
    original_alert: DetectionResult
    
    # Correlation results
    correlated_cves: List[CVEData]
    correlation_confidence: CorrelationConfidence
    correlation_reason: str
    
    # Enrichment
    threat_context: ThreatContext
    related_alerts: List[str]
    
    # Priority
    priority_score: PriorityScore
    
    # Actions
    recommended_actions: List[str]
    auto_response_triggered: bool
    
    # Metadata
    correlation_timestamp: datetime
    correlation_version: str = "1.0"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "original_alert": self.original_alert.to_dict() if hasattr(self.original_alert, 'to_dict') else str(self.original_alert),
            "correlated_cves": [c.cve_id for c in self.correlated_cves],
            "correlation_confidence": self.correlation_confidence.value,
            "correlation_reason": self.correlation_reason,
            "threat_context": self.threat_context.to_dict(),
            "related_alerts": self.related_alerts,
            "priority_score": self.priority_score.to_dict(),
            "recommended_actions": self.recommended_actions,
            "auto_response_triggered": self.auto_response_triggered,
            "correlation_timestamp": self.correlation_timestamp.isoformat(),
            "correlation_version": self.correlation_version
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)
    
    def generate_summary(self) -> str:
        """Generate human-readable summary."""
        lines = [
            f"Alert ID: {self.alert_id}",
            f"Timestamp: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Threat Level: {self.original_alert.threat_level.value if hasattr(self.original_alert, 'threat_level') else 'Unknown'}",
            f"",
            f"Correlation:",
            f"  Confidence: {self.correlation_confidence.value.upper()}",
            f"  Related CVEs: {len(self.correlated_cves)}",
        ]
        
        for cve in self.correlated_cves:
            lines.append(f"    - {cve.cve_id} ({cve.severity.value})")
        
        lines.extend([
            f"",
            f"Priority Score: {self.priority_score.final_score:.1f}/100",
            f"Priority Level: {self.priority_score.priority_level.upper()}",
            f"",
            f"Recommended Actions:"
        ])
        
        for action in self.recommended_actions:
            lines.append(f"  - {action}")
        
        return "\n".join(lines)


class AlertCorrelator:
    """Correlates detection alerts with CVE threat intelligence."""
    
    # Attack type to CVE keyword mapping
    ATTACK_TYPE_KEYWORDS = {
        AttackType.PROMPT_INJECTION: ["prompt injection", "prompt manipulation", "instruction override"],
        AttackType.JAILBREAK: ["jailbreak", "safety bypass", "restriction bypass"],
        AttackType.DATA_EXTRACTION: ["data extraction", "information disclosure", "data leak"],
        AttackType.PRIVILEGE_ESCALATION: ["privilege escalation", "elevation of privilege"],
        AttackType.SYSTEM_PROMPT_LEAK: ["prompt leak", "system prompt", "prompt extraction"],
        AttackType.INDIRECT_INJECTION: ["indirect injection", "second-order injection"],
        AttackType.AGENT_HIJACKING: ["agent hijacking", "agent takeover", "control hijacking"],
        AttackType.TOOL_ABUSE: ["tool abuse", "function call manipulation"],
        AttackType.CONTEXT_MANIPULATION: ["context manipulation", "context window"],
        AttackType.OUTPUT_INJECTION: ["output injection", "response manipulation"],
        AttackType.MEMORY_POISONING: ["memory poisoning", "data poisoning"],
        AttackType.KNOWLEDGE_POISONING: ["knowledge poisoning", "training data poisoning"]
    }
    
    # MITRE ATT&CK technique mappings
    MITRE_TECHNIQUES = {
        "prompt_injection": "T1550",  # Use Alternate Authentication Material
        "jailbreak": "T1078",  # Valid Accounts
        "data_extraction": "T1041",  # Exfiltration Over C2 Channel
        "privilege_escalation": "T1068",  # Exploitation for Privilege Escalation
        "system_prompt_leak": "T1083",  # File and Directory Discovery
        "agent_hijacking": "T1098",  # Account Manipulation
        "tool_abuse": "T1059",  # Command and Scripting Interpreter
        "memory_poisoning": "T1565",  # Data Manipulation
    }
    
    def __init__(
        self,
        intel_analyzer: Optional[IntelAnalyzer] = None,
        correlation_window_hours: int = 24
    ):
        self.intel_analyzer = intel_analyzer or IntelAnalyzer()
        self.correlation_window = timedelta(hours=correlation_window_hours)
        
        # Alert history for temporal correlation
        self._alert_history: List[CorrelatedAlert] = []
        self._history_max_size = 10000
        
        # CVE cache for correlation
        self._cve_cache: Dict[str, CVEData] = {}
        
        # Custom correlation rules
        self._correlation_rules: List[Callable] = []
        
        # Asset criticality map
        self._asset_criticality: Dict[str, float] = {}
    
    def correlate_alert(
        self,
        alert: DetectionResult,
        asset_id: Optional[str] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> CorrelatedAlert:
        """Correlate a detection alert with CVE data."""
        alert_id = self._generate_alert_id(alert)
        timestamp = datetime.now()
        
        # Step 1: Find related CVEs
        correlated_cves, confidence, reason = self._find_related_cves(alert)
        
        # Step 2: Build threat context
        threat_context = self._build_threat_context(correlated_cves, alert)
        
        # Step 3: Find related alerts
        related_alerts = self._find_related_alerts(alert, timestamp)
        
        # Step 4: Calculate priority score
        priority_score = self._calculate_priority(
            alert, correlated_cves, asset_id, related_alerts
        )
        
        # Step 5: Generate recommendations
        actions = self._generate_recommendations(alert, correlated_cves, priority_score)
        
        # Step 6: Determine auto-response
        auto_response = self._should_trigger_auto_response(priority_score, correlated_cves)
        
        correlated = CorrelatedAlert(
            alert_id=alert_id,
            timestamp=timestamp,
            original_alert=alert,
            correlated_cves=correlated_cves,
            correlation_confidence=confidence,
            correlation_reason=reason,
            threat_context=threat_context,
            related_alerts=related_alerts,
            priority_score=priority_score,
            recommended_actions=actions,
            auto_response_triggered=auto_response,
            correlation_timestamp=datetime.now()
        )
        
        # Store in history
        self._add_to_history(correlated)
        
        return correlated
    
    def correlate_alerts_batch(
        self,
        alerts: List[DetectionResult],
        asset_id: Optional[str] = None
    ) -> List[CorrelatedAlert]:
        """Correlate multiple alerts efficiently."""
        # Pre-fetch relevant CVEs
        self._prefetch_relevant_cves(alerts)
        
        return [self.correlate_alert(alert, asset_id) for alert in alerts]
    
    def set_asset_criticality(self, asset_id: str, criticality: float) -> None:
        """Set criticality score for an asset (0-10)."""
        self._asset_criticality[asset_id] = max(0, min(10, criticality))
    
    def add_correlation_rule(self, rule: Callable) -> None:
        """Add a custom correlation rule."""
        self._correlation_rules.append(rule)
    
    def get_alert_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get statistics on correlated alerts."""
        cutoff = datetime.now() - timedelta(hours=hours)
        recent_alerts = [
            a for a in self._alert_history
            if a.timestamp > cutoff
        ]
        
        if not recent_alerts:
            return {
                "total_alerts": 0,
                "correlated_alerts": 0,
                "high_priority_alerts": 0,
                "most_common_cves": [],
                "average_priority_score": 0
            }
        
        # Count correlations
        correlated_count = sum(
            1 for a in recent_alerts
            if a.correlation_confidence != CorrelationConfidence.NONE
        )
        
        # High priority count
        high_priority = sum(
            1 for a in recent_alerts
            if a.priority_score.priority_level in ["critical", "high"]
        )
        
        # Most common CVEs
        cve_counts = defaultdict(int)
        for alert in recent_alerts:
            for cve in alert.correlated_cves:
                cve_counts[cve.cve_id] += 1
        
        top_cves = sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Average priority
        avg_priority = sum(a.priority_score.final_score for a in recent_alerts) / len(recent_alerts)
        
        return {
            "total_alerts": len(recent_alerts),
            "correlated_alerts": correlated_count,
            "high_priority_alerts": high_priority,
            "most_common_cves": top_cves,
            "average_priority_score": round(avg_priority, 2)
        }
    
    def export_correlations(self, filepath: str, hours: int = 24) -> None:
        """Export correlations to file."""
        cutoff = datetime.now() - timedelta(hours=hours)
        recent_alerts = [
            a for a in self._alert_history
            if a.timestamp > cutoff
        ]
        
        data = {
            "export_timestamp": datetime.now().isoformat(),
            "time_range_hours": hours,
            "total_alerts": len(recent_alerts),
            "alerts": [a.to_dict() for a in recent_alerts]
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    def _generate_alert_id(self, alert: DetectionResult) -> str:
        """Generate unique alert ID."""
        # Hash alert content for ID
        content = f"{alert.timestamp.isoformat() if hasattr(alert, 'timestamp') else datetime.now().isoformat()}"
        if hasattr(alert, 'detector_id'):
            content += f"_{alert.detector_id}"
        
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _find_related_cves(
        self,
        alert: DetectionResult
    ) -> Tuple[List[CVEData], CorrelationConfidence, str]:
        """Find CVEs related to this alert."""
        related_cves = []
        
        # Get attack types from alert
        attack_types = []
        if hasattr(alert, 'attack_types'):
            attack_types = list(alert.attack_types)
        elif hasattr(alert, 'attack_type') and alert.attack_type:
            attack_types = [alert.attack_type]
        
        # Search CVE cache for matches
        for cve in self._cve_cache.values():
            match_score = self._calculate_cve_match_score(alert, attack_types, cve)
            if match_score > 0.5:
                related_cves.append((cve, match_score))
        
        # Sort by match score
        related_cves.sort(key=lambda x: x[1], reverse=True)
        related_cves = [c[0] for c in related_cves[:5]]  # Top 5
        
        # Determine confidence
        if not related_cves:
            return [], CorrelationConfidence.NONE, "No matching CVEs found"
        
        # Calculate average match score
        avg_score = sum(c[1] for c in related_cves) / len(related_cves)
        
        if avg_score > 0.8:
            confidence = CorrelationConfidence.HIGH
        elif avg_score > 0.5:
            confidence = CorrelationConfidence.MEDIUM
        else:
            confidence = CorrelationConfidence.LOW
        
        reason = f"Matched {len(related_cves)} CVEs based on attack type and patterns"
        
        # Apply custom rules
        for rule in self._correlation_rules:
            try:
                rule_result = rule(alert, related_cves)
                if rule_result:
                    related_cves.extend(rule_result.get("cves", []))
                    confidence = CorrelationConfidence.HIGH
                    reason += f"; Custom rule: {rule_result.get('reason', '')}"
            except Exception:
                pass
        
        return related_cves, confidence, reason
    
    def _calculate_cve_match_score(
        self,
        alert: DetectionResult,
        attack_types: List[AttackType],
        cve: CVEData
    ) -> float:
        """Calculate how well a CVE matches an alert."""
        score = 0.0
        
        # Check attack type keywords
        for attack_type in attack_types:
            keywords = self.ATTACK_TYPE_KEYWORDS.get(attack_type, [])
            desc_lower = cve.description.lower()
            
            for keyword in keywords:
                if keyword in desc_lower:
                    score += 0.3
        
        # Boost for AI-related CVEs
        if cve.ai_related:
            score += 0.2
        if cve.agent_related:
            score += 0.3
        if cve.llm_related:
            score += 0.25
        
        # Boost for high severity
        if cve.severity == Severity.CRITICAL:
            score += 0.2
        elif cve.severity == Severity.HIGH:
            score += 0.1
        
        return min(score, 1.0)
    
    def _build_threat_context(
        self,
        cves: List[CVEData],
        alert: DetectionResult
    ) -> ThreatContext:
        """Build threat context from correlated CVEs."""
        cve_ids = [c.cve_id for c in cves]
        
        # Check for active exploits
        active_exploits = []
        for cve in cves:
            exploit_info = self.intel_analyzer._check_exploit_availability(cve)
            if exploit_info["available"]:
                active_exploits.append(f"{cve.cve_id} ({exploit_info['maturity']})")
        
        # Extract MITRE techniques
        techniques = []
        for attack_type in (alert.attack_types if hasattr(alert, 'attack_types') else []):
            technique = self.MITRE_TECHNIQUES.get(attack_type.value if hasattr(attack_type, 'value') else str(attack_type).lower())
            if technique and technique not in techniques:
                techniques.append(technique)
        
        # Extract IOCs from CVE references
        iocs = []
        for cve in cves:
            for ref in cve.references:
                url = ref.get("url", "")
                # Simple IOC extraction (can be enhanced)
                if any(domain in url for domain in ["github.com", "exploit-db"]):
                    iocs.append(url)
        
        return ThreatContext(
            related_cves=cve_ids,
            active_exploits=active_exploits,
            threat_actors=[],  # Could be enriched with threat intel feeds
            campaign_associations=[],
            mitre_techniques=techniques,
            iocs=iocs[:10]  # Limit IOCs
        )
    
    def _find_related_alerts(
        self,
        alert: DetectionResult,
        timestamp: datetime
    ) -> List[str]:
        """Find historically related alerts."""
        related = []
        
        cutoff = timestamp - self.correlation_window
        
        for hist_alert in self._alert_history:
            if hist_alert.timestamp < cutoff:
                continue
            
            # Check for same attack type
            hist_types = set(
                str(at) for at in (hist_alert.original_alert.attack_types if hasattr(hist_alert.original_alert, 'attack_types') else [])
            )
            current_types = set(
                str(at) for at in (alert.attack_types if hasattr(alert, 'attack_types') else [])
            )
            
            if hist_types & current_types:
                related.append(hist_alert.alert_id)
                
                if len(related) >= 5:  # Limit related alerts
                    break
        
        return related
    
    def _calculate_priority(
        self,
        alert: DetectionResult,
        cves: List[CVEData],
        asset_id: Optional[str],
        related_alerts: List[str]
    ) -> PriorityScore:
        """Calculate priority score for alert."""
        # Base score from threat level
        threat_level_int = 0
        if hasattr(alert, 'threat_level'):
            threat_level_int = alert.threat_level.to_int() if hasattr(alert.threat_level, 'to_int') else 2
        base_score = threat_level_int * 20  # 0-80
        
        # Confidence boost
        if hasattr(alert, 'confidence'):
            base_score += alert.confidence * 20
        
        base_score = min(base_score, 100)
        
        # Severity multiplier from CVEs
        severity_mult = 1.0
        for cve in cves:
            if cve.severity == Severity.CRITICAL:
                severity_mult = max(severity_mult, 1.5)
            elif cve.severity == Severity.HIGH:
                severity_mult = max(severity_mult, 1.3)
            elif cve.severity == Severity.MEDIUM:
                severity_mult = max(severity_mult, 1.1)
        
        # Exploit multiplier
        exploit_mult = 1.0
        for cve in cves:
            exploit_info = self.intel_analyzer._check_exploit_availability(cve)
            if exploit_info["maturity"] == "high":
                exploit_mult = max(exploit_mult, 1.4)
            elif exploit_info["maturity"] == "functional":
                exploit_mult = max(exploit_mult, 1.2)
            elif exploit_info["available"]:
                exploit_mult = max(exploit_mult, 1.1)
        
        # Asset criticality
        asset_crit = self._asset_criticality.get(asset_id, 5.0) / 5.0  # Default 5/5 = 1.0
        
        # Temporal score (increase if multiple related alerts)
        temporal_mult = 1.0 + (len(related_alerts) * 0.1)
        
        # Calculate final score
        final_score = base_score * severity_mult * exploit_mult * asset_crit * temporal_mult
        final_score = min(final_score, 100)
        
        # Determine priority level
        if final_score >= 80:
            level = "critical"
        elif final_score >= 60:
            level = "high"
        elif final_score >= 40:
            level = "medium"
        else:
            level = "low"
        
        return PriorityScore(
            base_score=base_score,
            severity_multiplier=severity_mult,
            exploit_multiplier=exploit_mult,
            asset_criticality=asset_crit,
            temporal_score=temporal_mult,
            final_score=final_score,
            priority_level=level
        )
    
    def _generate_recommendations(
        self,
        alert: DetectionResult,
        cves: List[CVEData],
        priority: PriorityScore
    ) -> List[str]:
        """Generate recommended actions."""
        actions = []
        
        # Immediate containment for critical
        if priority.priority_level == "critical":
            actions.append("IMMEDIATE: Isolate affected component")
            actions.append("IMMEDIATE: Alert security team")
        
        # CVE-specific recommendations
        for cve in cves[:3]:  # Top 3
            if cve.is_high_severity:
                actions.append(f"Apply patch for {cve.cve_id}")
        
        # Attack type specific
        attack_types = []
        if hasattr(alert, 'attack_types'):
            attack_types = [str(at) for at in alert.attack_types]
        
        if "prompt_injection" in attack_types or "jailbreak" in attack_types:
            actions.append("Review and strengthen prompt filtering")
        
        if "data_extraction" in attack_types:
            actions.append("Audit data access logs")
            actions.append("Verify data loss prevention controls")
        
        if "agent_hijacking" in attack_types:
            actions.append("Review agent permissions and isolation")
        
        # Generic recommendations
        if not actions:
            actions.append("Monitor for additional alerts")
            actions.append("Review detection rules")
        
        return actions
    
    def _should_trigger_auto_response(
        self,
        priority: PriorityScore,
        cves: List[CVEData]
    ) -> bool:
        """Determine if auto-response should be triggered."""
        # Auto-response for critical priority
        if priority.priority_level == "critical":
            return True
        
        # Auto-response for active exploits
        for cve in cves:
            exploit_info = self.intel_analyzer._check_exploit_availability(cve)
            if exploit_info["maturity"] == "high":
                return True
        
        return False
    
    def _prefetch_relevant_cves(self, alerts: List[DetectionResult]) -> None:
        """Pre-fetch CVEs relevant to alerts."""
        # Get unique attack types
        attack_types = set()
        for alert in alerts:
            if hasattr(alert, 'attack_types'):
                attack_types.update(alert.attack_types)
        
        # Search for relevant CVEs
        for attack_type in attack_types:
            keywords = self.ATTACK_TYPE_KEYWORDS.get(attack_type, [])
            for keyword in keywords[:2]:  # Limit searches
                try:
                    cves = self.intel_analyzer.cve_fetcher.search_by_keyword(keyword)
                    for cve in cves[:10]:  # Limit cache
                        self._cve_cache[cve.cve_id] = cve
                except Exception:
                    pass
    
    def _add_to_history(self, alert: CorrelatedAlert) -> None:
        """Add alert to history, maintaining size limit."""
        self._alert_history.append(alert)
        
        if len(self._alert_history) > self._history_max_size:
            # Remove oldest alerts
            self._alert_history = self._alert_history[-self._history_max_size:]


# Convenience function for quick correlation
def correlate_alert_with_threat_intel(
    alert: DetectionResult,
    cve_fetcher=None
) -> CorrelatedAlert:
    """Quick correlate function."""
    from .intel_analyzer import IntelAnalyzer
    
    analyzer = IntelAnalyzer(cve_fetcher)
    correlator = AlertCorrelator(analyzer)
    
    return correlator.correlate_alert(alert)
