"""
Intelligence Analyzer Module

Analyzes CVE severity, checks if system is vulnerable,
correlates with detector capabilities, and generates threat reports.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Callable, Tuple
from packaging import version

from .cve_fetcher import CVEData, CVEFetcher, Severity


class SystemComponent(Enum):
    """System components that could be vulnerable."""
    PYTHON = "python"
    NODEJS = "nodejs"
    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    LLM_FRAMEWORK = "llm_framework"
    ML_LIBRARY = "ml_library"
    WEB_FRAMEWORK = "web_framework"
    DATABASE = "database"
    OS = "os"
    BROWSER = "browser"
    API_GATEWAY = "api_gateway"
    MESSAGE_QUEUE = "message_queue"
    CUSTOM = "custom"


@dataclass
class SystemVersion:
    """System component version information."""
    component: SystemComponent
    name: str
    version: str
    vendor: str = ""
    cpe: str = ""  # Common Platform Enumeration identifier
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def matches_cve(self, cve: CVEData) -> bool:
        """Check if this component/version matches a CVE."""
        # Check vendor match
        if cve.vendors:
            vendor_match = self.vendor.lower() in [v.lower() for v in cve.vendors]
            if not vendor_match and self.vendor:
                return False
        
        # Check product name match
        if cve.products:
            product_names = [p.lower() for p in cve.products]
            name_match = (
                self.name.lower() in product_names or
                any(self.name.lower() in p for p in product_names)
            )
            if not name_match:
                return False
        
        # Check version range if available in CVE
        for config in cve.configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        version_start = match.get("versionStartIncluding")
                        version_end = match.get("versionEndExcluding")
                        version_end_inc = match.get("versionEndIncluding")
                        
                        try:
                            current = version.parse(self.version)
                            
                            if version_start and current < version.parse(version_start):
                                continue
                            if version_end and current >= version.parse(version_end):
                                continue
                            if version_end_inc and current > version.parse(version_end_inc):
                                continue
                            
                            return True
                        except version.InvalidVersion:
                            continue
        
        # If no version constraints, vendor/product match is enough
        return bool(cve.vendors or cve.products)


@dataclass
class VulnerabilityCheck:
    """Result of checking if system is vulnerable to a CVE."""
    cve: CVEData
    is_vulnerable: bool
    matched_components: List[SystemVersion]
    risk_score: float  # 0.0 to 10.0
    exploit_available: bool = False
    exploit_maturity: str = "unproven"  # unproven, poc, functional, high
    mitigation_available: bool = False
    recommended_action: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "cve_id": self.cve.cve_id,
            "is_vulnerable": self.is_vulnerable,
            "matched_components": [
                {"component": c.component.value, "name": c.name, "version": c.version}
                for c in self.matched_components
            ],
            "risk_score": self.risk_score,
            "exploit_available": self.exploit_available,
            "exploit_maturity": self.exploit_maturity,
            "mitigation_available": self.mitigation_available,
            "recommended_action": self.recommended_action
        }


@dataclass
class DetectorCoverage:
    """CVE coverage by existing detectors."""
    cve_id: str
    attack_vector: str
    covered: bool
    covering_detectors: List[str]
    coverage_gaps: List[str]
    recommendation: str = ""


@dataclass
class ThreatReport:
    """Comprehensive threat report."""
    generated_at: datetime
    report_period_days: int
    total_cves_analyzed: int
    critical_cves: int
    high_cves: int
    medium_cves: int
    low_cves: int
    
    # System vulnerability summary
    system_vulnerabilities: List[VulnerabilityCheck]
    vulnerable_components: List[str]
    
    # Detector coverage analysis
    detector_coverage: List[DetectorCoverage]
    uncovered_attack_vectors: List[str]
    
    # AI/Agent specific threats
    ai_related_threats: List[CVEData]
    agent_related_threats: List[CVEData]
    llm_specific_threats: List[CVEData]
    
    # Risk assessment
    overall_risk_score: float
    risk_trend: str  # increasing, stable, decreasing
    
    # Recommendations
    immediate_actions: List[str]
    short_term_actions: List[str]
    long_term_actions: List[str]
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "generated_at": self.generated_at.isoformat(),
            "report_period_days": self.report_period_days,
            "total_cves_analyzed": self.total_cves_analyzed,
            "critical_cves": self.critical_cves,
            "high_cves": self.high_cves,
            "medium_cves": self.medium_cves,
            "low_cves": self.low_cves,
            "system_vulnerabilities": [v.to_dict() for v in self.system_vulnerabilities],
            "vulnerable_components": self.vulnerable_components,
            "uncovered_attack_vectors": self.uncovered_attack_vectors,
            "ai_related_threats_count": len(self.ai_related_threats),
            "agent_related_threats_count": len(self.agent_related_threats),
            "llm_specific_threats_count": len(self.llm_specific_threats),
            "overall_risk_score": self.overall_risk_score,
            "risk_trend": self.risk_trend,
            "immediate_actions": self.immediate_actions,
            "short_term_actions": self.short_term_actions,
            "long_term_actions": self.long_term_actions
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)
    
    def generate_summary(self) -> str:
        """Generate human-readable summary."""
        lines = [
            "=" * 60,
            "XClaw AgentGuard Threat Intelligence Report",
            "=" * 60,
            f"Generated: {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Report Period: Last {self.report_period_days} days",
            "",
            "CVE SUMMARY",
            "-" * 40,
            f"Total CVEs Analyzed: {self.total_cves_analyzed}",
            f"  Critical: {self.critical_cves}",
            f"  High:     {self.high_cves}",
            f"  Medium:   {self.medium_cves}",
            f"  Low:      {self.low_cves}",
            "",
            "SYSTEM VULNERABILITIES",
            "-" * 40,
            f"Vulnerable Components: {len(self.vulnerable_components)}",
        ]
        
        if self.vulnerable_components:
            for comp in self.vulnerable_components:
                lines.append(f"  - {comp}")
        
        lines.extend([
            "",
            "AI/AGENT THREATS",
            "-" * 40,
            f"AI-Related Threats: {len(self.ai_related_threats)}",
            f"Agent-Specific Threats: {len(self.agent_related_threats)}",
            f"LLM-Specific Threats: {len(self.llm_specific_threats)}",
            "",
            "DETECTOR COVERAGE",
            "-" * 40,
            f"Uncovered Attack Vectors: {len(self.uncovered_attack_vectors)}",
        ])
        
        if self.uncovered_attack_vectors:
            for vector in self.uncovered_attack_vectors[:5]:
                lines.append(f"  - {vector}")
            if len(self.uncovered_attack_vectors) > 5:
                lines.append(f"  ... and {len(self.uncovered_attack_vectors) - 5} more")
        
        lines.extend([
            "",
            "RISK ASSESSMENT",
            "-" * 40,
            f"Overall Risk Score: {self.overall_risk_score:.1f}/10.0",
            f"Risk Trend: {self.risk_trend.upper()}",
            "",
            "RECOMMENDED ACTIONS",
            "-" * 40,
            "IMMEDIATE:",
        ])
        
        if self.immediate_actions:
            for action in self.immediate_actions:
                lines.append(f"  [!] {action}")
        else:
            lines.append("  None")
        
        lines.extend(["", "SHORT-TERM:"])
        if self.short_term_actions:
            for action in self.short_term_actions:
                lines.append(f"  [+] {action}")
        else:
            lines.append("  None")
        
        lines.extend(["", "LONG-TERM:"])
        if self.long_term_actions:
            for action in self.long_term_actions:
                lines.append(f"  [~] {action}")
        else:
            lines.append("  None")
        
        lines.extend(["", "=" * 60])
        
        return "\n".join(lines)


class IntelAnalyzer:
    """Analyzes threat intelligence data."""
    
    # Known AI/agent security tools and frameworks
    AI_FRAMEWORKS = [
        "langchain", "llamaindex", "haystack", "transformers",
        "openai", "anthropic", "cohere", "huggingface", "hugging face",
        "pytorch", "tensorflow", "keras", "scikit-learn", "sklearn",
        "mlflow", "kubeflow", "bentoml", "ray", "triton"
    ]
    
    # Detector capabilities mapping
    DETECTOR_CAPABILITIES = {
        "prompt_injection": ["Prompt Injection", "Indirect Injection"],
        "jailbreak": ["Jailbreak", "Safety Bypass"],
        "exfiltration": ["Data Extraction", "PII Leakage"],
        "agent_hijacking": ["Agent Hijacking", "Privilege Escalation"],
        "backdoor": ["Backdoor", "Malicious Code"],
        "tool_poisoning": ["Tool Abuse", "Command Injection", "SQL Injection"],
        "memory_poisoning": ["Memory Poisoning", "Knowledge Poisoning"],
        "output_injection": ["Output Injection", "Context Manipulation"],
        "system_prompt_leak": ["System Prompt Leak", "Prompt Extraction"]
    }
    
    def __init__(
        self,
        cve_fetcher: Optional[CVEFetcher] = None,
        system_inventory: Optional[List[SystemVersion]] = None
    ):
        self.cve_fetcher = cve_fetcher or CVEFetcher()
        self.system_inventory = system_inventory or []
        self._detector_registry: Dict[str, List[str]] = {}
    
    def register_detectors(self, detectors: Dict[str, List[str]]) -> None:
        """Register available detectors and their capabilities."""
        self._detector_registry = detectors
    
    def analyze_cve_severity(self, cve: CVEData) -> Dict[str, Any]:
        """Analyze CVE severity in detail."""
        severity_score = cve.cvss.base_score
        
        analysis = {
            "cve_id": cve.cve_id,
            "severity": cve.severity.value,
            "cvss_score": severity_score,
            "exploitability": cve.cvss.exploitability_score,
            "impact": cve.cvss.impact_score,
            "vector": cve.cvss.vector_string,
            "ai_specific_risk": self._calculate_ai_risk(cve),
            "attack_complexity": self._assess_attack_complexity(cve),
            "privileges_required": self._assess_privileges_required(cve),
            "user_interaction": self._assess_user_interaction(cve)
        }
        
        return analysis
    
    def check_system_vulnerability(self, cve: CVEData) -> VulnerabilityCheck:
        """Check if system is vulnerable to a specific CVE."""
        matched_components = []
        
        for component in self.system_inventory:
            if component.matches_cve(cve):
                matched_components.append(component)
        
        is_vulnerable = len(matched_components) > 0
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(cve, matched_components)
        
        # Check exploit availability
        exploit_info = self._check_exploit_availability(cve)
        
        # Determine recommended action
        recommended_action = self._determine_action(cve, is_vulnerable, risk_score)
        
        return VulnerabilityCheck(
            cve=cve,
            is_vulnerable=is_vulnerable,
            matched_components=matched_components,
            risk_score=risk_score,
            exploit_available=exploit_info["available"],
            exploit_maturity=exploit_info["maturity"],
            mitigation_available=self._check_mitigation(cve),
            recommended_action=recommended_action
        )
    
    def check_all_vulnerabilities(self, cves: List[CVEData]) -> List[VulnerabilityCheck]:
        """Check system vulnerability against all CVEs."""
        results = []
        for cve in cves:
            check = self.check_system_vulnerability(cve)
            if check.is_vulnerable or cve.is_high_severity:
                results.append(check)
        return sorted(results, key=lambda x: x.risk_score, reverse=True)
    
    def correlate_with_detectors(self, cve: CVEData) -> DetectorCoverage:
        """Check if existing detectors cover this CVE's attack vector."""
        attack_vector = self._extract_attack_vector(cve)
        
        covered = False
        covering_detectors = []
        coverage_gaps = []
        
        for detector_id, capabilities in self._detector_registry.items():
            if self._matches_capabilities(attack_vector, capabilities):
                covered = True
                covering_detectors.append(detector_id)
        
        if not covered:
            coverage_gaps = self._identify_coverage_gaps(attack_vector)
        
        recommendation = ""
        if not covered:
            recommendation = self._recommend_detector(attack_vector)
        
        return DetectorCoverage(
            cve_id=cve.cve_id,
            attack_vector=attack_vector,
            covered=covered,
            covering_detectors=covering_detectors,
            coverage_gaps=coverage_gaps,
            recommendation=recommendation
        )
    
    def generate_threat_report(
        self,
        days: int = 30,
        include_ai_only: bool = True
    ) -> ThreatReport:
        """Generate comprehensive threat report."""
        # Fetch recent CVEs
        if include_ai_only:
            cves = self.cve_fetcher.fetch_ai_related(days)
        else:
            cves = self.cve_fetcher.fetch_recent(days)
        
        # Categorize by severity
        critical_cves = [c for c in cves if c.severity == Severity.CRITICAL]
        high_cves = [c for c in cves if c.severity == Severity.HIGH]
        medium_cves = [c for c in cves if c.severity == Severity.MEDIUM]
        low_cves = [c for c in cves if c.severity == Severity.LOW]
        
        # Check system vulnerabilities
        vuln_checks = self.check_all_vulnerabilities(cves)
        vulnerable_components = list(set(
            f"{v.matched_components[0].name} ({v.matched_components[0].version})"
            for v in vuln_checks if v.matched_components
        ))
        
        # Analyze detector coverage
        coverage_analysis = []
        uncovered_vectors = []
        
        for cve in cves[:50]:  # Limit to prevent excessive processing
            coverage = self.correlate_with_detectors(cve)
            coverage_analysis.append(coverage)
            if not coverage.covered:
                uncovered_vectors.append(coverage.attack_vector)
        
        uncovered_vectors = list(set(uncovered_vectors))
        
        # Categorize AI threats
        ai_threats = [c for c in cves if c.ai_related]
        agent_threats = [c for c in cves if c.agent_related]
        llm_threats = [c for c in cves if c.llm_related]
        
        # Calculate overall risk
        risk_score = self._calculate_overall_risk(vuln_checks, cves)
        risk_trend = self._determine_risk_trend(cves)
        
        # Generate recommendations
        immediate, short_term, long_term = self._generate_recommendations(
            vuln_checks, uncovered_vectors, cves
        )
        
        return ThreatReport(
            generated_at=datetime.now(),
            report_period_days=days,
            total_cves_analyzed=len(cves),
            critical_cves=len(critical_cves),
            high_cves=len(high_cves),
            medium_cves=len(medium_cves),
            low_cves=len(low_cves),
            system_vulnerabilities=vuln_checks,
            vulnerable_components=vulnerable_components,
            detector_coverage=coverage_analysis,
            uncovered_attack_vectors=uncovered_vectors,
            ai_related_threats=ai_threats,
            agent_related_threats=agent_threats,
            llm_specific_threats=llm_threats,
            overall_risk_score=risk_score,
            risk_trend=risk_trend,
            immediate_actions=immediate,
            short_term_actions=short_term,
            long_term_actions=long_term
        )
    
    def set_system_inventory(self, inventory: List[SystemVersion]) -> None:
        """Update system component inventory."""
        self.system_inventory = inventory
    
    def add_system_component(self, component: SystemVersion) -> None:
        """Add a system component to inventory."""
        self.system_inventory.append(component)
    
    def _calculate_ai_risk(self, cve: CVEData) -> float:
        """Calculate AI-specific risk score."""
        base_score = cve.cvss.base_score
        
        # Increase risk for AI-related CVEs
        if cve.agent_related:
            base_score *= 1.5
        elif cve.llm_related:
            base_score *= 1.3
        elif cve.ai_related:
            base_score *= 1.2
        
        # Cap at 10
        return min(base_score, 10.0)
    
    def _calculate_risk_score(
        self,
        cve: CVEData,
        matched_components: List[SystemVersion]
    ) -> float:
        """Calculate overall risk score."""
        base_score = cve.cvss.base_score
        
        # Increase for AI-specific threats
        if cve.agent_related:
            base_score *= 1.4
        elif cve.llm_related:
            base_score *= 1.2
        
        # Increase if system is actually vulnerable
        if matched_components:
            base_score *= 1.3
        
        # Check for known exploits
        if self._check_exploit_availability(cve)["available"]:
            base_score *= 1.2
        
        return min(base_score, 10.0)
    
    def _calculate_overall_risk(
        self,
        vuln_checks: List[VulnerabilityCheck],
        cves: List[CVEData]
    ) -> float:
        """Calculate overall system risk score."""
        if not cves:
            return 0.0
        
        # Weight by vulnerability presence
        vuln_weight = len([v for v in vuln_checks if v.is_vulnerable]) / max(len(cves), 1)
        
        # Average CVE score
        avg_cve_score = sum(c.cvss.base_score for c in cves) / len(cves)
        
        # AI threat presence
        ai_threat_factor = len([c for c in cves if c.ai_related]) / max(len(cves), 1)
        
        risk = (avg_cve_score * 0.4 + vuln_weight * 3.0 + ai_threat_factor * 2.0)
        return min(risk, 10.0)
    
    def _determine_risk_trend(self, cves: List[CVEData]) -> str:
        """Determine if risk is increasing, stable, or decreasing."""
        if not cves:
            return "stable"
        
        # Sort by date
        sorted_cves = sorted(cves, key=lambda c: c.published_date)
        
        if len(sorted_cves) < 10:
            return "stable"
        
        # Split into two halves
        mid = len(sorted_cves) // 2
        first_half = sorted_cves[:mid]
        second_half = sorted_cves[mid:]
        
        first_avg = sum(c.cvss.base_score for c in first_half) / len(first_half)
        second_avg = sum(c.cvss.base_score for c in second_half) / len(second_half)
        
        if second_avg > first_avg * 1.2:
            return "increasing"
        elif second_avg < first_avg * 0.8:
            return "decreasing"
        return "stable"
    
    def _check_exploit_availability(self, cve: CVEData) -> Dict[str, Any]:
        """Check if exploit code is available."""
        # Check references for exploit indicators
        exploit_indicators = ["exploit", "poc", "proof of concept", "github.com"]
        exploit_refs = [
            ref for ref in cve.references
            if any(ind in ref.get("url", "").lower() for ind in exploit_indicators)
        ]
        
        available = len(exploit_refs) > 0
        
        # Determine maturity
        maturity = "unproven"
        if available:
            if any("metasploit" in ref.get("url", "").lower() for ref in exploit_refs):
                maturity = "high"
            elif any("github" in ref.get("url", "").lower() for ref in exploit_refs):
                maturity = "functional"
            else:
                maturity = "poc"
        
        return {"available": available, "maturity": maturity}
    
    def _check_mitigation(self, cve: CVEData) -> bool:
        """Check if mitigation is available."""
        # Check for patch/workaround references
        mitigation_indicators = ["patch", "mitigation", "workaround", "fix", "update"]
        return any(
            any(ind in ref.get("url", "").lower() for ind in mitigation_indicators)
            for ref in cve.references
        )
    
    def _determine_action(
        self,
        cve: CVEData,
        is_vulnerable: bool,
        risk_score: float
    ) -> str:
        """Determine recommended action."""
        if not is_vulnerable:
            if risk_score > 7:
                return "Monitor for related vulnerabilities"
            return "No action required"
        
        if risk_score >= 9:
            return "CRITICAL: Patch immediately"
        elif risk_score >= 7:
            return "HIGH: Patch within 24 hours"
        elif risk_score >= 5:
            return "MEDIUM: Patch within 7 days"
        else:
            return "LOW: Patch during next maintenance window"
    
    def _extract_attack_vector(self, cve: CVEData) -> str:
        """Extract attack vector from CVE description."""
        desc = cve.description.lower()
        
        vectors = {
            "prompt injection": "prompt_injection",
            "command injection": "command_injection",
            "sql injection": "sql_injection",
            "path traversal": "path_traversal",
            "remote code execution": "rce",
            "buffer overflow": "buffer_overflow",
            "cross-site scripting": "xss",
            "authentication bypass": "auth_bypass",
            "privilege escalation": "privilege_escalation",
            "information disclosure": "info_disclosure"
        }
        
        for vector, key in vectors.items():
            if vector in desc:
                return key
        
        return "unknown"
    
    def _matches_capabilities(self, attack_vector: str, capabilities: List[str]) -> bool:
        """Check if attack vector matches detector capabilities."""
        attack_lower = attack_vector.lower().replace("_", " ")
        
        for cap in capabilities:
            cap_lower = cap.lower()
            if attack_lower in cap_lower or cap_lower in attack_lower:
                return True
            # Check word overlap
            attack_words = set(attack_lower.split())
            cap_words = set(cap_lower.split())
            if attack_words & cap_words:
                return True
        
        return False
    
    def _identify_coverage_gaps(self, attack_vector: str) -> List[str]:
        """Identify gaps in detector coverage."""
        gaps = []
        
        # Check if this attack type is in our known capabilities
        for detector, capabilities in self.DETECTOR_CAPABILITIES.items():
            if self._matches_capabilities(attack_vector, capabilities):
                gaps.append(f"Missing detector for {detector}")
        
        if not gaps:
            gaps.append(f"No detector coverage for {attack_vector}")
        
        return gaps
    
    def _recommend_detector(self, attack_vector: str) -> str:
        """Recommend detector implementation for uncovered vector."""
        recommendations = {
            "prompt_injection": "Implement PromptInjectionDetector with pattern matching",
            "command_injection": "Implement CommandInjectionDetector with shell parsing",
            "sql_injection": "Implement SQLInjectionDetector with query analysis",
            "path_traversal": "Implement PathTraversalDetector with path validation",
            "rce": "Implement RCEDetector with code execution detection",
            "auth_bypass": "Implement AuthBypassDetector with authentication checks",
            "privilege_escalation": "Implement PrivilegeEscalationDetector"
        }
        
        return recommendations.get(attack_vector, f"Consider implementing detector for {attack_vector}")
    
    def _generate_recommendations(
        self,
        vuln_checks: List[VulnerabilityCheck],
        uncovered_vectors: List[str],
        cves: List[CVEData]
    ) -> Tuple[List[str], List[str], List[str]]:
        """Generate prioritized recommendations."""
        immediate = []
        short_term = []
        long_term = []
        
        # Immediate: Critical vulnerabilities
        critical_vulns = [v for v in vuln_checks if v.risk_score >= 9]
        for v in critical_vulns[:3]:
            immediate.append(f"Patch {v.cve.cve_id} - {v.recommended_action}")
        
        # Immediate: Active exploits
        active_exploits = [v for v in vuln_checks if v.exploit_available and v.exploit_maturity == "high"]
        for v in active_exploits[:2]:
            immediate.append(f"Address {v.cve.cve_id} - active exploit in the wild")
        
        # Short-term: High vulnerabilities
        high_vulns = [v for v in vuln_checks if 7 <= v.risk_score < 9]
        for v in high_vulns[:3]:
            short_term.append(f"Schedule patch for {v.cve.cve_id}")
        
        # Short-term: Uncovered attack vectors
        for vector in uncovered_vectors[:3]:
            short_term.append(f"Implement detector for {vector}")
        
        # Long-term: AI-specific hardening
        if any(c.agent_related for c in cves):
            long_term.append("Implement agent-specific security controls")
        
        if any(c.llm_related for c in cves):
            long_term.append("Review LLM prompt injection defenses")
        
        long_term.append("Establish continuous vulnerability monitoring")
        long_term.append("Create automated threat feed integration")
        
        return immediate, short_term, long_term
    
    def _assess_attack_complexity(self, cve: CVEData) -> str:
        """Assess attack complexity from CVSS."""
        vector = cve.cvss.vector_string.lower()
        if "ac:l" in vector:
            return "low"
        elif "ac:h" in vector:
            return "high"
        return "unknown"
    
    def _assess_privileges_required(self, cve: CVEData) -> str:
        """Assess privileges required from CVSS."""
        vector = cve.cvss.vector_string.lower()
        if "pr:n" in vector:
            return "none"
        elif "pr:l" in vector:
            return "low"
        elif "pr:h" in vector:
            return "high"
        return "unknown"
    
    def _assess_user_interaction(self, cve: CVEData) -> str:
        """Assess user interaction required from CVSS."""
        vector = cve.cvss.vector_string.lower()
        if "ui:n" in vector:
            return "none"
        elif "ui:r" in vector:
            return "required"
        return "unknown"
