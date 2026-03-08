"""
Behavior Analyzer - XClaw AgentGuard

Analyzes sandbox execution behavior to detect suspicious activities.
Monitors file system changes, network activity, resource usage, and exit codes.
"""

import re
import json
import logging
from typing import Dict, Any, List, Optional, Set, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict

from .docker_manager import ExecutionResult
from .sandbox_executor import ToolExecutionRequest

logger = logging.getLogger(__name__)


class BehaviorSeverity(Enum):
    """Severity levels for behavior findings"""
    INFO = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


class BehaviorCategory(Enum):
    """Categories of suspicious behavior"""
    FILE_SYSTEM = auto()
    NETWORK = auto()
    RESOURCE = auto()
    PROCESS = auto()
    CODE_EXECUTION = auto()
    DATA_EXFILTRATION = auto()


@dataclass
class BehaviorFinding:
    """A single suspicious behavior finding"""
    category: BehaviorCategory
    severity: BehaviorSeverity
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.name,
            "severity": self.severity.name,
            "description": self.description,
            "details": self.details,
            "evidence": self.evidence,
        }


@dataclass
class BehaviorAnalysis:
    """Complete behavior analysis result"""
    tool_name: str
    command: str
    exit_code: int
    
    # Findings
    findings: List[BehaviorFinding] = field(default_factory=list)
    
    # Risk score (0-100)
    risk_score: int = 0
    
    # Summary
    file_operations: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))
    network_indicators: List[str] = field(default_factory=list)
    resource_usage: Dict[str, Any] = field(default_factory=dict)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "command": self.command,
            "exit_code": self.exit_code,
            "risk_score": self.risk_score,
            "findings": [f.to_dict() for f in self.findings],
            "file_operations": dict(self.file_operations),
            "network_indicators": self.network_indicators,
            "resource_usage": self.resource_usage,
            "recommendations": self.recommendations,
        }
    
    @property
    def has_critical_findings(self) -> bool:
        """Check if any critical findings exist"""
        return any(
            f.severity == BehaviorSeverity.CRITICAL 
            for f in self.findings
        )
    
    @property
    def has_high_findings(self) -> bool:
        """Check if any high severity findings exist"""
        return any(
            f.severity in (BehaviorSeverity.HIGH, BehaviorSeverity.CRITICAL)
            for f in self.findings
        )


class BehaviorAnalyzer:
    """
    Analyzes execution behavior for suspicious patterns
    
    Detects:
    - File system changes outside allowed paths
    - Network activity indicators
    - Resource exhaustion attempts
    - Suspicious command patterns
    - Data exfiltration attempts
    """
    
    # Suspicious file paths
    SENSITIVE_PATHS = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/hosts',
        '/root',
        '/home',
        '/var/log',
        '/proc',
        '/sys',
        '.ssh',
        '.aws',
        '.docker',
        '.kube',
        '.git',
    ]
    
    # Suspicious command patterns
    SUSPICIOUS_PATTERNS = {
        'reverse_shell': [
            r'bash\s+-i',
            r'sh\s+-i',
            r'/bin/bash\s+-i',
            r'nc\s+-e',
            r'netcat\s+-e',
            r'ncat\s+-e',
            r'python.*socket',
            r'ruby.*socket',
            r'perl.*socket',
        ],
        'command_injection': [
            r'[;&|]\s*\w+',
            r'`[^`]+`',
            r'\$\([^)]+\)',
            r'\|\s*bash',
            r'\|\s*sh',
        ],
        'data_exfiltration': [
            r'curl.*http',
            r'wget.*http',
            r'fetch',
            r'upload',
            r'exfiltrate',
        ],
        'privilege_escalation': [
            r'sudo',
            r'su\s+-',
            r'chmod\s+.*suid',
            r'setuid',
        ],
    }
    
    # Network indicators
    NETWORK_INDICATORS = [
        r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',  # IP addresses
        r'https?://[^\s]+',
        r'curl\s+',
        r'wget\s+',
        r'nc\s+',
        r'netcat\s+',
        r'telnet\s+',
        r'ssh\s+',
        r'scp\s+',
        r'ftp\s+',
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize behavior analyzer
        
        Args:
            config: Configuration options
        """
        self.config = config or {}
        self.custom_rules: List[Callable[[str, str, Dict], Optional[BehaviorFinding]]] = []
    
    def add_custom_rule(
        self,
        rule: Callable[[str, str, Dict], Optional[BehaviorFinding]]
    ) -> None:
        """Add a custom analysis rule"""
        self.custom_rules.append(rule)
    
    def analyze(
        self,
        request: ToolExecutionRequest,
        result: ExecutionResult
    ) -> BehaviorAnalysis:
        """
        Analyze execution behavior
        
        Args:
            request: The execution request
            result: The execution result
            
        Returns:
            BehaviorAnalysis with findings and risk assessment
        """
        analysis = BehaviorAnalysis(
            tool_name=request.tool_name,
            command=result.command,
            exit_code=result.exit_code,
        )
        
        # Analyze stdout and stderr
        combined_output = f"{result.stdout}\n{result.stderr}"
        
        # Check for suspicious patterns
        self._analyze_command_patterns(analysis, result.command)
        self._analyze_output_patterns(analysis, combined_output)
        self._analyze_network_indicators(analysis, combined_output)
        
        # Analyze resource usage
        self._analyze_resource_usage(analysis, result)
        
        # Analyze exit code
        self._analyze_exit_code(analysis, result)
        
        # Run custom rules
        for rule in self.custom_rules:
            try:
                finding = rule(result.command, combined_output, result.to_dict())
                if finding:
                    analysis.findings.append(finding)
            except Exception as e:
                logger.error(f"Custom rule failed: {e}")
        
        # Calculate risk score
        analysis.risk_score = self._calculate_risk_score(analysis)
        
        # Generate recommendations
        analysis.recommendations = self._generate_recommendations(analysis)
        
        return analysis
    
    def _analyze_command_patterns(
        self,
        analysis: BehaviorAnalysis,
        command: str
    ) -> None:
        """Analyze command for suspicious patterns"""
        for category, patterns in self.SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    severity = self._get_pattern_severity(category)
                    analysis.findings.append(BehaviorFinding(
                        category=BehaviorCategory.CODE_EXECUTION,
                        severity=severity,
                        description=f"Suspicious pattern detected: {category}",
                        details={
                            "pattern_category": category,
                            "matched_pattern": pattern,
                            "command_preview": command[:200]
                        },
                        evidence=[f"Matched: {pattern}"]
                    ))
    
    def _analyze_output_patterns(
        self,
        analysis: BehaviorAnalysis,
        output: str
    ) -> None:
        """Analyze output for suspicious patterns"""
        # Check for sensitive file access attempts
        for path in self.SENSITIVE_PATHS:
            if path in output.lower():
                analysis.findings.append(BehaviorFinding(
                    category=BehaviorCategory.FILE_SYSTEM,
                    severity=BehaviorSeverity.MEDIUM,
                    description=f"Access to sensitive path detected: {path}",
                    details={"sensitive_path": path},
                    evidence=[output[max(0, output.find(path)-50):output.find(path)+len(path)+50]]
                ))
        
        # Check for error messages indicating privilege issues
        privilege_errors = [
            'permission denied',
            'operation not permitted',
            'access denied',
            'authentication failed',
            'unauthorized',
        ]
        
        for error in privilege_errors:
            if error in output.lower():
                analysis.findings.append(BehaviorFinding(
                    category=BehaviorCategory.PROCESS,
                    severity=BehaviorSeverity.LOW,
                    description=f"Permission/authentication error detected",
                    details={"error_type": error},
                    evidence=[]
                ))
    
    def _analyze_network_indicators(
        self,
        analysis: BehaviorAnalysis,
        output: str
    ) -> None:
        """Analyze for network activity indicators"""
        for pattern in self.NETWORK_INDICATORS:
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                analysis.network_indicators.extend(matches)
                analysis.findings.append(BehaviorFinding(
                    category=BehaviorCategory.NETWORK,
                    severity=BehaviorSeverity.MEDIUM,
                    description="Network activity indicators detected",
                    details={"indicators": matches[:10]},  # Limit to 10
                    evidence=matches[:3]
                ))
    
    def _analyze_resource_usage(
        self,
        analysis: BehaviorAnalysis,
        result: ExecutionResult
    ) -> None:
        """Analyze resource usage patterns"""
        analysis.resource_usage = {
            "duration_ms": result.duration_ms,
            "memory_peak_mb": result.memory_peak_mb,
            "cpu_usage_percent": result.cpu_usage_percent,
        }
        
        # Check for excessive memory usage
        if result.memory_peak_mb > 1024:  # > 1GB
            analysis.findings.append(BehaviorFinding(
                category=BehaviorCategory.RESOURCE,
                severity=BehaviorSeverity.MEDIUM,
                description=f"High memory usage detected: {result.memory_peak_mb:.1f} MB",
                details={"memory_mb": result.memory_peak_mb},
                evidence=[]
            ))
        
        # Check for timeout
        if result.timed_out:
            analysis.findings.append(BehaviorFinding(
                category=BehaviorCategory.RESOURCE,
                severity=BehaviorSeverity.HIGH,
                description="Execution timed out - possible infinite loop or resource exhaustion",
                details={"duration_ms": result.duration_ms},
                evidence=[]
            ))
        
        # Check for excessive duration
        if result.duration_ms > 60000:  # > 60 seconds
            analysis.findings.append(BehaviorFinding(
                category=BehaviorCategory.RESOURCE,
                severity=BehaviorSeverity.LOW,
                description=f"Long execution time: {result.duration_ms/1000:.1f}s",
                details={"duration_ms": result.duration_ms},
                evidence=[]
            ))
    
    def _analyze_exit_code(
        self,
        analysis: BehaviorAnalysis,
        result: ExecutionResult
    ) -> None:
        """Analyze exit code for anomalies"""
        if result.exit_code != 0 and not result.timed_out:
            # Non-zero exit code
            severity = BehaviorSeverity.LOW
            if result.exit_code < 0 or result.exit_code > 128:
                severity = BehaviorSeverity.MEDIUM  # Signal termination
            
            analysis.findings.append(BehaviorFinding(
                category=BehaviorCategory.PROCESS,
                severity=severity,
                description=f"Process exited with non-zero code: {result.exit_code}",
                details={
                    "exit_code": result.exit_code,
                    "stderr_preview": result.stderr[:200] if result.stderr else ""
                },
                evidence=[result.stderr[:500]] if result.stderr else []
            ))
    
    def _get_pattern_severity(self, category: str) -> BehaviorSeverity:
        """Get severity for pattern category"""
        severity_map = {
            'reverse_shell': BehaviorSeverity.CRITICAL,
            'command_injection': BehaviorSeverity.HIGH,
            'data_exfiltration': BehaviorSeverity.HIGH,
            'privilege_escalation': BehaviorSeverity.CRITICAL,
        }
        return severity_map.get(category, BehaviorSeverity.MEDIUM)
    
    def _calculate_risk_score(self, analysis: BehaviorAnalysis) -> int:
        """
        Calculate overall risk score (0-100)
        
        Based on:
        - Number and severity of findings
        - Exit code anomalies
        - Resource usage patterns
        """
        score = 0
        
        # Score based on findings
        severity_scores = {
            BehaviorSeverity.INFO: 2,
            BehaviorSeverity.LOW: 5,
            BehaviorSeverity.MEDIUM: 15,
            BehaviorSeverity.HIGH: 30,
            BehaviorSeverity.CRITICAL: 50,
        }
        
        for finding in analysis.findings:
            score += severity_scores.get(finding.severity, 5)
        
        # Cap at 100
        return min(score, 100)
    
    def _generate_recommendations(self, analysis: BehaviorAnalysis) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if analysis.has_critical_findings:
            recommendations.append(
                "CRITICAL: Block execution immediately. Review tool for malicious code."
            )
        
        if analysis.has_high_findings:
            recommendations.append(
                "HIGH: Consider blocking execution. Manual review recommended."
            )
        
        # Category-specific recommendations
        categories = set(f.category for f in analysis.findings)
        
        if BehaviorCategory.NETWORK in categories:
            recommendations.append(
                "Consider restricting network access for this tool"
            )
        
        if BehaviorCategory.FILE_SYSTEM in categories:
            recommendations.append(
                "Review file system access permissions"
            )
        
        if BehaviorCategory.RESOURCE in categories:
            recommendations.append(
                "Consider implementing stricter resource limits"
            )
        
        if not recommendations:
            recommendations.append("No significant security concerns detected")
        
        return recommendations
    
    def analyze_quick(
        self,
        command: str,
        stdout: str,
        stderr: str,
        exit_code: int
    ) -> Dict[str, Any]:
        """
        Quick analysis without full request/result objects
        
        Returns:
            Simple dict with risk score and warnings
        """
        request = ToolExecutionRequest(
            tool_name="unknown",
            command=command.split(),
        )
        
        result = ExecutionResult(
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=0
        )
        
        analysis = self.analyze(request, result)
        
        return {
            "risk_score": analysis.risk_score,
            "has_warnings": analysis.has_high_findings,
            "has_critical": analysis.has_critical_findings,
            "findings_count": len(analysis.findings),
            "top_findings": [
                f"{f.category.name}: {f.description[:50]}"
                for f in analysis.findings[:3]
            ]
        }


class BehaviorAnalyzerPlugin:
    """
    Plugin interface for behavior analysis
    
    Integrates with the XClaw AgentGuard plugin system.
    """
    
    PLUGIN_ID = "behavior_analyzer"
    PLUGIN_VERSION = "1.0.0"
    PLUGIN_NAME = "Behavior Analyzer"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.analyzer = BehaviorAnalyzer(config)
        self.threshold = config.get('threshold', 50) if config else 50
    
    def analyze_execution(
        self,
        request: ToolExecutionRequest,
        result: ExecutionResult
    ) -> BehaviorAnalysis:
        """Analyze execution and return results"""
        return self.analyzer.analyze(request, result)
    
    def should_block(self, analysis: BehaviorAnalysis) -> bool:
        """Determine if execution should be blocked based on analysis"""
        if analysis.has_critical_findings:
            return True
        if analysis.risk_score >= self.threshold:
            return True
        return False


__all__ = [
    "BehaviorAnalyzer",
    "BehaviorAnalyzerPlugin",
    "BehaviorAnalysis",
    "BehaviorFinding",
    "BehaviorSeverity",
    "BehaviorCategory",
]