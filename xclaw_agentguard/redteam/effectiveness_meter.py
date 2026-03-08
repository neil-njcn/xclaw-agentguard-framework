"""
Effectiveness Meter Module

Measures defense effectiveness by calculating detection rates,
measuring response times, and scoring overall security posture.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple, Callable
from collections import defaultdict

from ..core.detection_result import DetectionResult, ThreatLevel, AttackType
from .attack_simulator import AttackSimulator, SimulatedAttack, AttackOutcome


class MetricType(Enum):
    """Types of effectiveness metrics."""
    DETECTION_RATE = "detection_rate"
    RESPONSE_TIME = "response_time"
    FALSE_POSITIVE_RATE = "false_positive_rate"
    FALSE_NEGATIVE_RATE = "false_negative_rate"
    PRECISION = "precision"
    RECALL = "recall"
    F1_SCORE = "f1_score"
    COVERAGE = "coverage"
    THROUGHPUT = "throughput"


@dataclass
class MetricValue:
    """A metric value with statistics."""
    value: float
    unit: str
    timestamp: datetime
    sample_size: int
    confidence_interval: Optional[Tuple[float, float]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": round(self.value, 4),
            "unit": self.unit,
            "timestamp": self.timestamp.isoformat(),
            "sample_size": self.sample_size,
            "confidence_interval": self.confidence_interval
        }


@dataclass
class DetectorMetrics:
    """Metrics for a specific detector."""
    detector_id: str
    detector_name: str
    
    # Detection metrics
    total_tests: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    
    # Performance metrics
    response_times_ms: List[float]
    avg_response_time_ms: float
    min_response_time_ms: float
    max_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    
    # Calculated metrics
    detection_rate: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    
    # Attack type breakdown
    detection_by_type: Dict[str, float]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector_id": self.detector_id,
            "detector_name": self.detector_name,
            "total_tests": self.total_tests,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "avg_response_time_ms": round(self.avg_response_time_ms, 2),
            "p95_response_time_ms": round(self.p95_response_time_ms, 2),
            "p99_response_time_ms": round(self.p99_response_time_ms, 2),
            "detection_rate": round(self.detection_rate, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
            "detection_by_type": {k: round(v, 4) for k, v in self.detection_by_type.items()}
        }


@dataclass
class DefenseMetrics:
    """Comprehensive defense effectiveness metrics."""
    measured_at: datetime
    measurement_period_hours: int
    
    # Overall metrics
    overall_detection_rate: float
    overall_false_positive_rate: float
    overall_response_time_ms: float
    
    # Per-detector metrics
    detector_metrics: List[DetectorMetrics]
    
    # Per-attack-type metrics
    detection_by_attack_type: Dict[str, float]
    
    # Threat level metrics
    detection_by_threat_level: Dict[str, float]
    
    # Time-based metrics (trends)
    detection_trend: str  # improving, stable, declining
    response_time_trend: str
    
    # Coverage metrics
    attack_type_coverage: float  # % of attack types covered
    threat_level_coverage: float
    
    # Metadata
    total_simulations: int
    unique_payloads_tested: int
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "measured_at": self.measured_at.isoformat(),
            "measurement_period_hours": self.measurement_period_hours,
            "overall_detection_rate": round(self.overall_detection_rate, 4),
            "overall_false_positive_rate": round(self.overall_false_positive_rate, 4),
            "overall_response_time_ms": round(self.overall_response_time_ms, 2),
            "detector_metrics": [m.to_dict() for m in self.detector_metrics],
            "detection_by_attack_type": {k: round(v, 4) for k, v in self.detection_by_attack_type.items()},
            "detection_by_threat_level": {k: round(v, 4) for k, v in self.detection_by_threat_level.items()},
            "detection_trend": self.detection_trend,
            "response_time_trend": self.response_time_trend,
            "attack_type_coverage": round(self.attack_type_coverage, 4),
            "threat_level_coverage": round(self.threat_level_coverage, 4),
            "total_simulations": self.total_simulations,
            "unique_payloads_tested": self.unique_payloads_tested
        }


@dataclass
class SecurityScore:
    """Overall security posture score."""
    overall_score: float  # 0-100
    detection_score: float  # 0-100
    performance_score: float  # 0-100
    coverage_score: float  # 0-100
    reliability_score: float  # 0-100
    
    # Grading
    letter_grade: str  # A+, A, A-, B+, etc.
    
    # Component breakdown
    component_scores: Dict[str, float]
    
    # Benchmark comparison
    percentile: Optional[float] = None  # Compared to industry
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_score": round(self.overall_score, 2),
            "detection_score": round(self.detection_score, 2),
            "performance_score": round(self.performance_score, 2),
            "coverage_score": round(self.coverage_score, 2),
            "reliability_score": round(self.reliability_score, 2),
            "letter_grade": self.letter_grade,
            "component_scores": {k: round(v, 2) for k, v in self.component_scores.items()},
            "percentile": self.percentile
        }
    
    def generate_summary(self) -> str:
        """Generate human-readable summary."""
        return f"""
Security Posture Score: {self.overall_score:.1f}/100 ({self.letter_grade})

Component Breakdown:
  Detection:    {self.detection_score:.1f}/100
  Performance:  {self.performance_score:.1f}/100
  Coverage:     {self.coverage_score:.1f}/100
  Reliability:  {self.reliability_score:.1f}/100

{self._get_grade_description()}
"""
    
    def _get_grade_description(self) -> str:
        """Get description for grade."""
        if self.letter_grade.startswith("A"):
            return "Excellent security posture. Defenses are robust and well-tuned."
        elif self.letter_grade.startswith("B"):
            return "Good security posture with minor areas for improvement."
        elif self.letter_grade.startswith("C"):
            return "Average security posture. Significant improvements recommended."
        elif self.letter_grade.startswith("D"):
            return "Below average. Immediate attention required for critical gaps."
        else:
            return "Critical security gaps present. Immediate action required."


@dataclass
class EffectivenessReport:
    """Complete effectiveness measurement report."""
    report_id: str
    generated_at: datetime
    metrics: DefenseMetrics
    security_score: SecurityScore
    historical_comparison: Optional[Dict[str, Any]] = None
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at.isoformat(),
            "metrics": self.metrics.to_dict(),
            "security_score": self.security_score.to_dict(),
            "historical_comparison": self.historical_comparison,
            "recommendations": self.recommendations
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class EffectivenessMeter:
    """Measures defense effectiveness."""
    
    # Grade thresholds
    GRADE_THRESHOLDS = [
        (97, "A+"), (93, "A"), (90, "A-"),
        (87, "B+"), (83, "B"), (80, "B-"),
        (77, "C+"), (73, "C"), (70, "C-"),
        (67, "D+"), (63, "D"), (60, "D-"),
        (0, "F")
    ]
    
    def __init__(
        self,
        attack_simulator: Optional[AttackSimulator] = None,
        measurement_history_size: int = 100
    ):
        self.attack_simulator = attack_simulator
        self._measurement_history: List[DefenseMetrics] = []
        self._history_size = measurement_history_size
        self._baseline_metrics: Optional[DefenseMetrics] = None
    
    def measure_effectiveness(
        self,
        simulation_results: Optional[List[SimulatedAttack]] = None,
        hours_of_history: int = 24
    ) -> DefenseMetrics:
        """Measure current defense effectiveness."""
        if simulation_results is None and self.attack_simulator:
            # Run simulations
            report = self.attack_simulator.simulate_campaign()
            simulation_results = []
            for attacks in report.attacks_by_type.values():
                simulation_results.extend(attacks)
        
        if not simulation_results:
            raise ValueError("No simulation results available for measurement")
        
        # Calculate overall metrics
        total = len(simulation_results)
        detected = sum(1 for a in simulation_results if a.outcome == AttackOutcome.DETECTED)
        undetected = sum(1 for a in simulation_results if a.outcome == AttackOutcome.UNDETECTED)
        
        detection_rate = detected / total if total > 0 else 0
        
        # Response times
        response_times = [
            a.response_time_ms for a in simulation_results
            if a.outcome == AttackOutcome.DETECTED and a.response_time_ms > 0
        ]
        
        avg_response = statistics.mean(response_times) if response_times else 0
        
        # Per-detector metrics
        detector_metrics = self._calculate_detector_metrics(simulation_results)
        
        # Per-attack-type metrics
        detection_by_type = self._calculate_type_metrics(simulation_results)
        
        # Per-threat-level metrics
        detection_by_level = self._calculate_level_metrics(simulation_results)
        
        # Calculate trends
        detection_trend = self._calculate_detection_trend(detection_rate)
        response_trend = self._calculate_response_trend(avg_response)
        
        # Calculate coverage
        attack_types_tested = set(
            str(a.attack_type) for a in simulation_results
        )
        all_attack_types = set(str(t) for t in AttackType)
        type_coverage = len(attack_types_tested) / len(all_attack_types) if all_attack_types else 0
        
        threat_levels_tested = set()
        for a in simulation_results:
            if hasattr(a, 'expected_threat_level'):
                threat_levels_tested.add(str(a.expected_threat_level))
        all_levels = set(str(l) for l in ThreatLevel)
        level_coverage = len(threat_levels_tested) / len(all_levels) if all_levels else 0
        
        metrics = DefenseMetrics(
            measured_at=datetime.now(),
            measurement_period_hours=hours_of_history,
            overall_detection_rate=detection_rate,
            overall_false_positive_rate=0.0,  # Would need benign data
            overall_response_time_ms=avg_response,
            detector_metrics=detector_metrics,
            detection_by_attack_type=detection_by_type,
            detection_by_threat_level=detection_by_level,
            detection_trend=detection_trend,
            response_time_trend=response_trend,
            attack_type_coverage=type_coverage,
            threat_level_coverage=level_coverage,
            total_simulations=total,
            unique_payloads_tested=len(set(a.payload for a in simulation_results))
        )
        
        # Store in history
        self._measurement_history.append(metrics)
        if len(self._measurement_history) > self._history_size:
            self._measurement_history = self._measurement_history[-self._history_size:]
        
        return metrics
    
    def calculate_security_score(self, metrics: DefenseMetrics) -> SecurityScore:
        """Calculate overall security posture score."""
        # Detection score (40% weight)
        detection_score = metrics.overall_detection_rate * 100
        
        # Performance score (25% weight)
        # Lower response time = higher score
        if metrics.overall_response_time_ms <= 10:
            perf_score = 100
        elif metrics.overall_response_time_ms <= 50:
            perf_score = 90
        elif metrics.overall_response_time_ms <= 100:
            perf_score = 80
        elif metrics.overall_response_time_ms <= 500:
            perf_score = 60
        else:
            perf_score = 40
        
        # Coverage score (20% weight)
        coverage_score = (
            metrics.attack_type_coverage * 50 +
            metrics.threat_level_coverage * 50
        )
        
        # Reliability score (15% weight)
        # Based on consistency across detectors
        if metrics.detector_metrics:
            detection_rates = [m.detection_rate for m in metrics.detector_metrics]
            if detection_rates:
                variance = statistics.variance(detection_rates) if len(detection_rates) > 1 else 0
                reliability_score = max(0, 100 - variance * 100)
            else:
                reliability_score = 50
        else:
            reliability_score = 50
        
        # Calculate weighted overall score
        overall = (
            detection_score * 0.40 +
            perf_score * 0.25 +
            coverage_score * 0.20 +
            reliability_score * 0.15
        )
        
        # Determine letter grade
        letter_grade = "F"
        for threshold, grade in self.GRADE_THRESHOLDS:
            if overall >= threshold:
                letter_grade = grade
                break
        
        # Component breakdown
        components = {
            "Prompt Injection Detection": metrics.detection_by_attack_type.get("prompt_injection", 0) * 100,
            "Jailbreak Detection": metrics.detection_by_attack_type.get("jailbreak", 0) * 100,
            "Data Extraction Prevention": metrics.detection_by_attack_type.get("data_extraction", 0) * 100,
            "Agent Hijacking Protection": metrics.detection_by_attack_type.get("agent_hijacking", 0) * 100,
            "Tool Abuse Prevention": metrics.detection_by_attack_type.get("tool_abuse", 0) * 100,
        }
        
        return SecurityScore(
            overall_score=overall,
            detection_score=detection_score,
            performance_score=perf_score,
            coverage_score=coverage_score,
            reliability_score=reliability_score,
            letter_grade=letter_grade,
            component_scores=components
        )
    
    def generate_report(
        self,
        include_historical: bool = True
    ) -> EffectivenessReport:
        """Generate comprehensive effectiveness report."""
        # Measure current effectiveness
        metrics = self.measure_effectiveness()
        
        # Calculate security score
        score = self.calculate_security_score(metrics)
        
        # Historical comparison
        historical = None
        if include_historical and len(self._measurement_history) > 1:
            historical = self._compare_with_history(metrics)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(metrics, score)
        
        return EffectivenessReport(
            report_id=f"eff_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            generated_at=datetime.now(),
            metrics=metrics,
            security_score=score,
            historical_comparison=historical,
            recommendations=recommendations
        )
    
    def set_baseline(self, metrics: DefenseMetrics) -> None:
        """Set baseline metrics for comparison."""
        self._baseline_metrics = metrics
    
    def compare_to_baseline(self, metrics: DefenseMetrics) -> Dict[str, Any]:
        """Compare metrics to baseline."""
        if not self._baseline_metrics:
            return {"error": "No baseline set"}
        
        return {
            "detection_rate_delta": round(
                metrics.overall_detection_rate - self._baseline_metrics.overall_detection_rate, 4
            ),
            "response_time_delta_ms": round(
                metrics.overall_response_time_ms - self._baseline_metrics.overall_response_time_ms, 2
            ),
            "coverage_delta": round(
                metrics.attack_type_coverage - self._baseline_metrics.attack_type_coverage, 4
            ),
            "improved": metrics.overall_detection_rate > self._baseline_metrics.overall_detection_rate
        }
    
    def get_metric_trend(
        self,
        metric_type: MetricType,
        hours: int = 168  # 1 week
    ) -> List[Dict[str, Any]]:
        """Get historical trend for a metric."""
        cutoff = datetime.now() - timedelta(hours=hours)
        relevant = [m for m in self._measurement_history if m.measured_at >= cutoff]
        
        trend = []
        for m in relevant:
            value = self._extract_metric(m, metric_type)
            trend.append({
                "timestamp": m.measured_at.isoformat(),
                "value": value
            })
        
        return trend
    
    def export_metrics(self, filepath: str, format: str = "json") -> None:
        """Export metrics to file."""
        data = {
            "export_timestamp": datetime.now().isoformat(),
            "measurement_count": len(self._measurement_history),
            "measurements": [m.to_dict() for m in self._measurement_history]
        }
        
        if format == "json":
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
    
    def _calculate_detector_metrics(
        self,
        attacks: List[SimulatedAttack]
    ) -> List[DetectorMetrics]:
        """Calculate metrics per detector."""
        # Group results by detector
        detector_results: Dict[str, List[Tuple[bool, float]]] = defaultdict(list)
        detector_names: Dict[str, str] = {}
        
        for attack in attacks:
            for result in attack.detection_results:
                detector_id = result.metadata.detector_id if hasattr(result, 'metadata') and hasattr(result.metadata, 'detector_id') else "unknown"
                detected = hasattr(result, 'detected') and result.detected
                response_time = result.metadata.processing_time_ms if hasattr(result, 'metadata') and hasattr(result.metadata, 'processing_time_ms') else 0
                
                detector_results[detector_id].append((detected, response_time))
        
        metrics = []
        for detector_id, results in detector_results.items():
            detected_count = sum(1 for d, _ in results if d)
            total = len(results)
            
            response_times = [t for _, t in results if t > 0]
            
            if response_times:
                sorted_times = sorted(response_times)
                p95_idx = int(len(sorted_times) * 0.95)
                p99_idx = int(len(sorted_times) * 0.99)
                
                avg_response = statistics.mean(response_times)
                p95 = sorted_times[min(p95_idx, len(sorted_times)-1)]
                p99 = sorted_times[min(p99_idx, len(sorted_times)-1)]
            else:
                avg_response = p95 = p99 = 0
            
            detection_rate = detected_count / total if total > 0 else 0
            
            # Calculate precision/recall (simplified)
            tp = detected_count
            fp = 0  # Would need benign samples
            fn = total - detected_count
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            
            metrics.append(DetectorMetrics(
                detector_id=detector_id,
                detector_name=detector_names.get(detector_id, detector_id),
                total_tests=total,
                true_positives=tp,
                false_positives=fp,
                true_negatives=0,
                false_negatives=fn,
                response_times_ms=response_times,
                avg_response_time_ms=avg_response,
                min_response_time_ms=min(response_times) if response_times else 0,
                max_response_time_ms=max(response_times) if response_times else 0,
                p95_response_time_ms=p95,
                p99_response_time_ms=p99,
                detection_rate=detection_rate,
                precision=precision,
                recall=recall,
                f1_score=f1,
                false_positive_rate=0,
                false_negative_rate=fn / total if total > 0 else 0,
                detection_by_type={}
            ))
        
        return metrics
    
    def _calculate_type_metrics(
        self,
        attacks: List[SimulatedAttack]
    ) -> Dict[str, float]:
        """Calculate detection rates by attack type."""
        by_type: Dict[str, List[bool]] = defaultdict(list)
        
        for attack in attacks:
            type_key = attack.attack_type.value if hasattr(attack.attack_type, 'value') else str(attack.attack_type)
            detected = attack.outcome == AttackOutcome.DETECTED
            by_type[type_key].append(detected)
        
        return {
            attack_type: sum(detected) / len(detected)
            for attack_type, detected in by_type.items()
        }
    
    def _calculate_level_metrics(
        self,
        attacks: List[SimulatedAttack]
    ) -> Dict[str, float]:
        """Calculate detection rates by threat level."""
        by_level: Dict[str, List[bool]] = defaultdict(list)
        
        for attack in attacks:
            level_key = attack.expected_threat_level.value if hasattr(attack.expected_threat_level, 'value') else str(attack.expected_threat_level)
            detected = attack.outcome == AttackOutcome.DETECTED
            by_level[level_key].append(detected)
        
        return {
            level: sum(detected) / len(detected)
            for level, detected in by_level.items()
        }
    
    def _calculate_detection_trend(self, current_rate: float) -> str:
        """Calculate detection rate trend."""
        if len(self._measurement_history) < 2:
            return "stable"
        
        prev_rate = self._measurement_history[-2].overall_detection_rate
        
        if current_rate > prev_rate * 1.05:
            return "improving"
        elif current_rate < prev_rate * 0.95:
            return "declining"
        return "stable"
    
    def _calculate_response_trend(self, current_time: float) -> str:
        """Calculate response time trend."""
        if len(self._measurement_history) < 2:
            return "stable"
        
        prev_time = self._measurement_history[-2].overall_response_time_ms
        
        if current_time < prev_time * 0.9:
            return "improving"
        elif current_time > prev_time * 1.1:
            return "declining"
        return "stable"
    
    def _extract_metric(self, metrics: DefenseMetrics, metric_type: MetricType) -> float:
        """Extract specific metric from metrics object."""
        mapping = {
            MetricType.DETECTION_RATE: metrics.overall_detection_rate,
            MetricType.RESPONSE_TIME: metrics.overall_response_time_ms,
            MetricType.FALSE_POSITIVE_RATE: metrics.overall_false_positive_rate,
            MetricType.COVERAGE: metrics.attack_type_coverage
        }
        return mapping.get(metric_type, 0.0)
    
    def _compare_with_history(self, current: DefenseMetrics) -> Dict[str, Any]:
        """Compare current metrics with historical average."""
        if len(self._measurement_history) < 2:
            return None
        
        historical = self._measurement_history[:-1]  # Exclude current
        
        avg_detection = statistics.mean(m.overall_detection_rate for m in historical)
        avg_response = statistics.mean(m.overall_response_time_ms for m in historical)
        
        return {
            "historical_avg_detection_rate": round(avg_detection, 4),
            "detection_rate_change": round(current.overall_detection_rate - avg_detection, 4),
            "historical_avg_response_time_ms": round(avg_response, 2),
            "response_time_change_ms": round(current.overall_response_time_ms - avg_response, 2),
            "comparison_period_measurements": len(historical)
        }
    
    def _generate_recommendations(
        self,
        metrics: DefenseMetrics,
        score: SecurityScore
    ) -> List[str]:
        """Generate recommendations based on metrics."""
        recommendations = []
        
        # Detection rate recommendations
        if metrics.overall_detection_rate < 0.8:
            recommendations.append(
                f"Detection rate ({metrics.overall_detection_rate:.1%}) is below target (80%). "
                "Review and enhance detection patterns."
            )
        
        # Response time recommendations
        if metrics.overall_response_time_ms > 100:
            recommendations.append(
                f"Average response time ({metrics.overall_response_time_ms:.0f}ms) exceeds target (100ms). "
                "Consider performance optimization."
            )
        
        # Coverage recommendations
        if metrics.attack_type_coverage < 0.8:
            missing_types = []
            for attack_type in AttackType:
                type_key = attack_type.value if hasattr(attack_type, 'value') else str(attack_type)
                if type_key not in metrics.detection_by_attack_type:
                    missing_types.append(type_key)
            
            if missing_types:
                recommendations.append(
                    f"Missing test coverage for attack types: {', '.join(missing_types[:3])}"
                )
        
        # Per-attack-type recommendations
        for attack_type, rate in metrics.detection_by_attack_type.items():
            if rate < 0.7:
                recommendations.append(
                    f"Low detection rate for {attack_type} ({rate:.1%}). Consider specialized detector."
                )
        
        # Component-specific recommendations
        for component, comp_score in score.component_scores.items():
            if comp_score < 70:
                recommendations.append(
                    f"Strengthen {component} defenses (current score: {comp_score:.0f}/100)"
                )
        
        return recommendations


# Convenience functions
def quick_assessment(attack_simulator: AttackSimulator) -> SecurityScore:
    """Quick security assessment."""
    meter = EffectivenessMeter(attack_simulator)
    metrics = meter.measure_effectiveness()
    return meter.calculate_security_score(metrics)
