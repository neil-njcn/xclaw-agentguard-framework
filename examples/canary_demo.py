"""
Canary Release Mechanism Usage Example

This example demonstrates how to use the Canary release mechanism to gradually roll out new detector versions.
"""
import time
import sys
import os
# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xclaw_agentguard.core.canary_registry import CanaryRegistry, create_canary_config
from xclaw_agentguard.core.base_detector import BaseDetector, DetectionResult


class OldSQLInjectionDetector(BaseDetector):
    """Old SQL Injection Detector (baseline)"""
    
    def detect(self, input_data):
        # Simplified detection logic
        if "'" in str(input_data) or ";" in str(input_data):
            return DetectionResult.success(detected=True, confidence=0.7)
        return DetectionResult.success(detected=False, confidence=0.9)


class NewSQLInjectionDetector(BaseDetector):
    """New SQL Injection Detector (improved version)"""
    
    def detect(self, input_data):
        # Improved detection logic with lower false positive rate
        input_str = str(input_data).lower()
        patterns = ["'", ";", "--", "union", "select", "drop"]
        score = sum(1 for p in patterns if p in input_str)
        
        if score >= 2:
            return DetectionResult.success(detected=True, confidence=0.95)
        return DetectionResult.success(detected=False, confidence=0.98)


def demo_canary_rollout():
    """Demonstrate Canary release process"""
    
    print("=" * 60)
    print("Canary Release Mechanism Demo")
    print("=" * 60)
    
    # 1. Create registry
    registry = CanaryRegistry(enable_auto_monitoring=True)
    
    # 2. Create detectors
    old_detector = OldSQLInjectionDetector("sql_injection_v1")
    new_detector = NewSQLInjectionDetector("sql_injection_v2")
    
    # 3. Configure Canary release
    config = create_canary_config(
        detector_id="sql_injection_v2",
        rollout_percentage=5,          # Start from 5%
        false_positive_rate=0.01,      # Target false positive rate 1%
        latency_p99=100,               # Target P99 latency 100ms
        auto_promote=True,             # Auto promote
        rollback_threshold=0.05,       # Auto rollback if false positive rate exceeds 5%
        observation_minutes=1          # 1 minute observation per stage (for demo)
    )
    
    # 4. Register Canary pair
    registry.register_canary_pair(
        "sql_injection_v2",
        new_detector,
        old_detector,
        config
    )
    
    # 5. Enable Canary
    registry.enable_with_canary("sql_injection_v2")
    
    print(f"\n[Stage 1] Canary enabled: 5% traffic")
    status = registry.get_canary_status("sql_injection_v2")
    print(f"  Current stage: {status['current_stage']}")
    print(f"  Traffic percentage: {status['current_percentage']}%")
    
    # 6. Simulate requests
    test_inputs = [
        "normal_user_input",
        "SELECT * FROM users",  # False positive candidate
        "admin' OR '1'='1",
        "safe_input_123",
        "'; DROP TABLE users; --",
        "username=test",
    ]
    
    print("\n[Simulated Requests]")
    for i, input_data in enumerate(test_inputs * 20):  # 120 requests
        # Simulate user ID for consistent routing
        user_id = f"user_{i % 10}"
        
        result = registry.detect(
            "sql_injection_v2",
            input_data=input_data,
            user_id=user_id,
            ground_truth=False  # Assume these are all normal requests
        )
        
        if i < 5:  # Only print first 5
            print(f"  Request {i+1}: input='{input_data[:30]}...' detected={result.detected}")
    
    # 7. View metrics
    print("\n[Current Metrics]")
    status = registry.get_canary_status("sql_injection_v2")
    metrics = status['metrics']
    print(f"  Total requests: {metrics['total_requests']}")
    print(f"  New detector requests: {metrics['new_detector_requests']}")
    print(f"  False positive rate: {metrics['false_positive_rate']:.4f}")
    print(f"  P99 latency: {metrics['p99_latency']:.2f}ms")
    
    # 8. Manual promotion (in real scenarios handled by monitoring thread)
    print("\n[Manual Promotion]")
    registry.promote("sql_injection_v2")
    status = registry.get_canary_status("sql_injection_v2")
    print(f"  Stage after promotion: {status['current_stage']}")
    print(f"  Traffic percentage: {status['current_percentage']}%")
    
    # 9. Continue promotion until GA
    print("\n[Continue Promotion]")
    registry.promote("sql_injection_v2")
    status = registry.get_canary_status("sql_injection_v2")
    print(f"  Current stage: {status['current_stage']} ({status['current_percentage']}%)")
    
    registry.promote("sql_injection_v2")
    status = registry.get_canary_status("sql_injection_v2")
    print(f"  Current stage: {status['current_stage']} ({status['current_percentage']}%)")
    
    # 10. List active Canaries
    print("\n[Active Canary List]")
    active = registry.list_active_canaries()
    for detector_id in active:
        status = registry.get_canary_status(detector_id)
        print(f"  - {detector_id}: {status['current_stage']} ({status['current_percentage']}%)")
    
    # Cleanup
    registry.shutdown()
    
    print("\n" + "=" * 60)
    print("Demo completed!")
    print("=" * 60)


def demo_rollback():
    """Demonstrate rollback mechanism"""
    
    print("\n" + "=" * 60)
    print("Rollback Mechanism Demo")
    print("=" * 60)
    
    registry = CanaryRegistry(enable_auto_monitoring=False)
    
    # Register a problematic detector
    old_detector = OldSQLInjectionDetector("sql_injection_v1")
    new_detector = NewSQLInjectionDetector("sql_injection_v2")
    
    config = create_canary_config(
        detector_id="bad_detector",
        rollout_percentage=20,
        rollback_threshold=0.10  # 10% false positive rate threshold
    )
    
    registry.register_canary_pair(
        "bad_detector",
        new_detector,
        old_detector,
        config
    )
    
    registry.enable_with_canary("bad_detector")
    
    print("\n[Simulate High False Positives]")
    # Simulate high false positives (all normal inputs misjudged)
    for i in range(100):
        registry.detect(
            "bad_detector",
            input_data=f"normal_safe_input_{i}",
            ground_truth=False,  # Actually safe
        )
        # But assume new detector detects as threat (false positive)
        # Here we manually record metrics to simulate
        from xclaw_agentguard.core.canary_controller import get_canary_controller
        controller = get_canary_controller()
        controller.record_request(
            "bad_detector",
            used_new_detector=True,
            latency_ms=50.0,
            detected=True,  # Detected as threat
            ground_truth=False  # But actually no threat
        )
    
    status = registry.get_canary_status("bad_detector")
    print(f"  False positive rate: {status['metrics']['false_positive_rate']:.2f}")
    
    # Evaluate whether to rollback
    decision = registry.evaluate("bad_detector")
    print(f"  Evaluation result: {decision.value}")
    
    # Execute rollback
    if decision.value == "rollback":
        registry.rollback("bad_detector", reason="high_false_positive_rate")
        print("  Auto rollback executed!")
    
    status = registry.get_canary_status("bad_detector")
    print(f"  Current stage: {status['current_stage']}")
    
    registry.shutdown()
    
    print("\n" + "=" * 60)
    print("Rollback demo completed!")
    print("=" * 60)


if __name__ == "__main__":
    demo_canary_rollout()
    demo_rollback()
