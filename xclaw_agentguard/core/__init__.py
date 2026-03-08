"""
XClaw AgentGuard Core Module

This module provides the foundational infrastructure for the XClaw AgentGuard security framework,
including the canary release system, detector registry, base detector abstractions, and
version management.

Architecture Overview:
    The core module implements a layered architecture for AI security detection:
    
    1. Base Detection Layer (base_detector.py)
       - Abstract base class for all security detectors
       - Template method pattern for standardized detection workflows
       - Attack type classification and metadata management
    
    2. Result Types Layer (detection_result.py)
       - Immutable, type-safe detection result structures
       - Threat severity levels and attack categorization
       - Evidence collection and result aggregation utilities
    
    3. Configuration Layer (config_schema.py)
       - Declarative configuration system with validation
       - Schema-based detector configuration management
       - Type-safe configuration with range and enum constraints
    
    4. Extension System Layer (extension_system.py)
       - Plugin architecture for custom security rules
       - Sandboxed execution environment with timeout protection
       - Extension lifecycle management and registry
    
    5. Canary Release Layer (canary_controller.py, canary_registry.py)
       - Gradual rollout system for detector deployments
       - Automated traffic routing and performance monitoring
       - Automatic promotion/rollback based on metrics
    
    6. Version Management Layer (version_management.py)
       - Semantic versioning for plugins and detectors
       - Dependency resolution and compatibility checking
       - Version constraint satisfaction

Key Concepts:
    - Detectors: Pluggable security analyzers that identify specific attack patterns
    - Canary Releases: Gradual rollout mechanism to minimize risk of detector updates
    - Extensions: Custom security rules that integrate with the detection pipeline
    - Results: Immutable detection outcomes with evidence and metadata

Example Usage:
    >>> from xclaw_agentguard.core import BaseDetector, AttackType, DetectionResult
    >>> from xclaw_agentguard.core import CanaryRegistry, create_canary_config
    >>> 
    >>> # Register a detector with canary release
    >>> registry = CanaryRegistry()
    >>> registry.register("my_detector", MyDetector())
    >>> registry.enable_with_canary("my_detector", config={
    ...     "rollout_percentage": 5,
    ...     "auto_promote": True
    ... })

See Also:
    - base_detector: BaseDetector abstract class and related types
    - canary_controller: Canary release flow control
    - detection_result: Result types and aggregation utilities
"""

# Base detector abstraction and core types
from .base_detector import (
    BaseDetector,
    AttackType,
    DetectionResult,
    DetectorMetadata,
)

# Canary release system components
from .canary_controller import (
    # Enumerations for canary stage management
    CanaryStage,
    RolloutStrategy,
    PromotionDecision,
    
    # Configuration and state dataclasses
    MetricThresholds,
    CanaryConfig,
    DetectorMetrics,
    CanaryState,
    
    # Traffic routing and control
    TrafficRouter,
    CanaryController,
    get_canary_controller,
    reset_canary_controller
)

# Canary registry integration
from .canary_registry import (
    CanaryRegistry,
    create_canary_config,
    get_canary_registry,
    reset_canary_registry
)

__all__ = [
    # Base detector exports
    "BaseDetector",
    "AttackType",
    "DetectionResult",
    "DetectorMetadata",
    
    # Canary system - enumerations
    "CanaryStage",
    "RolloutStrategy",
    "PromotionDecision",
    
    # Canary system - configuration dataclasses
    "MetricThresholds",
    "CanaryConfig",
    "DetectorMetrics",
    "CanaryState",
    
    # Canary system - controllers and utilities
    "TrafficRouter",
    "CanaryController",
    "get_canary_controller",
    "reset_canary_controller",
    
    # Canary system - registry integration
    "CanaryRegistry",
    "create_canary_config",
    "get_canary_registry",
    "reset_canary_registry"
]
