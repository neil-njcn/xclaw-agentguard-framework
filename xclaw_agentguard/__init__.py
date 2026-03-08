"""XClaw AgentGuard - Modular Security Detection System

A comprehensive AI agent security framework with 12 specialized detectors,
plugin system, and version management.
"""

__version__ = "2.3.1"

# Core infrastructure
from .base import BaseDetector
from .detection_result import DetectionResult, ThreatLevel, AttackType, DetectionResultBuilder
from .config import ConfigSchema, ConfigValidator, CommonConfigs, create_config, create_detector_config

# Config hot-reload
from .config_watcher import (
    ConfigFileWatcher,
    ConfigWatcherManager,
    ConfigReloadCallback,
    ConfigChangeEvent,
    get_config_watcher,
    initialize_config_watcher,
    stop_config_watcher,
)

# Sandbox system
from .sandbox import (
    DockerManager,
    SandboxConfig,
    ExecutionResult,
    SandboxExecutor,
    FallbackExecutor,
    ToolExecutionRequest,
    SandboxExecutionContext,
    create_executor,
    BehaviorAnalyzer,
    BehaviorAnalyzerPlugin,
    BehaviorAnalysis,
    BehaviorFinding,
    BehaviorSeverity,
    BehaviorCategory,
)

# Plugin system
from .core.extension_system import (
    AntiJackExtension,
    ExtensionViolation,
    ExtensionMetadata,
    ExtensionRegistry,
    ExtensionSandbox,
    AntiJackedExtensionMixin,
)

# Version management
from .core.version_management import (
    PluginVersion,
    VersionConstraint,
    PluginManifest,
    VersionManager,
    parse_version,
    check_version_constraint,
)

# 12 Security Detectors (from detectors/)
from .detectors.agent_hijacking.detector import AgentHijackingDetector
from .detectors.backdoor_code.detector import BackdoorCodeDetector
from .detectors.exfiltration_guard.detector import ExfiltrationGuard
from .detectors.jailbreak.detector import JailbreakDetector
from .detectors.memory_poisoning.knowledge_poisoning import KnowledgePoisoningDetector
from .detectors.memory_poisoning.context_manipulation import ContextManipulationDetector
from .detectors.output_injection.detector import OutputInjectionDetector
from .detectors.prompt_injection.detector import PromptInjectionDetector
from .detectors.system_prompt_leak.detector import SystemPromptLeakDetector
from .detectors.tool_poisoning.command_inj import CommandInjectionDetector
from .detectors.tool_poisoning.path_traversal import PathTraversalDetector
from .detectors.tool_poisoning.sql_injection import SQLInjectionDetector

# Anti-Jacked Security Base (NEW in v2.3.0)
from .anti_jacked import (
    IntegrityMonitor,
    ImmutableLogChain,
    TamperDetector,
    AutoRecovery,
    get_integrity_monitor,
    get_log_chain,
    get_tamper_detector,
    get_auto_recovery,
    log_event,
)

# Error Contract
from .error_contract import (
    ErrorCategory,
    ErrorContext,
    ErrorMetadata,
    DetectionError,
    ValidationError,
    ConfigurationError,
    RuntimeError,
    SecurityError,
    NetworkError,
    ResourceError,
    create_error_from_exception,
)

__all__ = [
    # Core
    "BaseDetector",
    "DetectionResult",
    "ThreatLevel",
    "AttackType",
    "DetectionResultBuilder",
    "ConfigSchema",
    "ConfigValidator",
    "CommonConfigs",
    "create_config",
    "create_detector_config",
    # Config hot-reload
    "ConfigFileWatcher",
    "ConfigWatcherManager",
    "ConfigReloadCallback",
    "ConfigChangeEvent",
    "get_config_watcher",
    "initialize_config_watcher",
    "stop_config_watcher",
    # Sandbox
    "DockerManager",
    "SandboxConfig",
    "ExecutionResult",
    "SandboxExecutor",
    "FallbackExecutor",
    "ToolExecutionRequest",
    "SandboxExecutionContext",
    "create_executor",
    "BehaviorAnalyzer",
    "BehaviorAnalyzerPlugin",
    "BehaviorAnalysis",
    "BehaviorFinding",
    "BehaviorSeverity",
    "BehaviorCategory",
    # Plugin system
    "AntiJackExtension",
    "ExtensionViolation",
    "ExtensionMetadata",
    "ExtensionRegistry",
    "ExtensionSandbox",
    "AntiJackedExtensionMixin",
    # Version management
    "PluginVersion",
    "VersionConstraint",
    "PluginManifest",
    "VersionManager",
    "parse_version",
    "check_version_constraint",
    # 12 Detectors
    "AgentHijackingDetector",
    "BackdoorCodeDetector",
    "ExfiltrationGuard",
    "JailbreakDetector",
    "KnowledgePoisoningDetector",
    "ContextManipulationDetector",
    "OutputInjectionDetector",
    "PromptInjectionDetector",
    "SystemPromptLeakDetector",
    "CommandInjectionDetector",
    "PathTraversalDetector",
    "SQLInjectionDetector",
    # Anti-Jacked Security Base
    "IntegrityMonitor",
    "ImmutableLogChain",
    "TamperDetector",
    "AutoRecovery",
    "get_integrity_monitor",
    "get_log_chain",
    "get_tamper_detector",
    "get_auto_recovery",
    "log_event",
]
