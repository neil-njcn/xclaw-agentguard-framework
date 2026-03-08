"""
XClaw AgentGuard - Docker Sandbox Package

Provides isolated execution environment for MCP tools with:
- Docker container management
- Resource limits (CPU, memory, time)
- Behavior analysis and anomaly detection
- Security monitoring

Example:
    >>> from xclaw_agentguard.sandbox import SandboxExecutor, SandboxConfig
    >>> from xclaw_agentguard.sandbox import BehaviorAnalyzer
    
    >>> # Execute tool in sandbox
    >>> config = SandboxConfig(timeout=30, memory_limit="256m")
    >>> executor = SandboxExecutor(config)
    >>> 
    >>> request = ToolExecutionRequest(
    ...     tool_name="file_reader",
    ...     command=["cat", "/etc/passwd"]
    ... )
    >>> result = executor.execute(request)
    
    >>> # Analyze behavior
    >>> analyzer = BehaviorAnalyzer()
    >>> analysis = analyzer.analyze(request, result)
    >>> print(f"Risk score: {analysis.risk_score}")
"""

from .docker_manager import (
    DockerManager,
    SandboxConfig,
    ExecutionResult,
)

from .sandbox_executor import (
    SandboxExecutor,
    FallbackExecutor,
    ToolExecutionRequest,
    SandboxExecutionContext,
    create_executor,
)

from .behavior_analyzer import (
    BehaviorAnalyzer,
    BehaviorAnalyzerPlugin,
    BehaviorAnalysis,
    BehaviorFinding,
    BehaviorSeverity,
    BehaviorCategory,
)

__version__ = "1.0.0"

__all__ = [
    # Docker Manager
    "DockerManager",
    "SandboxConfig",
    "ExecutionResult",
    
    # Sandbox Executor
    "SandboxExecutor",
    "FallbackExecutor",
    "ToolExecutionRequest",
    "SandboxExecutionContext",
    "create_executor",
    
    # Behavior Analyzer
    "BehaviorAnalyzer",
    "BehaviorAnalyzerPlugin",
    "BehaviorAnalysis",
    "BehaviorFinding",
    "BehaviorSeverity",
    "BehaviorCategory",
]