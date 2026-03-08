"""
Sandbox Executor - XClaw AgentGuard

Executes MCP tools in isolated Docker containers with resource limits
and comprehensive output capture.
"""

import os
import time
import json
import logging
import tempfile
import threading
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Union, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from .docker_manager import DockerManager, SandboxConfig, ExecutionResult

logger = logging.getLogger(__name__)


@dataclass
class ToolExecutionRequest:
    """Request to execute a tool in sandbox"""
    tool_name: str
    command: List[str]
    working_dir: str = "/sandbox"
    environment: Dict[str, str] = field(default_factory=dict)
    input_data: Optional[str] = None
    files_to_mount: Dict[str, str] = field(default_factory=dict)  # host_path -> container_path
    timeout: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "command": self.command,
            "working_dir": self.working_dir,
            "environment": self.environment,
            "input_data": self.input_data,
            "files_to_mount": self.files_to_mount,
            "timeout": self.timeout,
        }


@dataclass
class SandboxExecutionContext:
    """Context for sandbox execution"""
    container_id: str
    start_time: datetime
    temp_dir: Optional[str] = None
    mounted_files: List[str] = field(default_factory=list)
    
    def cleanup(self, docker_manager: DockerManager) -> None:
        """Cleanup resources"""
        try:
            if self.temp_dir and os.path.exists(self.temp_dir):
                import shutil
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            
            docker_manager.cleanup_container(self.container_id)
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")


class SandboxExecutor:
    """
    Executes tools in sandboxed Docker containers
    
    Provides:
    - Isolated execution environment
    - Resource limits (CPU, memory, time)
    - stdout/stderr capture
    - File system isolation
    - Input/output data handling
    """
    
    def __init__(
        self,
        config: Optional[SandboxConfig] = None,
        docker_manager: Optional[DockerManager] = None
    ):
        """
        Initialize sandbox executor
        
        Args:
            config: Sandbox configuration
            docker_manager: Docker manager instance (creates new if None)
        """
        self.config = config or SandboxConfig()
        self.docker = docker_manager or DockerManager(self.config)
        self._active_executions: Dict[str, SandboxExecutionContext] = {}
        self._lock = threading.Lock()
    
    @property
    def is_available(self) -> bool:
        """Check if sandbox execution is available"""
        return self.docker.is_available
    
    def _prepare_volumes(
        self,
        request: ToolExecutionRequest
    ) -> Tuple[Dict[str, Dict[str, str]], str]:
        """
        Prepare volume mounts for container
        
        Returns:
            (volumes_dict, temp_dir_path)
        """
        volumes = {}
        temp_dir = None
        
        # Create temp directory for input/output if needed
        if request.input_data or request.files_to_mount:
            temp_dir = tempfile.mkdtemp(prefix="xclaw_sandbox_")
            
            # Write input data to file if provided
            if request.input_data:
                input_file = Path(temp_dir) / "input.txt"
                input_file.write_text(request.input_data)
                volumes[str(input_file)] = {
                    'bind': '/sandbox/input.txt',
                    'mode': 'ro'
                }
            
            # Mount specified files
            for host_path, container_path in request.files_to_mount.items():
                if os.path.exists(host_path):
                    volumes[host_path] = {
                        'bind': container_path,
                        'mode': 'ro'
                    }
            
            # Mount temp dir for output
            volumes[temp_dir] = {
                'bind': '/sandbox/output',
                'mode': 'rw'
            }
        
        return volumes, temp_dir
    
    def _build_command(self, request: ToolExecutionRequest) -> str:
        """Build the command string for container execution"""
        # Escape the command parts
        escaped_parts = []
        for part in request.command:
            # Simple escaping for shell
            if any(c in part for c in [' ', '"', "'", '$', '`', '\\']):
                escaped = part.replace("'", "'\"'\"'")
                escaped_parts.append(f"'{escaped}'")
            else:
                escaped_parts.append(part)
        
        command_str = ' '.join(escaped_parts)
        
        # Add input redirection if input file exists
        if request.input_data:
            command_str = f"cat /sandbox/input.txt | {command_str}"
        
        return command_str
    
    def execute(
        self,
        request: ToolExecutionRequest,
        capture_behavior: bool = True
    ) -> ExecutionResult:
        """
        Execute a tool in sandbox
        
        Args:
            request: Tool execution request
            capture_behavior: Whether to capture behavior metrics
            
        Returns:
            ExecutionResult with output, exit code, and metrics
        """
        if not self.is_available:
            return ExecutionResult(
                command=' '.join(request.command),
                exit_code=-1,
                stdout="",
                stderr="Docker not available",
                duration_ms=0,
                error_message="Docker sandbox not available"
            )
        
        timeout = request.timeout or self.config.timeout
        start_time = time.time()
        container = None
        temp_dir = None
        
        try:
            # Prepare volumes
            volumes, temp_dir = self._prepare_volumes(request)
            
            # Build command
            command = self._build_command(request)
            
            # Create container
            container = self.docker.create_container(
                command=command,
                volumes=volumes,
                environment=request.environment,
                working_dir=request.working_dir
            )
            
            if not container:
                return ExecutionResult(
                    command=command,
                    exit_code=-1,
                    stdout="",
                    stderr="Failed to create container",
                    duration_ms=(time.time() - start_time) * 1000,
                    error_message="Container creation failed"
                )
            
            # Track active execution
            context = SandboxExecutionContext(
                container_id=container.id,
                start_time=datetime.now(),
                temp_dir=temp_dir,
                mounted_files=list(request.files_to_mount.keys())
            )
            
            with self._lock:
                self._active_executions[container.id] = context
            
            # Start container
            if not self.docker.start_container(container):
                return ExecutionResult(
                    command=command,
                    exit_code=-1,
                    stdout="",
                    stderr="Failed to start container",
                    duration_ms=(time.time() - start_time) * 1000,
                    container_id=container.id,
                    error_message="Container start failed"
                )
            
            # Wait for completion with timeout
            try:
                result = container.wait(timeout=timeout)
                exit_code = result.get('StatusCode', -1)
                timed_out = False
            except Exception as e:
                # Timeout or error
                exit_code = -1
                timed_out = "timeout" in str(e).lower()
                
                # Kill container
                try:
                    container.kill()
                except Exception:
                    pass
            
            # Get logs
            try:
                stdout = container.logs(stdout=True, stderr=False).decode('utf-8', errors='replace')
                stderr = container.logs(stdout=False, stderr=True).decode('utf-8', errors='replace')
            except Exception as e:
                stdout = ""
                stderr = f"Failed to retrieve logs: {e}"
            
            # Get resource stats if behavior capture enabled
            memory_peak = 0.0
            cpu_usage = 0.0
            
            if capture_behavior:
                try:
                    stats = self.docker.get_container_stats(container)
                    memory_peak = stats.get('memory_usage_bytes', 0) / (1024 * 1024)  # Convert to MB
                    cpu_usage = stats.get('memory_usage_percent', 0)
                except Exception as e:
                    logger.debug(f"Failed to get container stats: {e}")
            
            duration_ms = (time.time() - start_time) * 1000
            
            return ExecutionResult(
                command=command,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                container_id=container.id,
                memory_peak_mb=memory_peak,
                cpu_usage_percent=cpu_usage,
                timed_out=timed_out,
                killed=timed_out
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(f"Sandbox execution error: {e}")
            
            return ExecutionResult(
                command=' '.join(request.command),
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration_ms=duration_ms,
                container_id=container.id if container else None,
                error_message=f"Execution error: {e}"
            )
        
        finally:
            # Cleanup
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
                
                with self._lock:
                    self._active_executions.pop(container.id, None)
            
            if temp_dir and os.path.exists(temp_dir):
                try:
                    import shutil
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except Exception:
                    pass
    
    def execute_sync(
        self,
        tool_name: str,
        command: List[str],
        input_data: Optional[str] = None,
        timeout: Optional[int] = None,
        environment: Optional[Dict[str, str]] = None
    ) -> ExecutionResult:
        """
        Simplified synchronous execution
        
        Args:
            tool_name: Name of the tool
            command: Command and arguments
            input_data: Optional input data
            timeout: Timeout in seconds
            environment: Environment variables
            
        Returns:
            ExecutionResult
        """
        request = ToolExecutionRequest(
            tool_name=tool_name,
            command=command,
            input_data=input_data,
            timeout=timeout,
            environment=environment or {}
        )
        return self.execute(request)
    
    def execute_mcp_tool(
        self,
        tool_name: str,
        params: Dict[str, Any],
        timeout: Optional[int] = None
    ) -> ExecutionResult:
        """
        Execute an MCP tool in sandbox
        
        Args:
            tool_name: MCP tool name
            params: Tool parameters (will be passed as JSON)
            timeout: Timeout in seconds
            
        Returns:
            ExecutionResult
        """
        # Build MCP tool command
        command = ["python", "-m", "mcp.tool", tool_name]
        
        # Serialize params to JSON
        input_data = json.dumps(params, indent=2)
        
        return self.execute_sync(
            tool_name=tool_name,
            command=command,
            input_data=input_data,
            timeout=timeout
        )
    
    def get_active_executions(self) -> List[Dict[str, Any]]:
        """Get list of currently active executions"""
        with self._lock:
            return [
                {
                    "container_id": ctx.container_id,
                    "start_time": ctx.start_time.isoformat(),
                    "duration_seconds": (datetime.now() - ctx.start_time).total_seconds(),
                }
                for ctx in self._active_executions.values()
            ]
    
    def kill_execution(self, container_id: str) -> bool:
        """Kill a running execution"""
        with self._lock:
            context = self._active_executions.get(container_id)
        
        if context:
            return self.docker.stop_container(container_id, timeout=0)
        return False
    
    def cleanup_all(self) -> int:
        """Cleanup all active executions"""
        with self._lock:
            contexts = list(self._active_executions.values())
        
        count = 0
        for context in contexts:
            try:
                context.cleanup(self.docker)
                count += 1
            except Exception as e:
                logger.error(f"Error cleaning up execution: {e}")
        
        with self._lock:
            self._active_executions.clear()
        
        return count


class FallbackExecutor:
    """
    Fallback executor using subprocess (no isolation)
    
    Used when Docker is not available. Provides limited sandboxing
    through subprocess timeouts.
    """
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
    
    def execute(
        self,
        request: ToolExecutionRequest
    ) -> ExecutionResult:
        """Execute using subprocess"""
        start_time = time.time()
        
        try:
            result = subprocess.run(
                request.command,
                input=request.input_data,
                capture_output=True,
                text=True,
                timeout=request.timeout or self.timeout,
                env={**os.environ, **request.environment}
            )
            
            duration_ms = (time.time() - start_time) * 1000
            
            return ExecutionResult(
                command=' '.join(request.command),
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                duration_ms=duration_ms,
                timed_out=False
            )
            
        except subprocess.TimeoutExpired:
            duration_ms = (time.time() - start_time) * 1000
            return ExecutionResult(
                command=' '.join(request.command),
                exit_code=-1,
                stdout="",
                stderr="Execution timed out",
                duration_ms=duration_ms,
                timed_out=True,
                error_message="Timeout"
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return ExecutionResult(
                command=' '.join(request.command),
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration_ms=duration_ms,
                error_message=str(e)
            )


def create_executor(
    use_docker: bool = True,
    config: Optional[SandboxConfig] = None
) -> Union[SandboxExecutor, FallbackExecutor]:
    """
    Create appropriate executor
    
    Args:
        use_docker: Try Docker first
        config: Sandbox configuration
        
    Returns:
        SandboxExecutor or FallbackExecutor
    """
    if use_docker:
        executor = SandboxExecutor(config)
        if executor.is_available:
            return executor
        logger.warning("Docker not available, falling back to subprocess")
    
    return FallbackExecutor(config.timeout if config else 30)


__all__ = [
    "SandboxExecutor",
    "FallbackExecutor",
    "ToolExecutionRequest",
    "SandboxExecutionContext",
    "create_executor",
]