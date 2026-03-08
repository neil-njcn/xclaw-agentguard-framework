"""
Docker Sandbox - XClaw AgentGuard

Secure containerized execution environment for MCP tools.
Provides isolated execution, resource limits, and behavior monitoring.
"""

import os
import json
import time
import logging
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime

# Docker SDK
try:
    import docker
    from docker.errors import DockerException, NotFound, ContainerError
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    docker = None

logger = logging.getLogger(__name__)


@dataclass
class SandboxConfig:
    """Docker sandbox configuration"""
    # Container settings
    image: str = "xclaw-sandbox:latest"
    timeout: int = 30  # seconds
    
    # Resource limits
    cpu_limit: float = 1.0  # CPU cores
    memory_limit: str = "512m"  # memory limit
    memory_swap: str = "512m"  # swap limit
    
    # Network settings
    network_mode: str = "none"  # 'none', 'bridge', 'host'
    
    # Volume settings
    read_only: bool = True  # make root filesystem read-only
    tmpfs_size: str = "100m"  # tmpfs size for /tmp
    
    # Security settings
    cap_drop: List[str] = field(default_factory=lambda: ["ALL"])
    cap_add: List[str] = field(default_factory=list)
    no_new_privs: bool = True
    security_opt: List[str] = field(default_factory=list)
    
    # Logging
    log_driver: str = "json-file"
    log_max_size: str = "10m"
    log_max_files: int = 3


@dataclass
class ExecutionResult:
    """Result of sandboxed execution"""
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    container_id: Optional[str] = None
    
    # Resource usage
    memory_peak_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    
    # Status
    timed_out: bool = False
    killed: bool = False
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "container_id": self.container_id,
            "memory_peak_mb": self.memory_peak_mb,
            "cpu_usage_percent": self.cpu_usage_percent,
            "timed_out": self.timed_out,
            "killed": self.killed,
            "error_message": self.error_message,
        }


class DockerManager:
    """
    Manages Docker containers for sandboxed execution
    
    Handles container lifecycle, image building, and resource management.
    """
    
    # Default Dockerfile for sandbox image
    DEFAULT_DOCKERFILE = '''
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r sandbox && useradd -r -g sandbox sandbox

# Install minimal dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \\
    ca-certificates \\
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /sandbox
RUN chown sandbox:sandbox /sandbox

# Switch to non-root user
USER sandbox

# Default entrypoint
ENTRYPOINT ["/bin/bash", "-c"]
CMD ["echo 'XClaw Sandbox Ready'"]
'''
    
    def __init__(self, config: Optional[SandboxConfig] = None):
        """
        Initialize Docker manager
        
        Args:
            config: Sandbox configuration
        """
        self.config = config or SandboxConfig()
        self._client: Optional[Any] = None
        self._initialized = False
        
        if not DOCKER_AVAILABLE:
            logger.warning("Docker SDK not available. Install with: pip install docker")
            return
        
        try:
            self._client = docker.from_env()
            self._initialized = True
            logger.info("Docker manager initialized successfully")
        except DockerException as e:
            logger.error(f"Failed to connect to Docker: {e}")
    
    @property
    def is_available(self) -> bool:
        """Check if Docker is available and connected"""
        if not self._initialized or not self._client:
            return False
        try:
            self._client.ping()
            return True
        except Exception:
            return False
    
    def build_sandbox_image(
        self,
        dockerfile: Optional[str] = None,
        tag: Optional[str] = None,
        build_args: Optional[Dict[str, str]] = None
    ) -> bool:
        """
        Build the sandbox Docker image
        
        Args:
            dockerfile: Custom Dockerfile content (uses default if None)
            tag: Image tag (uses config.image if None)
            build_args: Build arguments
            
        Returns:
            True if build succeeded
        """
        if not self.is_available:
            logger.error("Docker not available")
            return False
        
        image_tag = tag or self.config.image
        dockerfile_content = dockerfile or self.DEFAULT_DOCKERFILE
        
        # Create temporary build context
        build_dir = tempfile.mkdtemp(prefix="xclaw_sandbox_build_")
        
        try:
            # Write Dockerfile
            dockerfile_path = Path(build_dir) / "Dockerfile"
            dockerfile_path.write_text(dockerfile_content)
            
            logger.info(f"Building sandbox image: {image_tag}")
            
            # Build image
            image, build_logs = self._client.images.build(
                path=build_dir,
                tag=image_tag,
                buildargs=build_args or {},
                rm=True,
                forcerm=True
            )
            
            # Log build output
            for log in build_logs:
                if 'stream' in log:
                    logger.debug(log['stream'].strip())
            
            logger.info(f"Successfully built sandbox image: {image_tag}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to build sandbox image: {e}")
            return False
        finally:
            shutil.rmtree(build_dir, ignore_errors=True)
    
    def ensure_image_exists(self, pull_if_missing: bool = False) -> bool:
        """
        Ensure the sandbox image exists
        
        Args:
            pull_if_missing: Try to pull image if not found locally
            
        Returns:
            True if image exists or was pulled/built successfully
        """
        if not self.is_available:
            return False
        
        try:
            self._client.images.get(self.config.image)
            return True
        except NotFound:
            if pull_if_missing:
                try:
                    logger.info(f"Pulling image: {self.config.image}")
                    self._client.images.pull(self.config.image)
                    return True
                except Exception as e:
                    logger.error(f"Failed to pull image: {e}")
            
            # Try to build default image
            logger.info("Building default sandbox image...")
            return self.build_sandbox_image()
        except Exception as e:
            logger.error(f"Error checking image: {e}")
            return False
    
    def create_container(
        self,
        command: str,
        volumes: Optional[Dict[str, Dict[str, str]]] = None,
        environment: Optional[Dict[str, str]] = None,
        working_dir: str = "/sandbox"
    ) -> Optional[Any]:
        """
        Create a new container (does not start it)
        
        Args:
            command: Command to execute
            volumes: Volume mounts {host_path: {'bind': container_path, 'mode': 'ro'}}
            environment: Environment variables
            working_dir: Working directory in container
            
        Returns:
            Container object or None
        """
        if not self.is_available:
            logger.error("Docker not available")
            return None
        
        if not self.ensure_image_exists():
            logger.error("Sandbox image not available")
            return None
        
        try:
            container = self._client.containers.create(
                image=self.config.image,
                command=command,
                volumes=volumes or {},
                environment=environment or {},
                working_dir=working_dir,
                network_mode=self.config.network_mode,
                mem_limit=self.config.memory_limit,
                memswap_limit=self.config.memory_swap,
                cpu_quota=int(self.config.cpu_limit * 100000),  # Convert to microseconds
                cpu_period=100000,
                read_only=self.config.read_only,
                cap_drop=self.config.cap_drop,
                cap_add=self.config.cap_add,
                security_opt=self.config.security_opt,
                tmpfs={
                    '/tmp': f'noexec,nosuid,size={self.config.tmpfs_size}',
                    '/var/tmp': f'noexec,nosuid,size={self.config.tmpfs_size}'
                },
                detach=True,
                stdin_open=False,
                tty=False,
            )
            
            return container
            
        except Exception as e:
            logger.error(f"Failed to create container: {e}")
            return None
    
    def start_container(self, container: Any) -> bool:
        """Start a created container"""
        try:
            container.start()
            return True
        except Exception as e:
            logger.error(f"Failed to start container: {e}")
            return False
    
    def stop_container(
        self,
        container: Any,
        timeout: Optional[int] = None
    ) -> bool:
        """
        Stop a running container
        
        Args:
            container: Container object or ID
            timeout: Seconds to wait before force kill
            
        Returns:
            True if stopped successfully
        """
        try:
            if isinstance(container, str):
                container = self._client.containers.get(container)
            
            timeout = timeout or self.config.timeout
            container.stop(timeout=timeout)
            return True
            
        except NotFound:
            logger.warning(f"Container not found: {container}")
            return True  # Already gone
        except Exception as e:
            logger.error(f"Failed to stop container: {e}")
            return False
    
    def remove_container(
        self,
        container: Any,
        force: bool = True
    ) -> bool:
        """
        Remove a container
        
        Args:
            container: Container object or ID
            force: Force remove even if running
            
        Returns:
            True if removed successfully
        """
        try:
            if isinstance(container, str):
                container = self._client.containers.get(container)
            
            container.remove(force=force)
            return True
            
        except NotFound:
            return True  # Already removed
        except Exception as e:
            logger.error(f"Failed to remove container: {e}")
            return False
    
    def cleanup_container(self, container: Any) -> bool:
        """Stop and remove a container"""
        self.stop_container(container)
        return self.remove_container(container)
    
    def get_container_stats(self, container: Any) -> Dict[str, Any]:
        """
        Get container resource usage statistics
        
        Returns:
            Dict with memory, CPU usage
        """
        try:
            if isinstance(container, str):
                container = self._client.containers.get(container)
            
            stats = container.stats(stream=False)
            
            # Parse memory usage
            memory_stats = stats.get('memory_stats', {})
            memory_usage = memory_stats.get('usage', 0)
            memory_limit = memory_stats.get('limit', 1)
            
            # Parse CPU usage
            cpu_stats = stats.get('cpu_stats', {})
            cpu_usage = cpu_stats.get('cpu_usage', {}).get('total_usage', 0)
            
            return {
                'memory_usage_bytes': memory_usage,
                'memory_limit_bytes': memory_limit,
                'memory_usage_percent': (memory_usage / memory_limit * 100) if memory_limit > 0 else 0,
                'cpu_total_usage': cpu_usage,
                'pids': stats.get('pids_stats', {}).get('current', 0),
            }
            
        except Exception as e:
            logger.error(f"Failed to get container stats: {e}")
            return {}
    
    def list_containers(
        self,
        all_containers: bool = False,
        filters: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        """List containers"""
        if not self.is_available:
            return []
        
        try:
            containers = self._client.containers.list(
                all=all_containers,
                filters=filters or {}
            )
            
            return [
                {
                    'id': c.id[:12],
                    'name': c.name,
                    'image': c.image.tags[0] if c.image.tags else 'unknown',
                    'status': c.status,
                    'created': c.attrs.get('Created'),
                }
                for c in containers
            ]
            
        except Exception as e:
            logger.error(f"Failed to list containers: {e}")
            return []
    
    def cleanup_all_sandboxes(self, force: bool = False) -> int:
        """
        Cleanup all sandbox containers
        
        Args:
            force: Force remove running containers
            
        Returns:
            Number of containers removed
        """
        if not self.is_available:
            return 0
        
        count = 0
        try:
            containers = self._client.containers.list(
                all=True,
                filters={'ancestor': self.config.image}
            )
            
            for container in containers:
                try:
                    if force and container.status == 'running':
                        container.kill()
                    container.remove(force=True)
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed to remove container {container.id[:12]}: {e}")
            
            logger.info(f"Cleaned up {count} sandbox containers")
            return count
            
        except Exception as e:
            logger.error(f"Failed to cleanup containers: {e}")
            return count


__all__ = [
    "DockerManager",
    "SandboxConfig",
    "ExecutionResult",
]