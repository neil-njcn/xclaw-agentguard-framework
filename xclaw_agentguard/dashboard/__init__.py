"""XClaw AgentGuard Web Dashboard

A minimal web dashboard for monitoring and controlling the AgentGuard security system.
"""

from .server import create_app, run_server
from .api import api_bp

__all__ = ["create_app", "run_server", "api_bp"]
