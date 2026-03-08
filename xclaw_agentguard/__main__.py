"""
Entry point for running xclaw_agentguard as a module.

Usage:
    python -m xclaw_agentguard [command] [options]
    
Examples:
    python -m xclaw_agentguard status
    python -m xclaw_agentguard detect --text "suspicious content"
    python -m xclaw_agentguard --json status
"""

from .cli import main

if __name__ == '__main__':
    main()
