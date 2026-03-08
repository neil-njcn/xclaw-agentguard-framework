"""CLI for XClaw AgentGuard Framework

Available commands:
    baseline-generate    Generate file integrity baseline
    integrity-check      Check file integrity against baseline
    security-status      Show framework security status

    engine-start         Start helper daemon (optional)
    engine-stop          Stop helper daemon
    engine-status        Check helper daemon status
"""

import sys
import argparse
from typing import Optional, List


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xclaw-agentguard",
        description="XClaw AgentGuard - AI Agent Security Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Framework commands:
  xclaw-agentguard baseline-generate    # Generate integrity baseline
  xclaw-agentguard integrity-check      # Check file integrity
  xclaw-agentguard security-status      # Show security status

Helper daemon (optional):
  xclaw-agentguard engine-start         # Requires [engine] extra
  xclaw-agentguard engine-stop
  xclaw-agentguard engine-status

Python Usage:
  # Framework mode (always works)
  from xclaw_agentguard import PromptInjectionDetector
  
  # Engine mode (optional)
  from xclaw_agentguard.engine import start_engine_daemon
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Framework commands
    subparsers.add_parser("baseline-generate", help="Generate integrity baseline")
    subparsers.add_parser("integrity-check", help="Check file integrity")
    subparsers.add_parser("security-status", help="Show security status")
    
    # Engine commands
    engine_start = subparsers.add_parser("engine-start", help="Start protection engine (optional)")
    engine_start.add_argument("--daemon", action="store_true", help="Run as daemon")
    
    subparsers.add_parser("engine-stop", help="Stop protection engine")
    subparsers.add_parser("engine-status", help="Show engine status")
    
    return parser


def cmd_baseline_generate(args) -> int:
    from .anti_jacked import get_integrity_monitor
    monitor = get_integrity_monitor()
    result = monitor.generate_baseline(["xclaw_agentguard/core"])
    print(f"✅ Baseline generated: {result['total_files']} files")
    return 0


def cmd_integrity_check(args) -> int:
    from .anti_jacked import get_integrity_monitor
    monitor = get_integrity_monitor()
    result = monitor.check_integrity()
    print(f"✓ Verified: {len(result['verified'])} files")
    print(f"⚠ Modified: {len(result['modified'])} files")
    return 0


def cmd_security_status(args) -> int:
    from .anti_jacked import get_integrity_monitor
    monitor = get_integrity_monitor()
    status = monitor.get_status()
    print("\n=== XClaw AgentGuard Status ===")
    print(f"Monitoring: {'Active' if status['monitoring_active'] else 'Inactive'}")
    print(f"Watched files: {status['watched_files']}")
    return 0


def cmd_engine_start(args) -> int:
    print("🚀 Starting protection engine...")
    print("   (Requires: pip install xclaw-agentguard[engine])")
    
    try:
        from .engine import start_engine_daemon, EngineConfig
        config = EngineConfig(daemon_mode=args.daemon)
        start_engine_daemon(config)
        return 0
    except ImportError as e:
        print(f"❌ Engine not available: {e}")
        print("   Install with: pip install xclaw-agentguard[engine]")
        return 1


def cmd_engine_stop(args) -> int:
    import os
    import signal
    
    pid_file = "/tmp/xclaw_agentguard.pid"
    if not os.path.exists(pid_file):
        print("⚠️  Engine not running")
        return 1
    
    with open(pid_file) as f:
        pid = int(f.read().strip())
    
    os.kill(pid, signal.SIGTERM)
    print("✅ Engine stopped")
    return 0


def cmd_engine_status(args) -> int:
    import os
    
    pid_file = "/tmp/xclaw_agentguard.pid"
    if os.path.exists(pid_file):
        try:
            with open(pid_file) as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            print(f"✅ Engine running (PID: {pid})")
            return 0
        except:
            pass
    
    print("⚠️  Engine not running")
    return 1


def main(args: Optional[List[str]] = None) -> int:
    parser = create_parser()
    parsed = parser.parse_args(args)
    
    if not parsed.command:
        parser.print_help()
        return 0
    
    commands = {
        "baseline-generate": cmd_baseline_generate,
        "integrity-check": cmd_integrity_check,
        "security-status": cmd_security_status,
        "engine-start": cmd_engine_start,
        "engine-stop": cmd_engine_stop,
        "engine-status": cmd_engine_status,
    }
    
    handler = commands.get(parsed.command)
    if handler:
        return handler(parsed)
    else:
        print(f"Unknown: {parsed.command}")
        return 1


if __name__ == "__main__":
    sys.exit(main())