"""
CLI Commands for Anti-Jacked Security Base

Integrates with xclaw_agentguard CLI to provide:
- integrity-check: Check file integrity
- baseline-generate: Generate integrity baseline
- integrity-status: Show monitoring status
- restore: Restore files from backup
"""

import click
from pathlib import Path
from xclaw_agentguard.anti_jacked import (
    get_integrity_monitor,
    get_tamper_detector,
    get_auto_recovery,
    get_log_chain
)


@click.group(name='anti-jacked')
def anti_jacked_cli():
    """Anti-Jacked security commands for file integrity protection"""
    pass


@anti_jacked_cli.command(name='integrity-check')
@click.option('--file', '-f', help='Check specific file')
@click.option('--all', '-a', is_flag=True, help='Check all watched files')
@click.option('--json', is_flag=True, help='Output as JSON')
def integrity_check(file, all, json):
    """Check file integrity against baseline"""
    monitor = get_integrity_monitor()
    
    if file:
        result = monitor.check_integrity(file)
    else:
        result = monitor.check_integrity()
    
    if json:
        import json as json_lib
        click.echo(json_lib.dumps(result, indent=2))
    else:
        click.echo("\n🔍 Integrity Check Results")
        click.echo("=" * 60)
        click.echo(f"Checked at: {result['checked_at']}")
        click.echo(f"Verified: {len(result['verified'])} files ✅")
        click.echo(f"Modified: {len(result['modified'])} files ⚠️")
        click.echo(f"Missing: {len(result['missing'])} files ❌")
        click.echo(f"Errors: {len(result['errors'])} files ⚡")
        
        if result['modified']:
            click.echo("\n⚠️ Modified Files (Potential Tampering):")
            for mod in result['modified']:
                click.echo(f"  - {mod['path']}")
        
        if result['missing']:
            click.echo("\n❌ Missing Files:")
            for miss in result['missing']:
                click.echo(f"  - {miss['path']}")


@anti_jacked_cli.command(name='baseline-generate')
@click.argument('directories', nargs=-1, required=True)
@click.option('--output', '-o', default='memory/genomes/anti-jacked-baseline.json',
              help='Output path for baseline')
def baseline_generate(directories, output):
    """Generate integrity baseline from directories"""
    monitor = get_integrity_monitor()
    monitor.baseline_path = output
    
    click.echo(f"\n📊 Generating integrity baseline...")
    click.echo(f"Directories: {', '.join(directories)}")
    
    result = monitor.generate_baseline(list(directories))
    
    click.echo(f"\n✅ Baseline generated!")
    click.echo(f"Files: {result['total_files']}")
    click.echo(f"Output: {result['baseline_path']}")


@anti_jacked_cli.command(name='integrity-status')
def integrity_status():
    """Show file integrity monitoring status"""
    monitor = get_integrity_monitor()
    status = monitor.get_status()
    
    click.echo("\n🔐 Anti-Jacked Integrity Status")
    click.echo("=" * 60)
    click.echo(f"Baseline loaded: {'✅ Yes' if status['baseline_loaded'] else '❌ No'}")
    click.echo(f"Watched files: {status['watched_files']}")
    click.echo(f"Monitoring active: {'🔄 Yes' if status['monitoring_active'] else '⏸️ No'}")
    click.echo(f"Check interval: {status['check_interval']} seconds")
    click.echo(f"Baseline path: {status['baseline_path']}")


@anti_jacked_cli.command(name='restore')
@click.argument('file_path')
@click.option('--backup', '-b', help='Specific backup to restore from')
@click.option('--latest', '-l', is_flag=True, help='Use latest backup')
def restore_file(file_path, backup, latest):
    """Restore a file from backup"""
    recovery = get_auto_recovery()
    
    if not backup and latest:
        backup = recovery._find_latest_backup(file_path)
        if not backup:
            click.echo(f"❌ No backup found for {file_path}")
            return
    
    click.echo(f"\n🔄 Restoring {file_path}...")
    if backup:
        click.echo(f"From backup: {backup}")
    
    success, message = recovery.restore_from_backup(file_path, backup)
    
    if success:
        click.echo(f"✅ {message}")
    else:
        click.echo(f"❌ {message}")


@anti_jacked_cli.command(name='backups')
@click.argument('file_path', required=False)
def list_backups(file_path):
    """List available backups"""
    recovery = get_auto_recovery()
    backups = recovery.list_backups(file_path)
    
    if not backups:
        click.echo("No backups found.")
        return
    
    click.echo(f"\n📦 Backups ({len(backups)} total):")
    click.echo("-" * 80)
    
    for i, backup in enumerate(backups[:20], 1):  # Show first 20
        click.echo(f"{i}. {backup['filename']}")
        click.echo(f"   Size: {backup['size']} bytes")
        click.echo(f"   Created: {backup['created']}")
        click.echo(f"   Label: {backup['label']}")
        click.echo()


@anti_jacked_cli.command(name='logs')
@click.option('--count', '-n', default=20, help='Number of entries to show')
@click.option('--severity', '-s', help='Filter by severity')
def show_logs(count, severity):
    """Show immutable audit logs"""
    log_chain = get_log_chain()
    entries = log_chain.get_entries(count=count, severity=severity)
    
    click.echo(f"\n📜 Audit Log (last {len(entries)} entries)")
    click.echo("=" * 80)
    
    for entry in entries:
        severity_emoji = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MEDIUM': '⚡',
            'LOW': 'ℹ️',
            'INFO': '•'
        }.get(entry.severity, '•')
        
        click.echo(f"{severity_emoji} [{entry.severity}] {entry.event_type}")
        click.echo(f"   Time: {entry.timestamp}")
        click.echo(f"   Seq: {entry.sequence}")
        click.echo(f"   Message: {entry.message}")
        if entry.details:
            click.echo(f"   Details: {entry.details}")
        click.echo(f"   Hash: {entry.entry_hash[:16]}...")
        click.echo()


@anti_jacked_cli.command(name='verify-logs')
def verify_logs():
    """Verify immutable log chain integrity"""
    log_chain = get_log_chain()
    result = log_chain.verify_chain()
    
    click.echo("\n🔐 Log Chain Verification")
    click.echo("=" * 60)
    
    if result['valid']:
        click.echo("✅ Log chain integrity verified")
        click.echo(f"   Total entries: {result['entries_count']}")
        click.echo("   Chain is intact and tamper-evident")
    else:
        click.echo("❌ Log chain verification FAILED")
        click.echo(f"   Error: {result['error']}")
        click.echo(f"   Broken at entry: {result['broken_at']}")
        click.echo(f"   Entries checked: {result['entries_count']}")


# Export the CLI group
__all__ = ['anti_jacked_cli']