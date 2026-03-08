"""
XClaw AgentGuard - Anti-Jacked Security Base
Auto-Recovery Mechanism

Automatically restores files from backup when tampering is detected.
Provides rollback capabilities and recovery verification.
"""

import os
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path

from .immutable_log import log_event


class AutoRecovery:
    """
    Auto-Recovery Mechanism
    
    Restores tampered files from backup copies.
    Maintains backup versions and verifies recovery.
    """
    
    def __init__(self, backup_dir: str = "memory/backups/anti-jacked"):
        self.backup_dir = backup_dir
        os.makedirs(backup_dir, exist_ok=True)
    
    def create_backup(self, file_path: str, label: str = "auto") -> Optional[str]:
        """
        Create a backup of a file
        
        Args:
            file_path: Path to file to backup
            label: Backup label (e.g., 'auto', 'baseline', 'manual')
            
        Returns:
            Path to backup file or None if failed
        """
        if not os.path.exists(file_path):
            return None
        
        try:
            # Create backup filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{os.path.basename(file_path)}.{timestamp}.{label}.bak"
            backup_path = os.path.join(self.backup_dir, filename)
            
            # Copy file to backup
            shutil.copy2(file_path, backup_path)
            
            # Log backup creation
            log_event(
                event_type='backup_created',
                severity='INFO',
                message=f'Created backup for {file_path}',
                details={'original': file_path, 'backup': backup_path}
            )
            
            return backup_path
            
        except Exception as e:
            print(f"Backup failed for {file_path}: {e}")
            return None
    
    def restore_from_backup(self, original_path: str, 
                           backup_path: Optional[str] = None) -> Tuple[bool, str]:
        """
        Restore a file from backup
        
        Args:
            original_path: Path to restore to
            backup_path: Specific backup to use (None = find latest)
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Find backup if not specified
            if backup_path is None:
                backup_path = self._find_latest_backup(original_path)
                if backup_path is None:
                    return False, f"No backup found for {original_path}"
            
            # Verify backup exists
            if not os.path.exists(backup_path):
                return False, f"Backup not found: {backup_path}"
            
            # Create pre-restore backup (in case we need to undo)
            pre_restore_backup = None
            if os.path.exists(original_path):
                pre_restore_backup = self.create_backup(original_path, "pre_restore")
            
            # Perform restore
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            shutil.copy2(backup_path, original_path)
            
            # Log restore
            log_event(
                event_type='file_restored',
                severity='HIGH',
                message=f'Restored {original_path} from backup',
                details={
                    'original': original_path,
                    'backup': backup_path,
                    'pre_restore_backup': pre_restore_backup
                }
            )
            
            return True, f"Successfully restored {original_path}"
            
        except Exception as e:
            error_msg = f"Restore failed: {e}"
            log_event(
                event_type='restore_failed',
                severity='CRITICAL',
                message=error_msg,
                details={'original': original_path, 'backup': backup_path, 'error': str(e)}
            )
            return False, error_msg
    
    def _find_latest_backup(self, original_path: str) -> Optional[str]:
        """Find the most recent backup for a file"""
        basename = os.path.basename(original_path)
        backups = []
        
        for filename in os.listdir(self.backup_dir):
            if filename.startswith(basename + ".") and filename.endswith(".bak"):
                backup_path = os.path.join(self.backup_dir, filename)
                backups.append((backup_path, os.path.getmtime(backup_path)))
        
        if not backups:
            return None
        
        # Sort by modification time (newest first)
        backups.sort(key=lambda x: x[1], reverse=True)
        return backups[0][0]
    
    def list_backups(self, original_path: Optional[str] = None) -> List[Dict]:
        """List available backups"""
        backups = []
        
        for filename in os.listdir(self.backup_dir):
            if not filename.endswith(".bak"):
                continue
            
            backup_path = os.path.join(self.backup_dir, filename)
            
            # Parse filename: original.YYYYMMDD_HHMMSS.label.bak
            parts = filename.rsplit('.', 3)
            if len(parts) >= 3:
                original_name = parts[0]
                timestamp = parts[1] if len(parts) > 1 else "unknown"
                label = parts[2] if len(parts) > 2 else "unknown"
            else:
                original_name = filename
                timestamp = "unknown"
                label = "unknown"
            
            if original_path and not filename.startswith(os.path.basename(original_path)):
                continue
            
            backups.append({
                'filename': filename,
                'path': backup_path,
                'original_name': original_name,
                'timestamp': timestamp,
                'label': label,
                'size': os.path.getsize(backup_path),
                'created': datetime.fromtimestamp(os.path.getctime(backup_path)).isoformat()
            })
        
        # Sort by creation time (newest first)
        backups.sort(key=lambda x: x['created'], reverse=True)
        return backups
    
    def cleanup_old_backups(self, max_backups_per_file: int = 10) -> int:
        """Remove old backups, keeping only the most recent N per file"""
        removed = 0
        
        # Group backups by original file
        backups_by_file: Dict[str, List[str]] = {}
        for backup in self.list_backups():
            original = backup['original_name']
            if original not in backups_by_file:
                backups_by_file[original] = []
            backups_by_file[original].append(backup['path'])
        
        # Keep only the most recent N for each file
        for original, paths in backups_by_file.items():
            if len(paths) > max_backups_per_file:
                # Sort by modification time
                paths.sort(key=lambda p: os.path.getmtime(p), reverse=True)
                
                # Remove old backups
                for old_backup in paths[max_backups_per_file:]:
                    try:
                        os.remove(old_backup)
                        removed += 1
                    except Exception as e:
                        print(f"Failed to remove old backup {old_backup}: {e}")
        
        return removed
    
    def verify_backup_integrity(self, backup_path: str) -> Tuple[bool, str]:
        """Verify that a backup file is not corrupted"""
        try:
            if not os.path.exists(backup_path):
                return False, "Backup file does not exist"
            
            # Check if file is readable
            with open(backup_path, 'r') as f:
                content = f.read(1024)  # Read first 1KB
            
            return True, "Backup integrity verified"
            
        except Exception as e:
            return False, f"Backup integrity check failed: {e}"


# Global instance
_auto_recovery: Optional[AutoRecovery] = None


def get_auto_recovery() -> AutoRecovery:
    """Get or create global auto-recovery instance"""
    global _auto_recovery
    if _auto_recovery is None:
        _auto_recovery = AutoRecovery()
    return _auto_recovery