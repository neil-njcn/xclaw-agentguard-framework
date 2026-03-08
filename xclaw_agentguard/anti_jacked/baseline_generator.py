"""Baseline Generator for Anti-Jacked Security System

Generates cryptographic baselines of critical files for integrity monitoring.
Uses SHA256 hashing with optional digital signatures for verification.
"""

import os
import json
import hashlib
import hmac
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set, Callable
from dataclasses import dataclass, asdict
from enum import Enum


class BaselineStatus(Enum):
    """Status of baseline generation."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class FileHashEntry:
    """Represents a single file's hash entry in the baseline."""
    path: str
    sha256: str
    size: int
    modified_time: float
    permissions: str
    
    def to_dict(self) -> Dict:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "modified_time": self.modified_time,
            "permissions": self.permissions
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "FileHashEntry":
        return cls(
            path=data["path"],
            sha256=data["sha256"],
            size=data["size"],
            modified_time=data["modified_time"],
            permissions=data["permissions"]
        )


@dataclass
class BaselineMetadata:
    """Metadata for the baseline."""
    version: str
    created_at: str
    created_by: str
    hostname: Optional[str]
    total_files: int
    signature: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "hostname": self.hostname,
            "total_files": self.total_files,
            "signature": self.signature
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "BaselineMetadata":
        return cls(
            version=data["version"],
            created_at=data["created_at"],
            created_by=data["created_by"],
            hostname=data.get("hostname"),
            total_files=data["total_files"],
            signature=data.get("signature")
        )


class BaselineGenerator:
    """Generates and manages integrity baselines for critical files.
    
    This class is responsible for:
    - Scanning critical directories for files to monitor
    - Computing SHA256 hashes for each file
    - Storing baseline data in a JSON format
    - Optionally signing the baseline for verification
    
    Example:
        >>> generator = BaselineGenerator()
        >>> baseline = generator.generate_baseline([
        ...     "xclaw_agentguard/config/",
        ...     "xclaw_agentguard/core/"
        ... ])
        >>> generator.save_baseline(baseline, "baseline.json")
    """
    
    # Default critical paths to monitor
    DEFAULT_CRITICAL_PATHS = [
        "config/*.py",
        "core/*.py",
        "detectors/*/detector.py",
        "*.json",
    ]
    
    def __init__(
        self,
        base_path: Optional[str] = None,
        secret_key: Optional[str] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None
    ):
        """Initialize the baseline generator.
        
        Args:
            base_path: Base path for resolving relative paths (default: xclaw_agentguard/)
            secret_key: Optional HMAC secret for signing baselines
            progress_callback: Optional callback(path, current, total) for progress updates
        """
        self.base_path = Path(base_path) if base_path else Path(__file__).parent.parent
        self.secret_key = secret_key.encode() if secret_key else None
        self.progress_callback = progress_callback
        self._status = BaselineStatus.PENDING
        self._errors: List[str] = []
    
    @property
    def status(self) -> BaselineStatus:
        """Current status of baseline generation."""
        return self._status
    
    @property
    def errors(self) -> List[str]:
        """List of errors encountered during generation."""
        return self._errors.copy()
    
    def _compute_file_hash(self, file_path: Path) -> Optional[FileHashEntry]:
        """Compute SHA256 hash for a single file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            FileHashEntry or None if file cannot be read
        """
        try:
            sha256_hash = hashlib.sha256()
            
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256_hash.update(chunk)
            
            stat = file_path.stat()
            
            return FileHashEntry(
                path=str(file_path.relative_to(self.base_path)),
                sha256=sha256_hash.hexdigest(),
                size=stat.st_size,
                modified_time=stat.st_mtime,
                permissions=oct(stat.st_mode)[-3:]
            )
        except (IOError, OSError) as e:
            self._errors.append(f"Failed to hash {file_path}: {e}")
            return None
    
    def _expand_patterns(self, patterns: List[str]) -> Set[Path]:
        """Expand glob patterns to get all matching files.
        
        Args:
            patterns: List of glob patterns
            
        Returns:
            Set of matching file paths
        """
        files = set()
        
        for pattern in patterns:
            # Handle both relative and absolute patterns
            if os.path.isabs(pattern):
                search_path = Path(pattern)
            else:
                search_path = self.base_path / pattern
            
            # Support ** for recursive glob
            if "**" in pattern:
                matched = self.base_path.rglob(pattern.replace("**", "").lstrip("/"))
            else:
                matched = self.base_path.glob(pattern)
            
            for path in matched:
                if path.is_file():
                    files.add(path)
        
        return files
    
    def generate_baseline(
        self,
        paths: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None
    ) -> Dict:
        """Generate a baseline of file hashes.
        
        Args:
            paths: List of paths/patterns to include (default: DEFAULT_CRITICAL_PATHS)
            exclude_patterns: List of patterns to exclude (e.g., ["*.pyc", "__pycache__/*"])
            
        Returns:
            Dictionary containing baseline data and metadata
        """
        self._status = BaselineStatus.IN_PROGRESS
        self._errors = []
        
        try:
            paths = paths or self.DEFAULT_CRITICAL_PATHS
            exclude_patterns = exclude_patterns or ["*.pyc", "__pycache__/*", "*.pyo", ".*"]
            
            # Collect all files
            all_files = self._expand_patterns(paths)
            
            # Filter out excluded files
            files_to_hash = []
            for f in all_files:
                excluded = False
                for pattern in exclude_patterns:
                    if f.match(pattern) or any(part.startswith(".") for part in f.parts):
                        excluded = True
                        break
                if not excluded:
                    files_to_hash.append(f)
            
            # Sort for consistent ordering
            files_to_hash.sort()
            
            # Compute hashes
            entries = []
            total = len(files_to_hash)
            
            for i, file_path in enumerate(files_to_hash):
                entry = self._compute_file_hash(file_path)
                if entry:
                    entries.append(entry)
                
                if self.progress_callback:
                    self.progress_callback(str(file_path), i + 1, total)
            
            # Create metadata
            metadata = BaselineMetadata(
                version="1.0.0",
                created_at=datetime.utcnow().isoformat() + "Z",
                created_by="xclaw_agentguard_baseline_generator",
                hostname=os.environ.get("HOSTNAME") or os.environ.get("COMPUTERNAME"),
                total_files=len(entries)
            )
            
            # Build baseline structure
            baseline = {
                "metadata": metadata.to_dict(),
                "files": {entry.path: entry.to_dict() for entry in entries}
            }
            
            # Sign baseline if secret key available
            if self.secret_key:
                baseline["metadata"]["signature"] = self._sign_baseline(baseline)
            
            self._status = BaselineStatus.COMPLETED
            return baseline
            
        except Exception as e:
            self._status = BaselineStatus.FAILED
            self._errors.append(f"Baseline generation failed: {e}")
            raise
    
    def _sign_baseline(self, baseline: Dict) -> str:
        """Sign the baseline with HMAC-SHA256.
        
        Args:
            baseline: The baseline dictionary to sign
            
        Returns:
            Hex-encoded signature
        """
        if not self.secret_key:
            raise ValueError("No secret key configured for signing")
        
        # Create a canonical representation for signing
        # Remove existing signature if present
        baseline_copy = json.loads(json.dumps(baseline))
        baseline_copy["metadata"].pop("signature", None)
        
        canonical = json.dumps(baseline_copy, sort_keys=True, separators=(",", ":"))
        signature = hmac.new(
            self.secret_key,
            canonical.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def verify_baseline(self, baseline: Dict) -> bool:
        """Verify the signature of a baseline.
        
        Args:
            baseline: The baseline dictionary to verify
            
        Returns:
            True if signature is valid or no signature present
        """
        if not self.secret_key:
            return True  # No verification possible without key
        
        stored_signature = baseline.get("metadata", {}).get("signature")
        if not stored_signature:
            return True  # No signature to verify
        
        computed = self._sign_baseline(baseline)
        return hmac.compare_digest(stored_signature, computed)
    
    def save_baseline(self, baseline: Dict, output_path: str) -> Path:
        """Save baseline to a JSON file.
        
        Args:
            baseline: The baseline dictionary
            output_path: Path to save the baseline
            
        Returns:
            Path object of the saved file
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, "w") as f:
            json.dump(baseline, f, indent=2)
        
        return output_file
    
    def load_baseline(self, input_path: str) -> Dict:
        """Load baseline from a JSON file.
        
        Args:
            input_path: Path to the baseline file
            
        Returns:
            Baseline dictionary
            
        Raises:
            FileNotFoundError: If baseline file doesn't exist
            ValueError: If baseline is malformed or signature invalid
        """
        input_file = Path(input_path)
        
        if not input_file.exists():
            raise FileNotFoundError(f"Baseline file not found: {input_path}")
        
        with open(input_file, "r") as f:
            baseline = json.load(f)
        
        # Verify signature if present
        if not self.verify_baseline(baseline):
            raise ValueError("Baseline signature verification failed - possible tampering")
        
        return baseline
    
    def diff_baselines(self, old_baseline: Dict, new_baseline: Dict) -> Dict:
        """Compare two baselines and identify differences.
        
        Args:
            old_baseline: The original baseline
            new_baseline: The new baseline to compare
            
        Returns:
            Dictionary with added, removed, and modified files
        """
        old_files = set(old_baseline.get("files", {}).keys())
        new_files = set(new_baseline.get("files", {}).keys())
        
        added = new_files - old_files
        removed = old_files - new_files
        common = old_files & new_files
        
        modified = []
        for path in common:
            old_hash = old_baseline["files"][path]["sha256"]
            new_hash = new_baseline["files"][path]["sha256"]
            if old_hash != new_hash:
                modified.append({
                    "path": path,
                    "old_hash": old_hash,
                    "new_hash": new_hash
                })
        
        return {
            "added": list(added),
            "removed": list(removed),
            "modified": modified,
            "summary": {
                "total_old": len(old_files),
                "total_new": len(new_files),
                "added_count": len(added),
                "removed_count": len(removed),
                "modified_count": len(modified)
            }
        }


def generate_baseline_cli(
    paths: Optional[List[str]] = None,
    output: str = "xclaw_agentguard/baseline.json",
    secret_key: Optional[str] = None,
    verbose: bool = False
) -> int:
    """CLI entry point for baseline generation.
    
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    def progress(path: str, current: int, total: int):
        if verbose:
            print(f"  [{current}/{total}] {path}")
    
    try:
        generator = BaselineGenerator(secret_key=secret_key, progress_callback=progress)
        
        print("Generating baseline...")
        baseline = generator.generate_baseline(paths)
        
        output_path = generator.save_baseline(baseline, output)
        
        print(f"\nBaseline saved to: {output_path}")
        print(f"Total files: {baseline['metadata']['total_files']}")
        print(f"Created: {baseline['metadata']['created_at']}")
        
        if baseline['metadata'].get('signature'):
            print("Signature: [SIGNED]")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(generate_baseline_cli())
