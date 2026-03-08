"""
Feed Updater Module

Manages scheduled updates of threat feeds, differential updates,
and backup of old feeds.
"""

from __future__ import annotations

import json
import shutil
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import schedule

from .cve_fetcher import CVEFetcher, CVEData, CVECache
from .intel_analyzer import IntelAnalyzer, ThreatReport


class UpdateStatus(Enum):
    """Status of a feed update operation."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class FeedSource:
    """Configuration for a threat feed source."""
    name: str
    url: str
    feed_type: str  # nvd, cve, oss, commercial
    enabled: bool = True
    update_interval_hours: int = 24
    api_key: Optional[str] = None
    last_update: Optional[datetime] = None
    last_status: UpdateStatus = UpdateStatus.PENDING
    last_error: Optional[str] = None
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "feed_type": self.feed_type,
            "enabled": self.enabled,
            "update_interval_hours": self.update_interval_hours,
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "last_status": self.last_status.value,
            "last_error": self.last_error
        }


@dataclass
class FeedUpdateResult:
    """Result of a feed update operation."""
    feed_name: str
    status: UpdateStatus
    started_at: datetime
    completed_at: Optional[datetime]
    cves_added: int
    cves_updated: int
    cves_removed: int
    errors: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration_seconds(self) -> float:
        """Get update duration in seconds."""
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "feed_name": self.feed_name,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "cves_added": self.cves_added,
            "cves_updated": self.cves_updated,
            "cves_removed": self.cves_removed,
            "errors": self.errors,
            "metadata": self.metadata
        }


@dataclass
class UpdateSchedule:
    """Schedule configuration for feed updates."""
    daily_update_time: str = "02:00"  # 2 AM
    differential_update_interval_minutes: int = 60
    full_update_interval_hours: int = 24
    max_concurrent_updates: int = 3
    retry_attempts: int = 3
    retry_delay_seconds: int = 300  # 5 minutes
    backup_before_update: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FeedUpdater:
    """Manages threat feed updates and scheduling."""
    
    DEFAULT_FEEDS = [
        FeedSource(
            name="NVD_API",
            url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            feed_type="nvd",
            update_interval_hours=24
        ),
        FeedSource(
            name="NVD_CVE_FEED",
            url="https://nvd.nist.gov/feeds/json/cve/1.1",
            feed_type="cve",
            update_interval_hours=24
        )
    ]
    
    def __init__(
        self,
        cve_fetcher: Optional[CVEFetcher] = None,
        data_dir: str = "~/.xclaw_agentguard/feeds",
        schedule_config: Optional[UpdateSchedule] = None
    ):
        self.cve_fetcher = cve_fetcher or CVEFetcher()
        self.data_dir = Path(data_dir).expanduser()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.schedule_config = schedule_config or UpdateSchedule()
        self.feeds: List[FeedSource] = []
        self.update_history: List[FeedUpdateResult] = []
        
        # Background scheduler
        self._scheduler_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Callbacks
        self._update_callbacks: List[Callable[[FeedUpdateResult], None]] = []
        self._error_callbacks: List[Callable[[str, Exception], None]] = []
        
        # State tracking
        self._is_updating = False
        self._last_full_update: Optional[datetime] = None
        self._last_diff_update: Optional[datetime] = None
        
        # Load configuration
        self._load_config()
    
    def _load_config(self) -> None:
        """Load feed configuration."""
        config_file = self.data_dir / "feeds_config.json"
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    data = json.load(f)
                
                self.feeds = [
                    FeedSource(**feed_data)
                    for feed_data in data.get("feeds", [])
                ]
                
                if data.get("schedule"):
                    self.schedule_config = UpdateSchedule(**data["schedule"])
            except (json.JSONDecodeError, TypeError):
                pass
        
        # Use defaults if no feeds configured
        if not self.feeds:
            self.feeds = [feed.copy() for feed in self.DEFAULT_FEEDS]
            self._save_config()
    
    def _save_config(self) -> None:
        """Save feed configuration."""
        config_file = self.data_dir / "feeds_config.json"
        data = {
            "feeds": [feed.to_dict() for feed in self.feeds],
            "schedule": self.schedule_config.to_dict(),
            "saved_at": datetime.now().isoformat()
        }
        
        with open(config_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def add_feed(self, feed: FeedSource) -> None:
        """Add a new threat feed source."""
        self.feeds.append(feed)
        self._save_config()
    
    def remove_feed(self, feed_name: str) -> bool:
        """Remove a feed source."""
        for i, feed in enumerate(self.feeds):
            if feed.name == feed_name:
                self.feeds.pop(i)
                self._save_config()
                return True
        return False
    
    def enable_feed(self, feed_name: str) -> bool:
        """Enable a feed source."""
        for feed in self.feeds:
            if feed.name == feed_name:
                feed.enabled = True
                self._save_config()
                return True
        return False
    
    def disable_feed(self, feed_name: str) -> bool:
        """Disable a feed source."""
        for feed in self.feeds:
            if feed.name == feed_name:
                feed.enabled = False
                self._save_config()
                return True
        return False
    
    def update_feed(self, feed_name: str, differential: bool = True) -> FeedUpdateResult:
        """Update a specific feed."""
        feed = None
        for f in self.feeds:
            if f.name == feed_name:
                feed = f
                break
        
        if not feed:
            return FeedUpdateResult(
                feed_name=feed_name,
                status=UpdateStatus.FAILED,
                started_at=datetime.now(),
                completed_at=datetime.now(),
                cves_added=0,
                cves_updated=0,
                cves_removed=0,
                errors=[f"Feed '{feed_name}' not found"]
            )
        
        if not feed.enabled:
            return FeedUpdateResult(
                feed_name=feed_name,
                status=UpdateStatus.SKIPPED,
                started_at=datetime.now(),
                completed_at=datetime.now(),
                cves_added=0,
                cves_updated=0,
                cves_removed=0,
                errors=["Feed is disabled"]
            )
        
        return self._perform_update(feed, differential)
    
    def update_all_feeds(self, differential: bool = True) -> List[FeedUpdateResult]:
        """Update all enabled feeds."""
        results = []
        enabled_feeds = [f for f in self.feeds if f.enabled]
        
        # Backup before update
        if self.schedule_config.backup_before_update and not differential:
            self._backup_feeds()
        
        # Update with concurrency limit
        with ThreadPoolExecutor(max_workers=self.schedule_config.max_concurrent_updates) as executor:
            future_to_feed = {
                executor.submit(self._perform_update, feed, differential): feed
                for feed in enabled_feeds
            }
            
            for future in as_completed(future_to_feed):
                feed = future_to_feed[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append(FeedUpdateResult(
                        feed_name=feed.name,
                        status=UpdateStatus.FAILED,
                        started_at=datetime.now(),
                        completed_at=datetime.now(),
                        cves_added=0,
                        cves_updated=0,
                        cves_removed=0,
                        errors=[str(e)]
                    ))
        
        # Update timestamps
        if not differential:
            self._last_full_update = datetime.now()
        else:
            self._last_diff_update = datetime.now()
        
        self.update_history.extend(results)
        
        # Trigger callbacks
        for result in results:
            for callback in self._update_callbacks:
                try:
                    callback(result)
                except Exception:
                    pass
        
        return results
    
    def update_differential(self) -> List[FeedUpdateResult]:
        """Perform differential update (only new/changed CVEs)."""
        return self.update_all_feeds(differential=True)
    
    def update_full(self) -> List[FeedUpdateResult]:
        """Perform full update (all CVEs)."""
        return self.update_all_feeds(differential=False)
    
    def _perform_update(self, feed: FeedSource, differential: bool) -> FeedUpdateResult:
        """Perform actual update for a feed."""
        result = FeedUpdateResult(
            feed_name=feed.name,
            status=UpdateStatus.RUNNING,
            started_at=datetime.now(),
            completed_at=None,
            cves_added=0,
            cves_updated=0,
            cves_removed=0,
            errors=[]
        )
        
        feed.last_status = UpdateStatus.RUNNING
        
        try:
            if feed.feed_type == "nvd":
                result = self._update_nvd_feed(feed, result, differential)
            elif feed.feed_type == "cve":
                result = self._update_cve_feed(feed, result, differential)
            else:
                result.errors.append(f"Unknown feed type: {feed.feed_type}")
                result.status = UpdateStatus.FAILED
            
        except Exception as e:
            result.status = UpdateStatus.FAILED
            result.errors.append(str(e))
            feed.last_error = str(e)
            
            # Trigger error callbacks
            for callback in self._error_callbacks:
                try:
                    callback(feed.name, e)
                except Exception:
                    pass
        
        finally:
            result.completed_at = datetime.now()
            feed.last_update = datetime.now()
            feed.last_status = result.status
            
            # Save state
            self._save_config()
        
        return result
    
    def _update_nvd_feed(
        self,
        feed: FeedSource,
        result: FeedUpdateResult,
        differential: bool
    ) -> FeedUpdateResult:
        """Update from NVD API."""
        # Determine time range
        if differential and feed.last_update:
            start_date = feed.last_update
        else:
            start_date = datetime.now() - timedelta(days=30)
        
        end_date = datetime.now()
        
        # Fetch CVEs
        cves = self.cve_fetcher.fetch_by_date_range(start_date, end_date)
        
        # Track changes
        existing_ids = set(self.cve_fetcher.cache._load_metadata().keys())
        new_ids = set(c.cve_id for c in cves)
        
        result.cves_added = len(new_ids - existing_ids)
        result.cves_updated = len(new_ids & existing_ids)
        
        result.status = UpdateStatus.SUCCESS if not result.errors else UpdateStatus.PARTIAL
        result.metadata["total_fetched"] = len(cves)
        result.metadata["time_range"] = f"{start_date.isoformat()} to {end_date.isoformat()}"
        
        return result
    
    def _update_cve_feed(
        self,
        feed: FeedSource,
        result: FeedUpdateResult,
        differential: bool
    ) -> FeedUpdateResult:
        """Update from CVE feed."""
        # Similar to NVD but can fetch different feeds
        # For now, delegate to NVD fetcher
        return self._update_nvd_feed(feed, result, differential)
    
    def _backup_feeds(self) -> str:
        """Create backup of current feeds."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = self.data_dir / "backups" / f"feed_backup_{timestamp}"
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Backup cache
        cache_backup = backup_dir / "cve_cache"
        if self.cve_fetcher.cache.cache_dir.exists():
            shutil.copytree(self.cve_fetcher.cache.cache_dir, cache_backup, dirs_exist_ok=True)
        
        # Backup config
        config_file = self.data_dir / "feeds_config.json"
        if config_file.exists():
            shutil.copy2(config_file, backup_dir / "feeds_config.json")
        
        return str(backup_dir)
    
    def start_scheduler(self) -> None:
        """Start background update scheduler."""
        if self._scheduler_thread and self._scheduler_thread.is_alive():
            return
        
        self._stop_event.clear()
        self._scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self._scheduler_thread.start()
    
    def stop_scheduler(self) -> None:
        """Stop background update scheduler."""
        self._stop_event.set()
        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=5)
    
    def _scheduler_loop(self) -> None:
        """Main scheduler loop."""
        # Schedule daily full update
        schedule.every().day.at(self.schedule_config.daily_update_time).do(
            self.update_full
        )
        
        # Schedule differential updates
        schedule.every(self.schedule_config.differential_update_interval_minutes).minutes.do(
            self.update_differential
        )
        
        while not self._stop_event.is_set():
            schedule.run_pending()
            time.sleep(1)
    
    def on_update_complete(self, callback: Callable[[FeedUpdateResult], None]) -> None:
        """Register callback for update completion."""
        self._update_callbacks.append(callback)
    
    def on_update_error(self, callback: Callable[[str, Exception], None]) -> None:
        """Register callback for update errors."""
        self._error_callbacks.append(callback)
    
    def get_update_status(self) -> Dict[str, Any]:
        """Get current update status."""
        return {
            "is_updating": self._is_updating,
            "last_full_update": self._last_full_update.isoformat() if self._last_full_update else None,
            "last_diff_update": self._last_diff_update.isoformat() if self._last_diff_update else None,
            "feeds": [
                {
                    "name": f.name,
                    "enabled": f.enabled,
                    "last_update": f.last_update.isoformat() if f.last_update else None,
                    "last_status": f.last_status.value,
                    "last_error": f.last_error
                }
                for f in self.feeds
            ],
            "recent_updates": [
                r.to_dict() for r in self.update_history[-10:]
            ]
        }
    
    def get_update_history(
        self,
        feed_name: Optional[str] = None,
        limit: int = 100
    ) -> List[FeedUpdateResult]:
        """Get update history."""
        history = self.update_history
        
        if feed_name:
            history = [h for h in history if h.feed_name == feed_name]
        
        return history[-limit:]
    
    def cleanup_old_backups(self, max_age_days: int = 30) -> int:
        """Clean up old backup files."""
        backup_dir = self.data_dir / "backups"
        if not backup_dir.exists():
            return 0
        
        cutoff = datetime.now() - timedelta(days=max_age_days)
        removed = 0
        
        for backup in backup_dir.iterdir():
            if backup.is_dir():
                try:
                    mtime = datetime.fromtimestamp(backup.stat().st_mtime)
                    if mtime < cutoff:
                        shutil.rmtree(backup)
                        removed += 1
                except Exception:
                    pass
        
        return removed
    
    def force_update(self, feed_name: Optional[str] = None) -> List[FeedUpdateResult]:
        """Force immediate update."""
        if feed_name:
            return [self.update_feed(feed_name, differential=False)]
        return self.update_full()


# Convenience functions
def run_manual_update(
    cve_fetcher: Optional[CVEFetcher] = None,
    differential: bool = True
) -> List[FeedUpdateResult]:
    """Run a manual update."""
    updater = FeedUpdater(cve_fetcher)
    if differential:
        return updater.update_differential()
    return updater.update_full()


def schedule_daily_updates(
    cve_fetcher: Optional[CVEFetcher] = None,
    update_time: str = "02:00"
) -> FeedUpdater:
    """Set up daily scheduled updates."""
    schedule_config = UpdateSchedule(daily_update_time=update_time)
    updater = FeedUpdater(cve_fetcher, schedule_config=schedule_config)
    updater.start_scheduler()
    return updater
