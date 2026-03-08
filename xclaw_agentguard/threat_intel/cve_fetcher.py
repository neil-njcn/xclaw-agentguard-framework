"""
CVE Fetcher Module

Fetches CVE (Common Vulnerabilities and Exposures) data from NVD
(National Vulnerability Database), parses JSON feeds, caches data locally,
and filters relevant CVEs related to AI/agent systems.
"""

from __future__ import annotations

import json
import gzip
import shutil
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Callable
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import time


class Severity(Enum):
    """CVE Severity levels based on CVSS scores."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"
    UNKNOWN = "unknown"
    
    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        """Convert CVSS score to severity level."""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0:
            return cls.LOW
        elif score == 0:
            return cls.NONE
        else:
            return cls.UNKNOWN


@dataclass
class CVSSData:
    """CVSS scoring data."""
    version: str = ""
    vector_string: str = ""
    base_score: float = 0.0
    severity: Severity = Severity.UNKNOWN
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    
    @classmethod
    def from_nvd_json(cls, data: Dict[str, Any]) -> CVSSData:
        """Parse CVSS data from NVD JSON format."""
        metrics = data.get("metrics", {})
        
        # Try CVSS v3.1 first, then v3.0, then v2
        cvss_key = None
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                cvss_key = key
                break
        
        if not cvss_key or not metrics[cvss_key]:
            return cls()
        
        cvss = metrics[cvss_key][0].get("cvssData", {})
        
        base_score = cvss.get("baseScore", 0.0)
        
        return cls(
            version=cvss.get("version", ""),
            vector_string=cvss.get("vectorString", ""),
            base_score=base_score,
            severity=Severity.from_cvss(base_score),
            exploitability_score=metrics[cvss_key][0].get("exploitabilityScore", 0.0),
            impact_score=metrics[cvss_key][0].get("impactScore", 0.0)
        )


@dataclass
class CVEData:
    """Structured CVE data."""
    cve_id: str
    published_date: datetime
    last_modified: datetime
    description: str = ""
    description_zh: str = ""  # Chinese description if available
    cvss: CVSSData = field(default_factory=CVSSData)
    references: List[Dict[str, str]] = field(default_factory=list)
    weaknesses: List[str] = field(default_factory=list)
    configurations: List[Dict[str, Any]] = field(default_factory=list)
    vendors: List[str] = field(default_factory=list)
    products: List[str] = field(default_factory=list)
    ai_related: bool = False
    agent_related: bool = False
    llm_related: bool = False
    tags: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict, repr=False)
    
    @property
    def severity(self) -> Severity:
        """Get severity from CVSS data."""
        return self.cvss.severity
    
    @property
    def is_high_severity(self) -> bool:
        """Check if CVE has high or critical severity."""
        return self.severity in [Severity.HIGH, Severity.CRITICAL]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "cve_id": self.cve_id,
            "published_date": self.published_date.isoformat(),
            "last_modified": self.last_modified.isoformat(),
            "description": self.description,
            "description_zh": self.description_zh,
            "cvss": asdict(self.cvss),
            "references": self.references,
            "weaknesses": self.weaknesses,
            "configurations": self.configurations,
            "vendors": self.vendors,
            "products": self.products,
            "ai_related": self.ai_related,
            "agent_related": self.agent_related,
            "llm_related": self.llm_related,
            "tags": self.tags
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CVEData:
        """Create from dictionary."""
        cvss_data = CVSSData(**data.get("cvss", {}))
        if "severity" in data.get("cvss", {}):
            cvss_data.severity = Severity(data["cvss"]["severity"])
        
        return cls(
            cve_id=data["cve_id"],
            published_date=datetime.fromisoformat(data["published_date"]),
            last_modified=datetime.fromisoformat(data["last_modified"]),
            description=data.get("description", ""),
            description_zh=data.get("description_zh", ""),
            cvss=cvss_data,
            references=data.get("references", []),
            weaknesses=data.get("weaknesses", []),
            configurations=data.get("configurations", []),
            vendors=data.get("vendors", []),
            products=data.get("products", []),
            ai_related=data.get("ai_related", False),
            agent_related=data.get("agent_related", False),
            llm_related=data.get("llm_related", False),
            tags=data.get("tags", [])
        )


class CVECache:
    """Local cache for CVE data."""
    
    def __init__(self, cache_dir: str = "~/.xclaw_agentguard/cve_cache"):
        self.cache_dir = Path(cache_dir).expanduser()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.cache_dir / "cache_metadata.json"
        self.metadata: Dict[str, Any] = self._load_metadata()
    
    def _load_metadata(self) -> Dict[str, Any]:
        """Load cache metadata."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {"last_update": None, "total_entries": 0}
    
    def _save_metadata(self) -> None:
        """Save cache metadata."""
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f, indent=2)
    
    def get(self, cve_id: str) -> Optional[CVEData]:
        """Get CVE from cache if exists and not expired."""
        cache_file = self.cache_dir / f"{cve_id}.json"
        if not cache_file.exists():
            return None
        
        # Check if cache is expired (7 days)
        file_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
        if file_age > timedelta(days=7):
            return None
        
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            return CVEData.from_dict(data)
        except (json.JSONDecodeError, IOError, KeyError):
            return None
    
    def set(self, cve: CVEData) -> None:
        """Store CVE in cache."""
        cache_file = self.cache_dir / f"{cve.cve_id}.json"
        try:
            with open(cache_file, 'w') as f:
                json.dump(cve.to_dict(), f, indent=2)
            self.metadata["total_entries"] = len(list(self.cache_dir.glob("CVE-*.json")))
            self._save_metadata()
        except IOError:
            pass
    
    def get_all(self) -> List[CVEData]:
        """Get all cached CVEs."""
        cves = []
        for cache_file in self.cache_dir.glob("CVE-*.json"):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                cves.append(CVEData.from_dict(data))
            except (json.JSONDecodeError, IOError, KeyError):
                continue
        return cves
    
    def clear(self) -> None:
        """Clear all cached CVEs."""
        for cache_file in self.cache_dir.glob("CVE-*.json"):
            cache_file.unlink()
        self.metadata = {"last_update": None, "total_entries": 0}
        self._save_metadata()
    
    def backup(self, backup_dir: Optional[str] = None) -> str:
        """Create backup of cache."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if backup_dir is None:
            backup_dir = self.cache_dir / "backups"
        else:
            backup_dir = Path(backup_dir)
        
        backup_path = backup_dir / f"cve_cache_backup_{timestamp}"
        backup_path.mkdir(parents=True, exist_ok=True)
        
        for cache_file in self.cache_dir.glob("CVE-*.json"):
            shutil.copy2(cache_file, backup_path / cache_file.name)
        
        shutil.copy2(self.metadata_file, backup_path / "cache_metadata.json")
        return str(backup_path)
    
    def update_timestamp(self) -> None:
        """Update last update timestamp."""
        self.metadata["last_update"] = datetime.now().isoformat()
        self._save_metadata()


class CVEFetcher:
    """Fetches CVE data from NVD API."""
    
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/1.1"
    
    # Keywords for AI/agent related CVE filtering
    AI_KEYWORDS = [
        "artificial intelligence", "machine learning", "ml", "deep learning",
        "neural network", "neural net", "ai model", "ai system", "ai agent",
        "language model", "llm", "gpt", "chatbot", "virtual assistant",
        "autonomous agent", "ai framework", "pytorch", "tensorflow", "keras",
        "scikit-learn", "hugging face", "transformer", "bert", "stable diffusion"
    ]
    
    AGENT_KEYWORDS = [
        "ai agent", "autonomous agent", "software agent", "intelligent agent",
        "multi-agent", "agent system", "agent framework", "autonomous system",
        "autonomous decision", "agent orchestration"
    ]
    
    LLM_KEYWORDS = [
        "large language model", "llm", "language model", "foundation model",
        "generative ai", "genai", "text generation", "inference api",
        "model serving", "prompt injection", "jailbreak"
    ]
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_dir: str = "~/.xclaw_agentguard/cve_cache",
        rate_limit_delay: float = 6.0  # NVD recommends 6 seconds between requests
    ):
        self.api_key = api_key
        self.cache = CVECache(cache_dir)
        self.rate_limit_delay = rate_limit_delay
        self._last_request_time: Optional[float] = None
        self._ai_related_filter: Optional[Callable[[CVEData], bool]] = None
    
    def _rate_limit(self) -> None:
        """Apply rate limiting between requests."""
        if self._last_request_time is not None:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.rate_limit_delay:
                time.sleep(self.rate_limit_delay - elapsed)
        self._last_request_time = time.time()
    
    def _make_request(self, url: str) -> Optional[Dict[str, Any]]:
        """Make HTTP request with error handling."""
        self._rate_limit()
        
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode('utf-8'))
        except HTTPError as e:
            if e.code == 403:
                print(f"API rate limit exceeded or invalid API key")
            elif e.code == 404:
                print(f"Resource not found: {url}")
            else:
                print(f"HTTP error {e.code}: {e.reason}")
        except URLError as e:
            print(f"URL error: {e.reason}")
        except json.JSONDecodeError:
            print(f"Invalid JSON response from: {url}")
        except Exception as e:
            print(f"Request error: {e}")
        
        return None
    
    def fetch_cve(self, cve_id: str) -> Optional[CVEData]:
        """Fetch single CVE by ID."""
        # Check cache first
        cached = self.cache.get(cve_id)
        if cached:
            return cached
        
        url = f"{self.NVD_API_BASE}?cveId={cve_id}"
        data = self._make_request(url)
        
        if not data or "vulnerabilities" not in data:
            return None
        
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None
        
        cve = self._parse_cve(vulnerabilities[0])
        if cve:
            self.cache.set(cve)
        
        return cve
    
    def fetch_recent(self, days: int = 30) -> List[CVEData]:
        """Fetch CVEs published in last N days."""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        return self.fetch_by_date_range(start_date, end_date)
    
    def fetch_by_date_range(
        self,
        start_date: datetime,
        end_date: datetime,
        results_per_page: int = 2000
    ) -> List[CVEData]:
        """Fetch CVEs by date range."""
        cves = []
        start_index = 0
        
        while True:
            url = (
                f"{self.NVD_API_BASE}?"
                f"pubStartDate={start_date.isoformat()}&"
                f"pubEndDate={end_date.isoformat()}&"
                f"resultsPerPage={results_per_page}&"
                f"startIndex={start_index}"
            )
            
            data = self._make_request(url)
            if not data:
                break
            
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break
            
            for vuln in vulnerabilities:
                cve = self._parse_cve(vuln)
                if cve:
                    cves.append(cve)
                    self.cache.set(cve)
            
            total_results = data.get("totalResults", 0)
            start_index += results_per_page
            
            if start_index >= total_results:
                break
        
        self.cache.update_timestamp()
        return cves
    
    def search_by_keyword(self, keyword: str, exact_match: bool = False) -> List[CVEData]:
        """Search CVEs by keyword."""
        cves = []
        start_index = 0
        results_per_page = 2000
        
        while True:
            url = (
                f"{self.NVD_API_BASE}?"
                f"keywordSearch={keyword}&"
                f"resultsPerPage={results_per_page}&"
                f"startIndex={start_index}"
            )
            
            if exact_match:
                url += "&keywordExactMatch"
            
            data = self._make_request(url)
            if not data:
                break
            
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break
            
            for vuln in vulnerabilities:
                cve = self._parse_cve(vuln)
                if cve:
                    cves.append(cve)
                    self.cache.set(cve)
            
            total_results = data.get("totalResults", 0)
            start_index += results_per_page
            
            if start_index >= total_results:
                break
        
        return cves
    
    def fetch_ai_related(self, days: int = 30) -> List[CVEData]:
        """Fetch CVEs related to AI/ML systems."""
        # First fetch recent CVEs
        recent_cves = self.fetch_recent(days)
        
        # Filter for AI-related
        ai_cves = [cve for cve in recent_cves if self._is_ai_related(cve)]
        
        # Also search for specific AI keywords
        for keyword in ["artificial intelligence", "machine learning", "llm", "ai model"]:
            search_results = self.search_by_keyword(keyword)
            for cve in search_results:
                if cve not in ai_cves and self._is_ai_related(cve):
                    ai_cves.append(cve)
        
        return ai_cves
    
    def _parse_cve(self, vuln_data: Dict[str, Any]) -> Optional[CVEData]:
        """Parse NVD vulnerability data into CVEData."""
        try:
            cve = vuln_data.get("cve", {})
            cve_id = cve.get("id", "")
            
            if not cve_id:
                return None
            
            # Parse dates
            published = cve.get("published", "")
            modified = cve.get("lastModified", "")
            
            # Parse descriptions
            descriptions = cve.get("descriptions", [])
            description_en = ""
            description_zh = ""
            
            for desc in descriptions:
                lang = desc.get("lang", "")
                value = desc.get("value", "")
                if lang == "en":
                    description_en = value
                elif lang == "zh":
                    description_zh = value
            
            # Parse CVSS
            cvss = CVSSData.from_nvd_json(cve)
            
            # Parse references
            references = []
            for ref in cve.get("references", []):
                references.append({
                    "url": ref.get("url", ""),
                    "source": ref.get("source", ""),
                    "tags": ref.get("tags", [])
                })
            
            # Parse weaknesses (CWE)
            weaknesses = []
            for weakness in cve.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        weaknesses.append(desc.get("value", ""))
            
            # Parse configurations (affected products)
            vendors = []
            products = []
            configurations = cve.get("configurations", [])
            
            for config in configurations:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria", "")
                        if criteria.startswith("cpe:"):
                            parts = criteria.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                if vendor and vendor not in vendors:
                                    vendors.append(vendor)
                                if product and product not in products:
                                    products.append(product)
            
            cve_data = CVEData(
                cve_id=cve_id,
                published_date=datetime.fromisoformat(published.replace('Z', '+00:00')),
                last_modified=datetime.fromisoformat(modified.replace('Z', '+00:00')),
                description=description_en,
                description_zh=description_zh,
                cvss=cvss,
                references=references,
                weaknesses=weaknesses,
                configurations=configurations,
                vendors=vendors,
                products=products,
                raw_data=vuln_data
            )
            
            # Classify AI-related
            self._classify_cve(cve_data)
            
            return cve_data
            
        except Exception as e:
            print(f"Error parsing CVE data: {e}")
            return None
    
    def _classify_cve(self, cve: CVEData) -> None:
        """Classify CVE as AI/agent/LLM related."""
        text_to_check = f"{cve.description} {' '.join(cve.products)} {' '.join(cve.vendors)}".lower()
        
        # Check AI-related
        cve.ai_related = any(kw.lower() in text_to_check for kw in self.AI_KEYWORDS)
        
        # Check agent-related
        cve.agent_related = any(kw.lower() in text_to_check for kw in self.AGENT_KEYWORDS)
        
        # Check LLM-related
        cve.llm_related = any(kw.lower() in text_to_check for kw in self.LLM_KEYWORDS)
        
        # Set tags
        tags = []
        if cve.ai_related:
            tags.append("ai-related")
        if cve.agent_related:
            tags.append("agent-related")
        if cve.llm_related:
            tags.append("llm-related")
        if cve.is_high_severity:
            tags.append("high-severity")
        
        cve.tags = tags
    
    def _is_ai_related(self, cve: CVEData) -> bool:
        """Check if CVE is AI-related."""
        return cve.ai_related or cve.agent_related or cve.llm_related
    
    def set_ai_filter(self, filter_func: Callable[[CVEData], bool]) -> None:
        """Set custom AI-related filter function."""
        self._ai_related_filter = filter_func
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "cache_dir": str(self.cache.cache_dir),
            "total_cached": self.cache.metadata.get("total_entries", 0),
            "last_update": self.cache.metadata.get("last_update")
        }
