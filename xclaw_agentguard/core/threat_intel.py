"""
Threat Intelligence Module - IP/Domain/Hash Query Interface

This module provides a unified interface for querying threat intelligence
data including IP addresses, domains, and file hashes. Currently returns
mock data for development and testing purposes.

TODO: Integrate with actual threat intelligence feeds:
- VirusTotal API
- AbuseIPDB
- AlienVault OTX
- MISP
- Custom threat feeds
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
from enum import Enum
from datetime import datetime


class ThreatType(Enum):
    """Types of threat indicators."""
    MALWARE = "malware"
    PHISHING = "phishing"
    SPAM = "spam"
    BOTNET = "botnet"
    SCANNER = "scanner"
    EXPLOIT = "exploit"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class ReputationScore(Enum):
    """Reputation score classifications."""
    CLEAN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class ThreatIntelResult:
    """
    Result of a threat intelligence query.
    
    Attributes:
        indicator: The queried indicator (IP, domain, or hash)
        indicator_type: Type of indicator ('ip', 'domain', 'hash')
        is_malicious: Whether the indicator is flagged as malicious
        reputation_score: Numerical reputation score (0-100, lower is worse)
        threat_types: List of threat classifications
        first_seen: When the indicator was first observed as malicious
        last_seen: When the indicator was last observed
        sources: List of threat intelligence sources that flagged this
        details: Additional details from the query
        raw_data: Raw response data from the source
        query_time: Timestamp of the query
        cached: Whether this result was from cache
    """
    indicator: str
    indicator_type: str
    is_malicious: bool = False
    reputation_score: int = 50
    threat_types: List[ThreatType] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    sources: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    raw_data: Optional[Dict[str, Any]] = None
    query_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    cached: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            'indicator': self.indicator,
            'indicator_type': self.indicator_type,
            'is_malicious': self.is_malicious,
            'reputation_score': self.reputation_score,
            'threat_types': [t.value for t in self.threat_types],
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'sources': self.sources,
            'details': self.details,
            'query_time': self.query_time,
            'cached': self.cached,
        }


class ThreatIntelProvider:
    """
    Threat Intelligence Provider - Unified query interface.
    
    This class provides a standardized interface for querying threat
    intelligence data. Currently returns mock data for development.
    
    Future integrations:
    - VirusTotal API v3
    - AbuseIPDB API v2
    - AlienVault OTX API
    - MISP API
    - Custom internal feeds
    """
    
    # Mock data for development/testing
    MOCK_MALICIOUS_IPS = {
        '192.168.1.100': {
            'reputation_score': 15,
            'threat_types': [ThreatType.MALWARE, ThreatType.BOTNET],
            'sources': ['mock_feed_1', 'mock_feed_2'],
        },
        '10.0.0.50': {
            'reputation_score': 25,
            'threat_types': [ThreatType.PHISHING],
            'sources': ['mock_feed_1'],
        },
    }
    
    MOCK_MALICIOUS_DOMAINS = {
        'phishing-example.com': {
            'reputation_score': 10,
            'threat_types': [ThreatType.PHISHING, ThreatType.MALWARE],
            'sources': ['mock_phishing_feed'],
        },
        'malware-site.ru': {
            'reputation_score': 5,
            'threat_types': [ThreatType.MALWARE],
            'sources': ['mock_malware_feed'],
        },
    }
    
    MOCK_MALICIOUS_HASHES = {
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': {
            'reputation_score': 0,
            'threat_types': [ThreatType.MALWARE],
            'sources': ['mock_hash_feed'],
            'file_name': 'malicious.exe',
        },
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the threat intelligence provider.
        
        Args:
            config: Configuration dictionary with optional settings:
                - cache_enabled: Whether to cache results (default: True)
                - cache_ttl: Cache time-to-live in seconds (default: 3600)
                - api_keys: Dict of API keys for various services
                - timeout: Request timeout in seconds (default: 30)
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.cache_enabled = self.config.get('cache_enabled', True)
        self.cache_ttl = self.config.get('cache_ttl', 3600)
        self.timeout = self.config.get('timeout', 30)
        self._cache: Dict[str, Dict[str, Any]] = {}
    
    def query_ip(self, ip_address: str, context: Optional[Dict[str, Any]] = None) -> ThreatIntelResult:
        """
        Query threat intelligence for an IP address.
        
        Args:
            ip_address: The IP address to query
            context: Optional context (source logs, timeframe, etc.)
            
        Returns:
            ThreatIntelResult with threat assessment
            
        TODO: Implement actual API integration:
            - VirusTotal IP lookup
            - AbuseIPDB check
            - AlienVault OTX pulses
        """
        self.logger.debug(f"Querying threat intel for IP: {ip_address}")
        
        # Check cache
        cache_key = f"ip:{ip_address}"
        if self.cache_enabled and self._is_cached(cache_key):
            return self._get_cached_result(cache_key, ip_address, 'ip')
        
        # Mock implementation - check against mock data
        mock_data = self.MOCK_MALICIOUS_IPS.get(ip_address, {})
        
        if mock_data:
            result = ThreatIntelResult(
                indicator=ip_address,
                indicator_type='ip',
                is_malicious=True,
                reputation_score=mock_data['reputation_score'],
                threat_types=mock_data['threat_types'],
                sources=mock_data['sources'],
                first_seen='2024-01-01T00:00:00Z',
                last_seen=datetime.utcnow().isoformat(),
                details={'query_source': 'mock_feed', 'confidence': 'high'},
            )
        else:
            # Return clean result for unknown IPs
            result = ThreatIntelResult(
                indicator=ip_address,
                indicator_type='ip',
                is_malicious=False,
                reputation_score=80,
                threat_types=[],
                sources=['mock_feed'],
                details={'query_source': 'mock_feed', 'confidence': 'medium'},
            )
        
        # Cache result
        if self.cache_enabled:
            self._cache_result(cache_key, result)
        
        return result
    
    def query_domain(self, domain: str, context: Optional[Dict[str, Any]] = None) -> ThreatIntelResult:
        """
        Query threat intelligence for a domain.
        
        Args:
            domain: The domain to query
            context: Optional context (referrer, user_agent, etc.)
            
        Returns:
            ThreatIntelResult with threat assessment
            
        TODO: Implement actual API integration:
            - VirusTotal domain lookup
            - URLScan.io analysis
            - Google Safe Browsing API
        """
        self.logger.debug(f"Querying threat intel for domain: {domain}")
        
        # Check cache
        cache_key = f"domain:{domain}"
        if self.cache_enabled and self._is_cached(cache_key):
            return self._get_cached_result(cache_key, domain, 'domain')
        
        # Mock implementation - check against mock data
        mock_data = self.MOCK_MALICIOUS_DOMAINS.get(domain.lower(), {})
        
        if mock_data:
            result = ThreatIntelResult(
                indicator=domain,
                indicator_type='domain',
                is_malicious=True,
                reputation_score=mock_data['reputation_score'],
                threat_types=mock_data['threat_types'],
                sources=mock_data['sources'],
                first_seen='2024-01-01T00:00:00Z',
                last_seen=datetime.utcnow().isoformat(),
                details={'query_source': 'mock_feed', 'confidence': 'high'},
            )
        else:
            # Return clean result for unknown domains
            result = ThreatIntelResult(
                indicator=domain,
                indicator_type='domain',
                is_malicious=False,
                reputation_score=75,
                threat_types=[],
                sources=['mock_feed'],
                details={'query_source': 'mock_feed', 'confidence': 'medium'},
            )
        
        # Cache result
        if self.cache_enabled:
            self._cache_result(cache_key, result)
        
        return result
    
    def query_hash(self, file_hash: str, hash_type: str = 'sha256', 
                   context: Optional[Dict[str, Any]] = None) -> ThreatIntelResult:
        """
        Query threat intelligence for a file hash.
        
        Args:
            file_hash: The file hash to query
            hash_type: Type of hash ('md5', 'sha1', 'sha256')
            context: Optional context (file source, user, etc.)
            
        Returns:
            ThreatIntelResult with threat assessment
            
        TODO: Implement actual API integration:
            - VirusTotal file lookup
            - MalwareBazaar
            - Hybrid Analysis
        """
        self.logger.debug(f"Querying threat intel for hash: {file_hash}")
        
        # Check cache
        cache_key = f"hash:{hash_type}:{file_hash}"
        if self.cache_enabled and self._is_cached(cache_key):
            return self._get_cached_result(cache_key, file_hash, 'hash')
        
        # Mock implementation - check against mock data
        mock_data = self.MOCK_MALICIOUS_HASHES.get(file_hash.lower(), {})
        
        if mock_data:
            result = ThreatIntelResult(
                indicator=file_hash,
                indicator_type='hash',
                is_malicious=True,
                reputation_score=mock_data['reputation_score'],
                threat_types=mock_data['threat_types'],
                sources=mock_data['sources'],
                first_seen='2024-01-01T00:00:00Z',
                last_seen=datetime.utcnow().isoformat(),
                details={
                    'query_source': 'mock_feed',
                    'confidence': 'high',
                    'file_name': mock_data.get('file_name', 'unknown'),
                    'hash_type': hash_type,
                },
            )
        else:
            # Return clean result for unknown hashes
            result = ThreatIntelResult(
                indicator=file_hash,
                indicator_type='hash',
                is_malicious=False,
                reputation_score=85,
                threat_types=[],
                sources=['mock_feed'],
                details={'query_source': 'mock_feed', 'confidence': 'medium', 'hash_type': hash_type},
            )
        
        # Cache result
        if self.cache_enabled:
            self._cache_result(cache_key, result)
        
        return result
    
    def batch_query(self, indicators: List[Dict[str, str]]) -> List[ThreatIntelResult]:
        """
        Query multiple indicators in batch.
        
        Args:
            indicators: List of dicts with 'indicator' and 'type' keys
                Example: [{'indicator': '1.2.3.4', 'type': 'ip'}, ...]
                
        Returns:
            List of ThreatIntelResult objects
        """
        results = []
        for item in indicators:
            indicator = item.get('indicator', '')
            indicator_type = item.get('type', '').lower()
            
            if indicator_type == 'ip':
                results.append(self.query_ip(indicator))
            elif indicator_type == 'domain':
                results.append(self.query_domain(indicator))
            elif indicator_type == 'hash':
                hash_type = item.get('hash_type', 'sha256')
                results.append(self.query_hash(indicator, hash_type))
            else:
                self.logger.warning(f"Unknown indicator type: {indicator_type}")
                results.append(ThreatIntelResult(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    is_malicious=False,
                    details={'error': f'Unknown indicator type: {indicator_type}'},
                ))
        
        return results
    
    def clear_cache(self) -> None:
        """Clear the result cache."""
        self._cache.clear()
        self.logger.debug("Threat intel cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            'cache_enabled': self.cache_enabled,
            'cached_items': len(self._cache),
            'cache_ttl': self.cache_ttl,
        }
    
    def _is_cached(self, key: str) -> bool:
        """Check if a key is in cache and not expired."""
        if key not in self._cache:
            return False
        
        entry = self._cache[key]
        age = (datetime.utcnow() - datetime.fromisoformat(entry['timestamp'])).total_seconds()
        
        if age > self.cache_ttl:
            del self._cache[key]
            return False
        
        return True
    
    def _get_cached_result(self, key: str, indicator: str, indicator_type: str) -> ThreatIntelResult:
        """Get a cached result."""
        entry = self._cache[key]
        result = entry['result']
        result.cached = True
        self.logger.debug(f"Cache hit for {key}")
        return result
    
    def _cache_result(self, key: str, result: ThreatIntelResult) -> None:
        """Cache a result."""
        self._cache[key] = {
            'result': result,
            'timestamp': datetime.utcnow().isoformat(),
        }


# Convenience functions for simple usage
def query_ip_threat_intel(ip_address: str, config: Optional[Dict[str, Any]] = None) -> ThreatIntelResult:
    """Query threat intelligence for an IP address."""
    provider = ThreatIntelProvider(config)
    return provider.query_ip(ip_address)


def query_domain_threat_intel(domain: str, config: Optional[Dict[str, Any]] = None) -> ThreatIntelResult:
    """Query threat intelligence for a domain."""
    provider = ThreatIntelProvider(config)
    return provider.query_domain(domain)


def query_hash_threat_intel(file_hash: str, hash_type: str = 'sha256',
                            config: Optional[Dict[str, Any]] = None) -> ThreatIntelResult:
    """Query threat intelligence for a file hash."""
    provider = ThreatIntelProvider(config)
    return provider.query_hash(file_hash, hash_type)


__all__ = [
    'ThreatIntelProvider',
    'ThreatIntelResult',
    'ThreatType',
    'ReputationScore',
    'query_ip_threat_intel',
    'query_domain_threat_intel',
    'query_hash_threat_intel',
]