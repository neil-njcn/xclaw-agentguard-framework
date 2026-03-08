r"""
XClaw AgentGuard Custom Rules Plugin

A flexible, configuration-driven detection plugin that enables security rules
to be defined via YAML without writing code. Ideal for security teams who need
to rapidly deploy detection patterns without Python development expertise.

Features:
    - YAML-based rule configuration (no coding required)
    - Regular expression pattern matching with automatic compilation
    - Dynamic rule management (add/remove at runtime)
    - Severity-based threat classification (low/medium/high/critical)
    - Full XClaw AgentGuard DetectionResult compatibility
    - Support for both file-based and in-memory rule definitions

Usage Scenarios:
    - SOC teams adding custom IOC (Indicator of Compromise) patterns
    - Compliance teams defining organization-specific data patterns
    - Rapid response to emerging threats without code deployment
    - Non-developer security staff creating detection rules

Rule Configuration Schema (YAML):
    rules:
      - name: "Rule Name"           # Required: Unique identifier
        pattern: "regex_pattern"    # Required: Python-compatible regex
        severity: "high"            # Optional: low|medium|high|critical (default: medium)
        description: "What it does" # Optional: Human-readable explanation
        enabled: true               # Optional: Enable/disable switch (default: true)

Example:
    >>> from xclaw_agentguard.plugins.custom_rules import CustomRulesPlugin
    >>> detector = CustomRulesPlugin.create_detector("rules.yaml")
    >>> result = detector.detect("This input matches a custom pattern")

Plugin Development Guide:
    To extend this plugin:
    1. Add new rule types by extending CustomRule dataclass
    2. Implement additional loaders (e.g., from_json, from_database)
    3. Add rule validation logic in CustomRulesDetector
    4. Consider caching strategies for high-volume detection scenarios

Author: XClaw AgentGuard Team
Version: 1.0.0
"""

import re
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from xclaw_agentguard import AntiJackExtension, DetectionResult, ThreatLevel


@dataclass
class CustomRule:
    r"""
    Represents a single detection rule with regex pattern matching.
    
    This dataclass encapsulates all metadata and compiled pattern state
    for an individual detection rule. Patterns are automatically compiled
    to regex objects during instantiation for efficient repeated matching.
    
    Attributes:
        name (str): Unique rule identifier used in match results and logging
        pattern (str): Python-compatible regular expression pattern
        severity (str): Threat severity level - "low", "medium", "high", or "critical"
        description (str): Human-readable explanation of the rule's purpose
        enabled (bool): Whether this rule is active for matching
        _compiled_pattern (Pattern): Compiled regex object (internal use only)
        
    Configuration Options:
        - severity: Controls threat level classification in DetectionResult
            "low"      → ThreatLevel.LOW
            "medium"   → ThreatLevel.MEDIUM  
            "high"     → ThreatLevel.HIGH
            "critical" → ThreatLevel.CRITICAL
            
    Pattern Tips:
        - Use raw strings for complex patterns to avoid escape sequence issues
        - Consider re.IGNORECASE behavior (always applied in this implementation)
        - Test patterns thoroughly; invalid regex raises ValueError at init time
        
    Example:
        >>> rule = CustomRule(
        ...     name="PII_SSN",
        ...     pattern=r"\b\d{3}-\d{2}-\d{4}\b",
        ...     severity="high",
        ...     description="Detects US Social Security Numbers"
        ... )
        >>> match = rule.match("My SSN is 123-45-6789")
        >>> print(match["matched_text"])
        123-45-6789
    """
    
    name: str
    pattern: str
    severity: str = "medium"
    description: str = ""
    enabled: bool = True
    
    # Compiled regex cache - excluded from repr to avoid clutter
    _compiled_pattern: Any = field(default=None, repr=False)
    
    def __post_init__(self):
        """
        Compile regex pattern after initialization.
        
        Automatically invoked by dataclass after __init__. Compiles the
        pattern string to a regex Pattern object for efficient matching.
        Disabled rules skip compilation to save resources.
        
        Raises:
            ValueError: If the pattern is invalid regex syntax
        """
        if self.enabled:
            try:
                self._compiled_pattern = re.compile(self.pattern, re.IGNORECASE)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern in rule '{self.name}': {e}")
    
    def match(self, text: str) -> Optional[Dict[str, Any]]:
        r"""
        Execute pattern match against input text.
        
        Performs a regex search (not full match) against the provided text.
        Returns structured match information if found, None otherwise.
        
        Args:
            text: The input string to search for pattern matches
            
        Returns:
            Dict containing match details if found:
                - rule_name: The rule's name attribute
                - matched_text: The actual substring that matched
                - position: Tuple of (start, end) indices in the input
                - severity: The rule's severity level
                - description: The rule's description
            None: If no match found or rule is disabled
            
        Example:
            >>> rule = CustomRule(name="test", pattern=r"hello\\s+\w+")  # noqa: W605
            >>> result = rule.match("Say hello world today")
            >>> print(result)
            {
                'rule_name': 'test',
                'matched_text': 'hello world',
                'position': (4, 15),
                'severity': 'medium',
                'description': ''
            }
        """
        if not self.enabled or not self._compiled_pattern:
            return None
        
        match = self._compiled_pattern.search(text)
        if match:
            return {
                "rule_name": self.name,
                "matched_text": match.group(0),
                "position": match.span(),
                "severity": self.severity,
                "description": self.description,
            }
        return None


class CustomRulesDetector:
    """
    Core detection engine for custom rule-based pattern matching.
    
    This class implements the full XClaw AgentGuard detector interface, allowing
    custom YAML-defined rules to integrate seamlessly with the broader
    detection ecosystem. Supports multiple rule sources and runtime modification.
    
    Attributes:
        PLUGIN_ID (str): Plugin identifier for registration ("custom_rules")
        PLUGIN_VERSION (str): Semantic version ("1.0.0")
        PLUGIN_NAME (str): Display name ("Custom Rules Detector")
        rules (List[CustomRule]): Active rule set
        
    Usage Patterns:
        1. File-based rules (production deployments):
           detector = CustomRulesDetector.from_yaml("/path/to/rules.yaml")
           
        2. Dictionary-based rules (dynamic/programmatic):
           detector = CustomRulesDetector.from_dict(rules_dict)
           
        3. Runtime rule management:
           detector.add_rule(CustomRule(...))
           detector.remove_rule("rule_name")
           
    YAML Configuration Format:
        rules:
          - name: "PII_EMAIL"
            pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
            severity: "medium"
            description: "Email address detection"
            enabled: true
            
          - name: "SUSPICIOUS_KEYWORDS"
            pattern: "(hack|exploit|backdoor|malware)"
            severity: "high"
            description: "Suspicious security keywords"
            enabled: true
            
    Example:
        >>> # Load rules from YAML
        >>> detector = CustomRulesDetector.from_yaml("security_rules.yaml")
        >>> 
        >>> # Run detection
        >>> result = detector.detect("Contact us at admin@example.com")
        >>> print(result.detected)  # True if any rule matched
        >>> print(result.threat_level)  # Severity of highest match
    """
    
    PLUGIN_ID = "custom_rules"
    PLUGIN_VERSION = "1.0.0"
    PLUGIN_NAME = "Custom Rules Detector"
    
    def __init__(self, rules: Optional[List[CustomRule]] = None):
        """
        Initialize detector with optional rule list.
        
        Args:
            rules: List of CustomRule objects. Empty list if None.
        """
        self.rules: List[CustomRule] = rules or []
    
    @classmethod
    def from_yaml(cls, yaml_path: str) -> "CustomRulesDetector":
        r"""
        Factory method: Create detector from YAML configuration file.
        
        Loads rule definitions from a YAML file and instantiates a fully
        configured detector. Invalid rules are logged as warnings but don't
        prevent other rules from loading.
        
        Args:
            yaml_path: Filesystem path to YAML configuration file
            
        Returns:
            CustomRulesDetector: Configured detector instance
            
        Raises:
            FileNotFoundError: If yaml_path does not exist
            yaml.YAMLError: If file contains invalid YAML syntax
            
        Example YAML:
            rules:
              - name: "API_KEY_PATTERN"
                pattern: "api[_-]?key\\s*[:=]\\s*['\"][a-zA-Z0-9]{32}['\"]"  # noqa: W605
                severity: "critical"
                description: "Hardcoded API key detection"
                enabled: true
                
        Example:
            >>> try:
            ...     detector = CustomRulesDetector.from_yaml("/etc/xclaw_agentguard/rules.yaml")
            ... except FileNotFoundError:
            ...     print("Rules file not found, using defaults")
        """
        path = Path(yaml_path)
        if not path.exists():
            raise FileNotFoundError(f"Rules file not found: {yaml_path}")
        
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        rules = []
        for rule_data in data.get('rules', []):
            try:
                rule = CustomRule(
                    name=rule_data['name'],
                    pattern=rule_data['pattern'],
                    severity=rule_data.get('severity', 'medium'),
                    description=rule_data.get('description', ''),
                    enabled=rule_data.get('enabled', True),
                )
                rules.append(rule)
            except (KeyError, ValueError) as e:
                print(f"Warning: Skipping invalid rule: {e}")
                continue
        
        return cls(rules=rules)
    
    @classmethod
    def from_dict(cls, rules_dict: Dict[str, Any]) -> "CustomRulesDetector":
        r"""
        Factory method: Create detector from dictionary configuration.
        
        Useful for programmatic rule generation, database-loaded rules,
        or dynamic configuration scenarios where YAML files aren't appropriate.
        
        Args:
            rules_dict: Dictionary with "rules" key containing list of rule dicts.
                       Each rule dict requires "name" and "pattern" keys;
                       optionally includes "severity", "description", "enabled".
                       
        Returns:
            CustomRulesDetector: Configured detector instance
            
        Example:
            >>> rules_config = {
            ...     "rules": [
            ...         {
            ...             "name": "PASSWORD_PATTERN",
            ...             "pattern": r"password\\s*=\\s*['\"][^'\"]+['\"]",  # noqa: W605
            ...             "severity": "high",
            ...             "description": "Hardcoded password",
            ...             "enabled": True
            ...         }
            ...     ]
            ... }
            >>> detector = CustomRulesDetector.from_dict(rules_config)
        """
        rules = []
        for rule_data in rules_dict.get('rules', []):
            try:
                rule = CustomRule(
                    name=rule_data['name'],
                    pattern=rule_data['pattern'],
                    severity=rule_data.get('severity', 'medium'),
                    description=rule_data.get('description', ''),
                    enabled=rule_data.get('enabled', True),
                )
                rules.append(rule)
            except (KeyError, ValueError) as e:
                print(f"Warning: Skipping invalid rule: {e}")
                continue
        
        return cls(rules=rules)
    
    def add_rule(self, rule: CustomRule) -> None:
        """
        Dynamically add a rule at runtime.
        
        Allows rule modification without reloading the entire configuration.
        New rules take effect immediately on subsequent detect() calls.
        
        Args:
            rule: CustomRule instance to add to the active rule set
            
        Example:
            >>> detector = CustomRulesDetector()
            >>> new_rule = CustomRule(
            ...     name="TEMP_RULE",
            ...     pattern=r"emergency.*shutdown",
            ...     severity="critical"
            ... )
            >>> detector.add_rule(new_rule)
            >>> # Rule is now active
        """
        self.rules.append(rule)
    
    def remove_rule(self, rule_name: str) -> bool:
        """
        Remove a rule by name.
        
        Searches for and removes the first rule matching the given name.
        If multiple rules share the same name, only the first is removed.
        
        Args:
            rule_name: The name attribute of the rule to remove
            
        Returns:
            bool: True if a rule was found and removed, False otherwise
            
        Example:
            >>> removed = detector.remove_rule("TEMP_RULE")
            >>> if removed:
            ...     print("Rule successfully removed")
            ... else:
            ...     print("Rule not found")
        """
        for i, rule in enumerate(self.rules):
            if rule.name == rule_name:
                self.rules.pop(i)
                return True
        return False
    
    def get_metadata(self) -> Dict[str, Any]:
        """
        Get detector metadata for introspection and monitoring.
        
        Returns:
            Dict containing:
                - id: Plugin identifier
                - name: Human-readable name
                - version: Plugin version string
                - rule_count: Total number of configured rules
                - enabled_rules: Number of currently active rules
                
        Example:
            >>> meta = detector.get_metadata()
            >>> print(f"{meta['name']} v{meta['version']}")
            >>> print(f"Active rules: {meta['enabled_rules']}/{meta['rule_count']}")
        """
        return {
            "id": self.PLUGIN_ID,
            "name": self.PLUGIN_NAME,
            "version": self.PLUGIN_VERSION,
            "rule_count": len(self.rules),
            "enabled_rules": len([r for r in self.rules if r.enabled]),
        }
    
    def custom_check(self, file_path: str, content: str = None) -> List[Dict[str, Any]]:
        """
        Run custom rules against content and return raw match data.
        
        This is an internal/low-level method that returns the raw match
        information. For standard XClaw AgentGuard integration, use detect() instead.
        
        Args:
            file_path: Path to the file being checked (used for context)
            content: The text content to scan. Empty list returned if None.
            
        Returns:
            List[Dict]: Match details for each rule that matched.
                       Empty list if no matches or no content.
                       
        Note:
            This method returns raw match dictionaries. To get a standard
            DetectionResult object compatible with other XClaw AgentGuard components,
            use the detect() method instead.
        """
        if not content:
            return []
        
        matches = []
        for rule in self.rules:
            match = rule.match(content)
            if match:
                matches.append(match)
        
        return matches
    
    def detect(self, content: str) -> DetectionResult:
        """
        Standard XClaw AgentGuard detection interface.
        
        Implements the canonical detector API, returning a DetectionResult
        that integrates with the broader XClaw AgentGuard ecosystem. Aggregates
        all rule matches and determines the highest threat level.
        
        Args:
            content: The text content to analyze
            
        Returns:
            DetectionResult: Structured result with the following properties:
                - detected: True if any rule matched
                - threat_level: Severity of highest match (or NONE if clean)
                - attack_types: Always [AttackType.PROMPT_INJECTION] for matches
                - confidence: Fixed at 0.9 (regex match certainty)
                - metadata: Includes matched_rules and detailed match info
                
        Example:
            >>> result = detector.detect("This contains PII: 123-45-6789")
            >>> if result.detected:
            ...     print(f"Threat level: {result.threat_level}")
            ...     print(f"Matched rules: {result.metadata.additional_info['matched_rules']}")
        """
        from xclaw_agentguard import DetectionResultBuilder, ThreatLevel, AttackType
        from xclaw_agentguard.core.detection_result import ResultMetadata
        
        matches = self.custom_check("", content)
        
        if not matches:
            return DetectionResultBuilder()\
                .detected(False)\
                .threat_level(ThreatLevel.NONE)\
                .metadata("custom_rules", self.PLUGIN_VERSION, 0.0)\
                .build()
        
        # Map severity strings to ThreatLevel enum values
        severity_map = {
            "low": ThreatLevel.LOW,
            "medium": ThreatLevel.MEDIUM,
            "high": ThreatLevel.HIGH,
            "critical": ThreatLevel.CRITICAL,
        }
        
        # Find the highest severity match
        severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        max_severity_match = max(matches, key=lambda m: severity_order.get(m['severity'], 1))
        
        threat_level = severity_map.get(max_severity_match['severity'], ThreatLevel.MEDIUM)
        
        # Build metadata with match details
        additional_info = {
            "matched_rules": [m['rule_name'] for m in matches],
            "matches": matches
        }
        
        return DetectionResultBuilder()\
            .detected(True)\
            .threat_level(threat_level)\
            .attack_type(AttackType.PROMPT_INJECTION)\
            .confidence(0.9)\
            .metadata("custom_rules", self.PLUGIN_VERSION, 0.0, **additional_info)\
            .build()
    
    def list_rules(self) -> List[Dict[str, Any]]:
        """
        Export all rules as a list of dictionaries.
        
        Useful for configuration management, UI displays, and serialization.
        
        Returns:
            List[Dict]: Each dict contains:
                - name: Rule identifier
                - pattern: Regex pattern string (not compiled)
                - severity: Threat level string
                - description: Human-readable explanation
                - enabled: Active status boolean
                
        Example:
            >>> for rule_info in detector.list_rules():
            ...     status = "✓" if rule_info['enabled'] else "✗"
            ...     print(f"{status} {rule_info['name']}: {rule_info['description']}")
        """
        return [
            {
                "name": rule.name,
                "pattern": rule.pattern,
                "severity": rule.severity,
                "description": rule.description,
                "enabled": rule.enabled,
            }
            for rule in self.rules
        ]


class CustomRulesPlugin:
    """
    High-level plugin interface for custom rule management.
    
    Provides static factory methods as a convenience API for users who
    prefer a plugin-centric interface over direct detector instantiation.
    This class serves as the primary entry point for plugin-based usage.
    
    Attributes:
        PLUGIN_ID (str): Plugin identifier ("custom_rules")
        PLUGIN_VERSION (str): Semantic version ("1.0.0")
        PLUGIN_NAME (str): Display name ("Custom Rules")
        
    Usage Pattern:
        >>> from xclaw_agentguard.plugins.custom_rules import CustomRulesPlugin
        >>> # Load from file
        >>> detector = CustomRulesPlugin.create_detector("/path/to/rules.yaml")
        >>> # Or from dictionary
        >>> detector = CustomRulesPlugin.create_detector_from_dict(rules_dict)
        
        >>> # Use the detector
        >>> result = detector.detect(user_input)
    """
    
    PLUGIN_ID = "custom_rules"
    PLUGIN_VERSION = "1.0.0"
    PLUGIN_NAME = "Custom Rules"
    
    @staticmethod
    def create_detector(yaml_path: str) -> CustomRulesDetector:
        """
        Create a detector from a YAML configuration file.
        
        Convenience wrapper around CustomRulesDetector.from_yaml().
        
        Args:
            yaml_path: Path to the YAML rules file
            
        Returns:
            CustomRulesDetector: Configured and ready for detection
            
        Example:
            >>> detector = CustomRulesPlugin.create_detector("rules.yaml")
        """
        return CustomRulesDetector.from_yaml(yaml_path)
    
    @staticmethod
    def create_detector_from_dict(rules_dict: Dict) -> CustomRulesDetector:
        r"""
        Create a detector from a dictionary configuration.
        
        Convenience wrapper around CustomRulesDetector.from_dict().
        
        Args:
            rules_dict: Dictionary with "rules" key containing rule definitions
            
        Returns:
            CustomRulesDetector: Configured and ready for detection
            
        Example:
            >>> detector = CustomRulesPlugin.create_detector_from_dict(config)
        """
        return CustomRulesDetector.from_dict(rules_dict)


# =============================================================================
# Convenience Functions
# =============================================================================
# These module-level functions provide a streamlined API for common operations.
# They are thin wrappers around class methods for functional-style usage.
# =============================================================================

def load_rules(yaml_path: str) -> CustomRulesDetector:
    """
    Load detection rules from a YAML file.
    
    Convenience function equivalent to:
        CustomRulesDetector.from_yaml(yaml_path)
    
    Args:
        yaml_path: Path to the YAML configuration file
        
    Returns:
        CustomRulesDetector: Configured detector instance
        
    Example:
        >>> detector = load_rules("/etc/security/rules.yaml")
        >>> result = detector.detect("Test input")
    """
    return CustomRulesDetector.from_yaml(yaml_path)


def create_rule(name: str, pattern: str, severity: str = "medium", description: str = "") -> CustomRule:
    """
    Create a single detection rule.
    
    Convenience function for programmatic rule creation without directly
    instantiating the CustomRule dataclass.
    
    Args:
        name: Unique rule identifier
        pattern: Python-compatible regular expression
        severity: Threat level - "low", "medium", "high", or "critical"
        description: Human-readable explanation of the rule
        
    Returns:
        CustomRule: Configured rule ready for use
        
    Example:
        >>> rule = create_rule(
        ...     name="API_KEY",
        ...     pattern=r"sk-[a-zA-Z0-9]{48}",
        ...     severity="critical",
        ...     description="OpenAI API key pattern"
        ... )
        >>> detector = CustomRulesDetector()
        >>> detector.add_rule(rule)
    """
    return CustomRule(
        name=name,
        pattern=pattern,
        severity=severity,
        description=description,
    )


__all__ = [
    # Main plugin class
    "CustomRulesPlugin",
    # Core detector implementation
    "CustomRulesDetector",
    # Rule definition dataclass
    "CustomRule",
    # Convenience functions
    "load_rules",
    "create_rule",
]
