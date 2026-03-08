"""
Detection Result Types Module

Provides type-safe, immutable data structures for representing security detection
outcomes. Implements a comprehensive threat classification system with severity
levels, attack types, and evidence collection.

Design Principles:
    - Immutability: DetectionResult cannot be modified after creation, ensuring
      result integrity throughout the processing pipeline.
    - Type Safety: Uses Enum for all categorical values instead of raw strings,
      preventing invalid values and enabling IDE autocomplete.
    - Extensibility: New fields can be added without breaking existing code
      through the builder pattern and copy methods.
    - Serialization: Full support for JSON and dictionary serialization for
      storage, transmission, and logging.

Key Components:
    - ThreatLevel: Severity enumeration with comparison operators
    - AttackType: Comprehensive attack categorization
    - DetectionEvidence: Immutable evidence container
    - ResultMetadata: Execution context and provenance
    - DetectionResult: Main result type with factory methods
    - DetectionResultBuilder: Fluent API for complex construction

Example Usage:
    >>> # Simple clean result
    >>> result = DetectionResult.clean(metadata=result_metadata)
    
    >>> # Threat detection with builder
    >>> result = DetectionResult.builder()
    ...     .detected(True)
    ...     .threat_level(ThreatLevel.HIGH)
    ...     .attack_type(AttackType.PROMPT_INJECTION)
    ...     .confidence(0.95)
    ...     .metadata("detector_1", "1.0.0", 42.0)
    ...     .pattern("ignore previous instructions")
    ...     .build()
    
    >>> # Serialization
    >>> json_str = result.to_json(indent=2)
    >>> restored = DetectionResult.from_json(json_str)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Self


class ThreatLevel(Enum):
    """
    Standardized threat severity enumeration.
    
    Provides five severity levels from NONE (no threat) to CRITICAL (immediate
    action required). Includes comparison operators for severity ranking and
    integer conversion for quantitative analysis.
    
    The severity hierarchy: NONE < LOW < MEDIUM < HIGH < CRITICAL
    
    Attributes:
        CRITICAL: Severe threat requiring immediate intervention
        HIGH: Significant threat with serious impact potential
        MEDIUM: Moderate threat warranting attention
        LOW: Minor threat with limited impact
        NONE: No threat detected
    
    Example:
        >>> level = ThreatLevel.HIGH
        >>> print(level.to_int())
        3
        >>> level > ThreatLevel.MEDIUM
        True
        >>> ThreatLevel.from_int(2)
        <ThreatLevel.MEDIUM: 'medium'>
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"
    
    def __str__(self) -> str:
        """Return the string value for serialization."""
        return self.value
    
    def to_int(self) -> int:
        """
        Convert to numeric level for comparison and scoring.
        
        Returns:
            Integer from 0 (NONE) to 4 (CRITICAL)
        
        Example:
            >>> ThreatLevel.CRITICAL.to_int()
            4
        """
        mapping = {
            ThreatLevel.CRITICAL: 4,
            ThreatLevel.HIGH: 3,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.LOW: 1,
            ThreatLevel.NONE: 0
        }
        return mapping[self]
    
    @classmethod
    def from_int(cls, level: int) -> ThreatLevel:
        """
        Create ThreatLevel from numeric value.
        
        Args:
            level: Integer from 0 to 4
        
        Returns:
            Corresponding ThreatLevel, defaults to NONE for invalid values
        
        Example:
            >>> ThreatLevel.from_int(3)
            <ThreatLevel.HIGH: 'high'>
        """
        mapping = {
            4: ThreatLevel.CRITICAL,
            3: ThreatLevel.HIGH,
            2: ThreatLevel.MEDIUM,
            1: ThreatLevel.LOW,
            0: ThreatLevel.NONE
        }
        return mapping.get(level, ThreatLevel.NONE)
    
    def __lt__(self, other: ThreatLevel) -> bool:
        """Less than comparison based on numeric severity."""
        return self.to_int() < other.to_int()
    
    def __le__(self, other: ThreatLevel) -> bool:
        """Less than or equal comparison."""
        return self.to_int() <= other.to_int()
    
    def __gt__(self, other: ThreatLevel) -> bool:
        """Greater than comparison."""
        return self.to_int() > other.to_int()
    
    def __ge__(self, other: ThreatLevel) -> bool:
        """Greater than or equal comparison."""
        return self.to_int() >= other.to_int()


class AttackType(Enum):
    """
    Comprehensive attack type classification.
    
    Enumerates known attack vectors against AI systems, from direct prompt
    injection to sophisticated manipulation techniques. Each attack type has
    an associated default severity level.
    
    Categories:
        Direct Injection: PROMPT_INJECTION, JAILBREAK
        Information Extraction: DATA_EXTRACTION, SYSTEM_PROMPT_LEAK
        Control Hijacking: AGENT_HIJACKING, PRIVILEGE_ESCALATION
        Tool Manipulation: TOOL_ABUSE, INDIRECT_INJECTION
        Context Attacks: CONTEXT_MANIPULATION, OUTPUT_INJECTION
        Memory Attacks: MEMORY_POISONING, KNOWLEDGE_POISONING
    
    Example:
        >>> attack = AttackType.PROMPT_INJECTION
        >>> print(attack.display_name)
        'Prompt Injection'
        >>> print(attack.severity)
        ThreatLevel.HIGH
    """
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXTRACTION = "data_extraction"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    INDIRECT_INJECTION = "indirect_injection"
    AGENT_HIJACKING = "agent_hijacking"
    TOOL_ABUSE = "tool_abuse"
    CONTEXT_MANIPULATION = "context_manipulation"
    OUTPUT_INJECTION = "output_injection"
    MEMORY_POISONING = "memory_poisoning"
    KNOWLEDGE_POISONING = "knowledge_poisoning"
    
    def __str__(self) -> str:
        """Return string value for serialization."""
        return self.value
    
    @property
    def display_name(self) -> str:
        """
        Human-readable attack type name.
        
        Returns:
            Formatted display name suitable for UI presentation.
        
        Example:
            >>> AttackType.PROMPT_INJECTION.display_name
            'Prompt Injection'
        """
        names = {
            AttackType.PROMPT_INJECTION: "Prompt Injection",
            AttackType.JAILBREAK: "Jailbreak",
            AttackType.DATA_EXTRACTION: "Data Extraction",
            AttackType.PRIVILEGE_ESCALATION: "Privilege Escalation",
            AttackType.SYSTEM_PROMPT_LEAK: "System Prompt Leak",
            AttackType.INDIRECT_INJECTION: "Indirect Injection",
            AttackType.AGENT_HIJACKING: "Agent Hijacking",
            AttackType.TOOL_ABUSE: "Tool Abuse",
            AttackType.CONTEXT_MANIPULATION: "Context Manipulation",
            AttackType.OUTPUT_INJECTION: "Output Injection",
            AttackType.MEMORY_POISONING: "Memory Poisoning",
            AttackType.KNOWLEDGE_POISONING: "Knowledge Poisoning"
        }
        return names.get(self, self.value.replace("_", " ").title())
    
    @property
    def severity(self) -> ThreatLevel:
        """
        Default severity level for this attack type.
        
        Returns:
            ThreatLevel indicating the default severity classification.
            Used when detector doesn't explicitly specify severity.
        
        Example:
            >>> AttackType.DATA_EXTRACTION.severity
            ThreatLevel.CRITICAL
            >>> AttackType.SYSTEM_PROMPT_LEAK.severity
            ThreatLevel.MEDIUM
        """
        severity_map = {
            AttackType.PROMPT_INJECTION: ThreatLevel.HIGH,
            AttackType.JAILBREAK: ThreatLevel.HIGH,
            AttackType.DATA_EXTRACTION: ThreatLevel.CRITICAL,
            AttackType.PRIVILEGE_ESCALATION: ThreatLevel.CRITICAL,
            AttackType.SYSTEM_PROMPT_LEAK: ThreatLevel.MEDIUM,
            AttackType.INDIRECT_INJECTION: ThreatLevel.MEDIUM,
            AttackType.AGENT_HIJACKING: ThreatLevel.CRITICAL,
            AttackType.TOOL_ABUSE: ThreatLevel.HIGH,
            AttackType.CONTEXT_MANIPULATION: ThreatLevel.MEDIUM,
            AttackType.OUTPUT_INJECTION: ThreatLevel.HIGH,
            AttackType.MEMORY_POISONING: ThreatLevel.CRITICAL,
            AttackType.KNOWLEDGE_POISONING: ThreatLevel.CRITICAL
        }
        return severity_map.get(self, ThreatLevel.LOW)


@dataclass(frozen=True)
class DetectionEvidence:
    """
    Immutable container for detection supporting evidence.
    
    Captures artifacts that support the detection decision, including matched
    patterns, extracted indicators of compromise (IOCs), and relevant context
    snippets. The frozen dataclass ensures evidence integrity.
    
    Attributes:
        matched_patterns: List of regex patterns or signatures that matched
        extracted_iocs: Indicators of compromise found in the input
        context_snippets: Relevant text segments providing context
    
    Example:
        >>> evidence = DetectionEvidence(
        ...     matched_patterns=[r"ignore.*previous", r"system.*prompt"],
        ...     extracted_iocs=["malicious-domain.com"],
        ...     context_snippets=["User: ignore previous instructions"]
        ... )
    """
    matched_patterns: List[str] = field(default_factory=list)
    extracted_iocs: List[str] = field(default_factory=list)
    context_snippets: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """
        Convert lists to tuples for true immutability.
        
        This ensures the evidence cannot be accidentally modified after creation,
        maintaining forensic integrity of detection results.
        """
        object.__setattr__(self, 'matched_patterns', tuple(self.matched_patterns))
        object.__setattr__(self, 'extracted_iocs', tuple(self.extracted_iocs))
        object.__setattr__(self, 'context_snippets', tuple(self.context_snippets))
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization.
        
        Returns:
            Dictionary with list values (converting from internal tuples).
        """
        return {
            "matched_patterns": list(self.matched_patterns),
            "extracted_iocs": list(self.extracted_iocs),
            "context_snippets": list(self.context_snippets)
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DetectionEvidence:
        """
        Create instance from dictionary.
        
        Args:
            data: Dictionary with evidence fields
        
        Returns:
            New DetectionEvidence instance
        """
        return cls(
            matched_patterns=data.get("matched_patterns", []),
            extracted_iocs=data.get("extracted_iocs", []),
            context_snippets=data.get("context_snippets", [])
        )
    
    def with_patterns(self, patterns: List[str]) -> DetectionEvidence:
        """
        Create new instance with additional patterns (immutable update).
        
        Args:
            patterns: Patterns to append to existing ones
        
        Returns:
            New DetectionEvidence with combined patterns
        """
        return DetectionEvidence(
            matched_patterns=list(self.matched_patterns) + patterns,
            extracted_iocs=list(self.extracted_iocs),
            context_snippets=list(self.context_snippets)
        )
    
    def with_iocs(self, iocs: List[str]) -> DetectionEvidence:
        """
        Create new instance with additional IOCs (immutable update).
        
        Args:
            iocs: IOCs to append to existing ones
        
        Returns:
            New DetectionEvidence with combined IOCs
        """
        return DetectionEvidence(
            matched_patterns=list(self.matched_patterns),
            extracted_iocs=list(self.extracted_iocs) + iocs,
            context_snippets=list(self.context_snippets)
        )


@dataclass(frozen=True)
class ResultMetadata:
    """
    Immutable metadata about detection execution.
    
    Captures provenance information including detector identification,
    version, and performance metrics. Essential for audit trails and
    debugging.
    
    Attributes:
        detector_id: Unique identifier of the detecting component
        detector_version: Version string of the detector
        processing_time_ms: Execution duration in milliseconds
        additional_info: Optional extra metadata as key-value pairs
    
    Example:
        >>> metadata = ResultMetadata(
        ...     detector_id="prompt_injection_v2",
        ...     detector_version="2.1.0",
        ...     processing_time_ms=42.5,
        ...     additional_info={"model": "transformer-v3"}
        ... )
    """
    detector_id: str
    detector_version: str
    processing_time_ms: float
    additional_info: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "processing_time_ms": self.processing_time_ms,
            "additional_info": self.additional_info
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ResultMetadata:
        """Create instance from dictionary."""
        return cls(
            detector_id=data["detector_id"],
            detector_version=data["detector_version"],
            processing_time_ms=data["processing_time_ms"],
            additional_info=data.get("additional_info", {})
        )


@dataclass(frozen=True)
class DetectionResult:
    """
    Immutable detection result with comprehensive threat information.
    
    The primary data structure for representing security analysis outcomes.
    Uses frozen dataclass to ensure result integrity and prevent accidental
    modification after creation.
    
    Design Principles:
        - Immutability: Results are facts that shouldn't change post-creation
        - Type Safety: All fields have explicit types; enums prevent invalid values
        - Validation: __post_init__ enforces consistency (detected flag aligns
          with threat_level and attack_types)
        - Usability: Factory methods for common creation patterns
    
    Attributes:
        detected: Boolean indicating if any threat was found
        threat_level: Overall severity classification
        attack_types: List of identified attack categories
        confidence: Detection confidence score [0.0, 1.0]
        evidence: Supporting evidence for the detection
        metadata: Execution provenance and performance data
        timestamp: When the detection occurred
    
    Raises:
        ValueError: If confidence outside [0.0, 1.0], or if detected=False
                   but threat_level != NONE or attack_types non-empty
    
    Example:
        >>> result = DetectionResult(
        ...     detected=True,
        ...     threat_level=ThreatLevel.HIGH,
        ...     attack_types=[AttackType.PROMPT_INJECTION],
        ...     confidence=0.95,
        ...     evidence=DetectionEvidence(),
        ...     metadata=ResultMetadata("detector_1", "1.0.0", 42.0),
        ...     timestamp=datetime.now()
        ... )
        >>> print(result)
        [🚨 DETECTED] HIGH | Attacks: Prompt Injection | Confidence: 95.00%
    """
    detected: bool
    threat_level: ThreatLevel
    attack_types: List[AttackType]
    confidence: float
    evidence: DetectionEvidence
    metadata: ResultMetadata
    timestamp: datetime
    
    def __post_init__(self):
        """
        Validate result consistency and enforce immutability.
        
        Validates:
            1. Confidence is within [0.0, 1.0]
            2. If detected=False, threat_level must be NONE
            3. If detected=False, attack_types must be empty
        
        Also converts attack_types to tuple for immutability.
        
        Raises:
            ValueError: If any validation check fails
        """
        # Validate confidence range for statistical validity
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"confidence must be between 0.0 and 1.0, got {self.confidence}"
            )
        
        # Convert to tuple for immutability
        object.__setattr__(self, 'attack_types', tuple(self.attack_types))
        
        # Enforce logical consistency: no detection means no threat
        if not self.detected and self.threat_level != ThreatLevel.NONE:
            raise ValueError(
                "If detected is False, threat_level must be NONE"
            )
        
        # Enforce logical consistency: no detection means no attack types
        if not self.detected and len(self.attack_types) > 0:
            raise ValueError(
                "If detected is False, attack_types must be empty"
            )
    
    def __bool__(self) -> bool:
        """
        Boolean evaluation for convenient truthiness checks.
        
        Returns:
            Value of detected attribute
        
        Example:
            >>> if result:  # True if detected
            ...     print("Threat found!")
        """
        return self.detected
    
    def __str__(self) -> str:
        """
        Human-readable representation with visual indicators.
        
        Returns:
            Formatted string showing status, severity, attacks, and confidence
        """
        status = "🚨 DETECTED" if self.detected else "✅ CLEAN"
        attacks = ", ".join(at.display_name for at in self.attack_types) if self.attack_types else "None"
        return f"[{status}] {self.threat_level.value.upper()} | Attacks: {attacks} | Confidence: {self.confidence:.2%}"
    
    # ========================================================================
    # Serialization Methods
    # ========================================================================
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for JSON serialization.
        
        Returns:
            Dictionary with all fields serialized to primitive types
        """
        return {
            "detected": self.detected,
            "threat_level": self.threat_level.value,
            "attack_types": [at.value for at in self.attack_types],
            "confidence": self.confidence,
            "evidence": self.evidence.to_dict(),
            "metadata": self.metadata.to_dict(),
            "timestamp": self.timestamp.isoformat()
        }
    
    def to_json(self, indent: Optional[int] = None) -> str:
        """
        Convert to JSON string.
        
        Args:
            indent: Indentation level for pretty printing
        
        Returns:
            JSON string representation
        """
        return json.dumps(self.to_dict(), indent=indent)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DetectionResult:
        """
        Create instance from dictionary.
        
        Args:
            data: Dictionary with serialized detection result
        
        Returns:
            New DetectionResult instance
        """
        return cls(
            detected=data["detected"],
            threat_level=ThreatLevel(data["threat_level"]),
            attack_types=[AttackType(at) for at in data.get("attack_types", [])],
            confidence=data["confidence"],
            evidence=DetectionEvidence.from_dict(data["evidence"]),
            metadata=ResultMetadata.from_dict(data["metadata"]),
            timestamp=datetime.fromisoformat(data["timestamp"])
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> DetectionResult:
        """
        Create instance from JSON string.
        
        Args:
            json_str: JSON serialized detection result
        
        Returns:
            New DetectionResult instance
        """
        return cls.from_dict(json.loads(json_str))
    
    # ========================================================================
    # Factory Methods
    # ========================================================================
    
    @classmethod
    def clean(
        cls,
        metadata: ResultMetadata,
        confidence: float = 1.0,
        timestamp: Optional[datetime] = None
    ) -> DetectionResult:
        """
        Factory method for creating "no threat detected" results.
        
        Args:
            metadata: Execution metadata
            confidence: Confidence in the clean assessment (default 1.0)
            timestamp: Detection timestamp (default now)
        
        Returns:
            DetectionResult with detected=False and threat_level=NONE
        
        Example:
            >>> result = DetectionResult.clean(
            ...     metadata=ResultMetadata("detector_1", "1.0.0", 42.0)
            ... )
        """
        return cls(
            detected=False,
            threat_level=ThreatLevel.NONE,
            attack_types=[],
            confidence=confidence,
            evidence=DetectionEvidence(),
            metadata=metadata,
            timestamp=timestamp or datetime.now()
        )
    
    @classmethod
    def threat(
        cls,
        attack_type: AttackType,
        metadata: ResultMetadata,
        threat_level: Optional[ThreatLevel] = None,
        confidence: float = 0.9,
        evidence: Optional[DetectionEvidence] = None,
        timestamp: Optional[datetime] = None
    ) -> DetectionResult:
        """
        Factory method for creating single-threat results.
        
        Args:
            attack_type: The detected attack type
            metadata: Execution metadata
            threat_level: Severity (defaults to attack_type.severity)
            confidence: Detection confidence
            evidence: Supporting evidence
            timestamp: Detection timestamp (default now)
        
        Returns:
            DetectionResult with single attack type
        
        Example:
            >>> result = DetectionResult.threat(
            ...     attack_type=AttackType.PROMPT_INJECTION,
            ...     metadata=ResultMetadata("detector_1", "1.0.0", 42.0)
            ... )
        """
        return cls(
            detected=True,
            threat_level=threat_level or attack_type.severity,
            attack_types=[attack_type],
            confidence=confidence,
            evidence=evidence or DetectionEvidence(),
            metadata=metadata,
            timestamp=timestamp or datetime.now()
        )
    
    @classmethod
    def critical(
        cls,
        attack_types: List[AttackType],
        metadata: ResultMetadata,
        confidence: float = 0.95,
        evidence: Optional[DetectionEvidence] = None,
        timestamp: Optional[datetime] = None
    ) -> DetectionResult:
        """
        Factory method for creating critical severity results.
        
        Args:
            attack_types: List of detected attack types
            metadata: Execution metadata
            confidence: Detection confidence (default 0.95)
            evidence: Supporting evidence
            timestamp: Detection timestamp (default now)
        
        Returns:
            DetectionResult with CRITICAL threat level
        
        Example:
            >>> result = DetectionResult.critical(
            ...     attack_types=[AttackType.DATA_EXTRACTION, AttackType.AGENT_HIJACKING],
            ...     metadata=ResultMetadata("detector_1", "1.0.0", 100.0)
            ... )
        """
        return cls(
            detected=True,
            threat_level=ThreatLevel.CRITICAL,
            attack_types=attack_types,
            confidence=confidence,
            evidence=evidence or DetectionEvidence(),
            metadata=metadata,
            timestamp=timestamp or datetime.now()
        )
    
    # ========================================================================
    # Query Methods
    # ========================================================================
    
    def is_critical(self) -> bool:
        """
        Check if this is a critical severity threat.
        
        Returns:
            True if detected and threat_level is CRITICAL
        """
        return self.detected and self.threat_level == ThreatLevel.CRITICAL
    
    def is_high_or_above(self) -> bool:
        """
        Check if this is high severity or worse.
        
        Returns:
            True if detected and threat_level >= HIGH
        """
        return self.detected and self.threat_level >= ThreatLevel.HIGH
    
    def has_attack_type(self, attack_type: AttackType) -> bool:
        """
        Check if specific attack type was detected.
        
        Args:
            attack_type: AttackType to check for
        
        Returns:
            True if attack_type is in attack_types list
        """
        return attack_type in self.attack_types
    
    def get_primary_attack(self) -> Optional[AttackType]:
        """
        Get the primary (first) attack type.
        
        Returns:
            First attack type in list, or None if no attacks detected
        """
        return self.attack_types[0] if self.attack_types else None
    
    def get_severity_score(self) -> float:
        """
        Calculate composite severity score from 0.0 to 10.0.
        
        Formula: threat_level_numeric * 2.0 + confidence * 2.0
        
        This provides a continuous severity metric useful for prioritization
        and alerting thresholds.
        
        Returns:
            Float severity score in range [0.0, 10.0]
        
        Example:
            >>> result.get_severity_score()
            7.8  # HIGH (3) * 2 + 0.9 confidence * 2
        """
        if not self.detected:
            return 0.0
        return self.threat_level.to_int() * 2.0 + self.confidence * 2.0
    
    # ========================================================================
    # Builder Pattern
    # ========================================================================
    
    @classmethod
    def builder(cls) -> DetectionResultBuilder:
        """
        Get a builder for constructing complex results.
        
        Returns:
            DetectionResultBuilder for fluent API construction
        
        Example:
            >>> result = DetectionResult.builder()
            ...     .detected(True)
            ...     .threat_level(ThreatLevel.HIGH)
            ...     .attack_type(AttackType.PROMPT_INJECTION)
            ...     .confidence(0.95)
            ...     .metadata("detector_1", "1.0.0", 42.0)
            ...     .build()
        """
        return DetectionResultBuilder()
    
    def copy_with(
        self,
        detected: Optional[bool] = None,
        threat_level: Optional[ThreatLevel] = None,
        attack_types: Optional[List[AttackType]] = None,
        confidence: Optional[float] = None,
        evidence: Optional[DetectionEvidence] = None,
        metadata: Optional[ResultMetadata] = None,
        timestamp: Optional[datetime] = None
    ) -> DetectionResult:
        """
        Create modified copy with specified changes (immutable update).
        
        All parameters default to current values, allowing selective updates.
        
        Args:
            detected: New detected status
            threat_level: New threat level
            attack_types: New attack types list
            confidence: New confidence score
            evidence: New evidence object
            metadata: New metadata object
            timestamp: New timestamp
        
        Returns:
            New DetectionResult with specified changes applied
        
        Example:
            >>> # Increase confidence while preserving everything else
            >>> new_result = result.copy_with(confidence=0.99)
        """
        return DetectionResult(
            detected=detected if detected is not None else self.detected,
            threat_level=threat_level if threat_level is not None else self.threat_level,
            attack_types=attack_types if attack_types is not None else list(self.attack_types),
            confidence=confidence if confidence is not None else self.confidence,
            evidence=evidence if evidence is not None else self.evidence,
            metadata=metadata if metadata is not None else self.metadata,
            timestamp=timestamp if timestamp is not None else self.timestamp
        )


class DetectionResultBuilder:
    """
    Fluent builder for constructing DetectionResult instances.
    
    Provides a chainable API for building complex detection results with
    many optional fields. Useful when constructing results incrementally
    or with conditional fields.
    
    Example:
        >>> result = DetectionResult.builder()
        ...     .detected(True)
        ...     .threat_level(ThreatLevel.HIGH)
        ...     .attack_type(AttackType.PROMPT_INJECTION)
        ...     .attack_type(AttackType.JAILBREAK)
        ...     .confidence(0.95)
        ...     .metadata("my_detector", "2.0.0", 42.0)
        ...     .pattern("matched_regex_1")
        ...     .pattern("matched_regex_2")
        ...     .ioc("suspicious-domain.com")
        ...     .build()
    """
    
    def __init__(self):
        """Initialize builder with default values."""
        self._detected: bool = False
        self._threat_level: ThreatLevel = ThreatLevel.NONE
        self._attack_types: List[AttackType] = []
        self._confidence: float = 1.0
        self._evidence: DetectionEvidence = DetectionEvidence()
        self._metadata: Optional[ResultMetadata] = None
        self._timestamp: datetime = datetime.now()
        self._patterns: List[str] = []
        self._iocs: List[str] = []
        self._snippets: List[str] = []
    
    def detected(self, value: bool) -> Self:
        """Set detection status."""
        self._detected = value
        return self
    
    def threat_level(self, level: ThreatLevel) -> Self:
        """Set threat severity level."""
        self._threat_level = level
        return self
    
    def attack_type(self, attack_type: AttackType) -> Self:
        """Add an attack type (can be called multiple times)."""
        self._attack_types.append(attack_type)
        return self
    
    def attack_types(self, attack_types: List[AttackType]) -> Self:
        """Set complete attack types list."""
        self._attack_types = list(attack_types)
        return self
    
    def confidence(self, value: float) -> Self:
        """Set confidence score [0.0, 1.0]."""
        self._confidence = value
        return self
    
    def metadata(
        self,
        detector_id: str,
        detector_version: str,
        processing_time_ms: float,
        **additional_info
    ) -> Self:
        """Set execution metadata."""
        self._metadata = ResultMetadata(
            detector_id=detector_id,
            detector_version=detector_version,
            processing_time_ms=processing_time_ms,
            additional_info=additional_info
        )
        return self
    
    def pattern(self, pattern: str) -> Self:
        """Add a matched pattern (can be called multiple times)."""
        self._patterns.append(pattern)
        return self
    
    def patterns(self, patterns: List[str]) -> Self:
        """Set complete patterns list."""
        self._patterns = list(patterns)
        return self
    
    def ioc(self, ioc: str) -> Self:
        """Add an IOC (can be called multiple times)."""
        self._iocs.append(ioc)
        return self
    
    def iocs(self, iocs: List[str]) -> Self:
        """Set complete IOCs list."""
        self._iocs = list(iocs)
        return self
    
    def snippet(self, snippet: str) -> Self:
        """Add a context snippet (can be called multiple times)."""
        self._snippets.append(snippet)
        return self
    
    def snippets(self, snippets: List[str]) -> Self:
        """Set complete snippets list."""
        self._snippets = list(snippets)
        return self
    
    def evidence(self, evidence: DetectionEvidence) -> Self:
        """Set evidence object directly (resets accumulated patterns/IOCs)."""
        self._evidence = evidence
        self._patterns = []
        self._iocs = []
        self._snippets = []
        return self
    
    def timestamp(self, timestamp: datetime) -> Self:
        """Set detection timestamp."""
        self._timestamp = timestamp
        return self
    
    def build(self) -> DetectionResult:
        """
        Build the DetectionResult instance.
        
        Raises:
            ValueError: If metadata was not set
        
        Returns:
            Constructed DetectionResult
        """
        if self._metadata is None:
            raise ValueError("metadata is required. Call metadata() before build()")
        
        # Build evidence from accumulated components if any were provided
        if self._patterns or self._iocs or self._snippets:
            evidence = DetectionEvidence(
                matched_patterns=self._patterns,
                extracted_iocs=self._iocs,
                context_snippets=self._snippets
            )
        else:
            evidence = self._evidence
        
        return DetectionResult(
            detected=self._detected,
            threat_level=self._threat_level,
            attack_types=self._attack_types,
            confidence=self._confidence,
            evidence=evidence,
            metadata=self._metadata,
            timestamp=self._timestamp
        )
    
    def build_clean(self, detector_id: str, detector_version: str) -> DetectionResult:
        """
        Quick builder for "no threat" results.
        
        Args:
            detector_id: Detector identifier
            detector_version: Detector version
        
        Returns:
            DetectionResult with detected=False
        """
        return DetectionResult.clean(
            metadata=ResultMetadata(
                detector_id=detector_id,
                detector_version=detector_version,
                processing_time_ms=0.0
            ),
            timestamp=self._timestamp
        )
    
    def build_threat(
        self,
        attack_type: AttackType,
        detector_id: str,
        detector_version: str,
        processing_time_ms: float = 0.0
    ) -> DetectionResult:
        """
        Quick builder for threat results.
        
        Args:
            attack_type: Type of attack detected
            detector_id: Detector identifier
            detector_version: Detector version
            processing_time_ms: Execution time
        
        Returns:
            DetectionResult with detected=True
        """
        return DetectionResult.threat(
            attack_type=attack_type,
            metadata=ResultMetadata(
                detector_id=detector_id,
                detector_version=detector_version,
                processing_time_ms=processing_time_ms
            ),
            confidence=self._confidence,
            evidence=DetectionEvidence(
                matched_patterns=self._patterns,
                extracted_iocs=self._iocs,
                context_snippets=self._snippets
            ),
            timestamp=self._timestamp
        )


# ============================================================================
# Aggregation Utilities
# ============================================================================

def merge_results(results: List[DetectionResult]) -> DetectionResult:
    """
    Merge multiple detection results into a single aggregate.
    
    Aggregation Rules:
        - detected: True if ANY result detected a threat
        - threat_level: HIGHEST severity among all results
        - attack_types: UNION of all attack types (deduplicated)
        - confidence: AVERAGE of all confidence scores
        - evidence: COMBINED evidence from all results
        - metadata/timestamp: From first result (arbitrary choice)
    
    Args:
        results: List of DetectionResult to merge
    
    Returns:
        Single DetectionResult representing the aggregate
    
    Raises:
        ValueError: If results list is empty
    
    Example:
        >>> merged = merge_results([result1, result2, result3])
        >>> if merged.is_high_or_above():
        ...     alert_security_team(merged)
    """
    if not results:
        raise ValueError("Cannot merge empty list of results")
    
    if len(results) == 1:
        return results[0]
    
    # Aggregate detection status - any positive is a positive
    detected = any(r.detected for r in results)
    
    if not detected:
        # If all clean, return first one (they're all equivalent)
        return results[0]
    
    # Take highest threat level for worst-case assessment
    max_threat = max(r.threat_level for r in results if r.detected)
    
    # Merge attack types, preserving order and removing duplicates
    all_attacks = []
    seen = set()
    for r in results:
        for at in r.attack_types:
            if at not in seen:
                all_attacks.append(at)
                seen.add(at)
    
    # Average confidence for aggregate certainty
    avg_confidence = sum(r.confidence for r in results) / len(results)
    
    # Combine all evidence
    all_patterns = []
    all_iocs = []
    all_snippets = []
    for r in results:
        all_patterns.extend(r.evidence.matched_patterns)
        all_iocs.extend(r.evidence.extracted_iocs)
        all_snippets.extend(r.evidence.context_snippets)
    
    # Use first result's metadata as representative
    return DetectionResult(
        detected=True,
        threat_level=max_threat,
        attack_types=all_attacks,
        confidence=avg_confidence,
        evidence=DetectionEvidence(
            matched_patterns=all_patterns,
            extracted_iocs=all_iocs,
            context_snippets=all_snippets
        ),
        metadata=results[0].metadata,
        timestamp=results[0].timestamp
    )


def get_highest_threat(results: List[DetectionResult]) -> Optional[DetectionResult]:
    """
    Find the result with highest threat level.
    
    Useful for identifying the most severe finding when multiple detectors
    have analyzed the same input.
    
    Args:
        results: List of DetectionResult to search
    
    Returns:
        Result with highest threat level, or None if no threats or empty list
    
    Example:
        >>> worst = get_highest_threat(detector_results)
        >>> if worst:
        ...     print(f"Most severe: {worst.threat_level}")
    """
    if not results:
        return None
    
    # Filter to only detected threats
    detected_results = [r for r in results if r.detected]
    if not detected_results:
        return None
    
    # Return result with maximum threat level
    return max(detected_results, key=lambda r: r.threat_level.to_int())


# ============================================================================
# Backward Compatibility Aliases
# ============================================================================

# Legacy names for compatibility with existing code
DetectorResult = DetectionResult
ThreatSeverity = ThreatLevel
