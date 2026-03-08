"""
Base Detector Module

Provides the abstract base class and common infrastructure for all security detectors
in the XClaw AgentGuard framework. Implements the template method pattern to standardize
the detection workflow while allowing subclasses to define specific detection logic.

The BaseDetector class serves as the foundation for implementing attack detection
capabilities including prompt injection, jailbreak attempts, data extraction, and
other security threats against AI systems.

Design Patterns:
    - Template Method: Defines the detection workflow skeleton, subclasses implement steps
    - Strategy: AttackType enum allows pluggable attack classification
    - Data Class: DetectionResult and DetectorMetadata provide structured data containers

Example:
    >>> class SQLInjectionDetector(BaseDetector):
    ...     def detect(self, text, context=None):
    ...         # Implementation-specific detection logic
    ...         is_attack = self._check_sql_patterns(text)
    ...         confidence = 0.95 if is_attack else 0.1
    ...         return DetectionResult(
    ...             is_attack=is_attack,
    ...             confidence=confidence,
    ...             attack_type=AttackType.DATA_EXTRACTION
    ...         )
    ...     
    ...     def get_detector_id(self):
    ...         return "sql_injection_detector"
    ...     
    ...     def get_supported_attack_types(self):
    ...         return [AttackType.DATA_EXTRACTION]
    
    >>> detector = SQLInjectionDetector(config={'threshold': 0.8})
    >>> result = detector.detect_with_preprocessing("SELECT * FROM users")
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum, auto
import time


class AttackType(Enum):
    """
    Enumeration of attack types that detectors can identify.
    
    This enum standardizes attack classification across all detectors, enabling
    consistent reporting, filtering, and aggregation of security events.
    
    Attributes:
        PROMPT_INJECTION: Malicious input designed to override system instructions
        JAILBREAK: Attempts to bypass safety constraints or content policies
        DATA_EXTRACTION: Unauthorized attempts to retrieve sensitive information
        TOXICITY: Generation or propagation of harmful, offensive content
        BIAS: Systematic unfairness or discriminatory outputs
        PII_LEAKAGE: Exposure of personally identifiable information
        ADVERSARIAL: Inputs crafted to cause model misbehavior
        CUSTOM: User-defined attack categories for specialized detectors
    
    Example:
        >>> attack = AttackType.PROMPT_INJECTION
        >>> print(attack.name)
        'PROMPT_INJECTION'
    """
    PROMPT_INJECTION = auto()
    JAILBREAK = auto()
    DATA_EXTRACTION = auto()
    TOXICITY = auto()
    BIAS = auto()
    PII_LEAKAGE = auto()
    ADVERSARIAL = auto()
    CUSTOM = auto()


@dataclass
class DetectionResult:
    """
    Container for detector execution results.
    
    This dataclass captures all relevant information from a detection operation,
    including the attack determination, confidence score, classification, and
    diagnostic metadata.
    
    Attributes:
        is_attack: Boolean indicating whether an attack was detected
        confidence: Float between 0.0 and 1.0 indicating detection confidence
        attack_type: Primary attack classification (deprecated, use attack_types)
        attack_types: List of all identified attack types for multi-class detection
        details: Dictionary containing detector-specific diagnostic information
        processing_time_ms: Execution duration in milliseconds for performance tracking
        detector_id: Identifier of the detector that produced this result
        error_message: Error description if detection failed, None otherwise
    
    Example:
        >>> result = DetectionResult(
        ...     is_attack=True,
        ...     confidence=0.95,
        ...     attack_type=AttackType.PROMPT_INJECTION,
        ...     details={"matched_patterns": ["ignore previous"]},
        ...     detector_id="prompt_injection_v2"
        ... )
    """
    is_attack: bool = False
    confidence: float = 0.0
    attack_type: Optional[AttackType] = None
    attack_types: List[AttackType] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    processing_time_ms: float = 0.0
    detector_id: str = ""
    error_message: Optional[str] = None
    
    def __post_init__(self):
        """
        Post-initialization processing to maintain backward compatibility.
        
        Ensures the primary attack_type is included in the attack_types list
        for unified handling of single and multi-class detection results.
        """
        if self.attack_type and self.attack_type not in self.attack_types:
            self.attack_types.append(self.attack_type)


@dataclass
class DetectorMetadata:
    """
    Metadata describing a detector's properties and capabilities.
    
    Provides descriptive information about a detector for registry management,
    UI display, and version tracking purposes.
    
    Attributes:
        id: Unique detector identifier (lowercase_with_underscores recommended)
        name: Human-readable detector name
        version: Semantic version string (e.g., "2.3.0")
        supported_types: List of AttackType values this detector can identify
        description: Brief explanation of the detector's purpose
        author: Creator or maintainer of the detector
        created_at: ISO 8601 timestamp of detector creation
    
    Example:
        >>> metadata = DetectorMetadata(
        ...     id="prompt_injection_v2",
        ...     name="Prompt Injection Detector",
        ...     version="2.3.0",
        ...     supported_types=[AttackType.PROMPT_INJECTION],
        ...     description="Detects attempts to manipulate LLM behavior through prompt injection",
        ...     author="Security Team",
        ...     created_at="2024-01-15T10:30:00Z"
        ... )
    """
    id: str
    name: str
    version: str
    supported_types: List[AttackType]
    description: str = ""
    author: str = ""
    created_at: Optional[str] = None


class BaseDetector(ABC):
    """
    Abstract base class for all security detectors.
    
    Implements the template method pattern to provide a standardized detection
    workflow while allowing subclasses to define specific detection algorithms.
    Subclasses must implement the detect(), get_detector_id(), and
    get_supported_attack_types() methods.
    
    The detection workflow consists of:
    1. Input validation - ensures text is non-empty string
    2. Preprocessing - normalizes text (whitespace, line endings)
    3. Detection execution - subclass-specific analysis
    4. Postprocessing - applies threshold, adds metadata
    
    Attributes:
        config: Runtime configuration dictionary
        threshold: Detection threshold in range [0.0, 1.0]
    
    Class Attributes:
        VERSION: Class-level semantic version for the detector framework
    
    Example:
        >>> class MyDetector(BaseDetector):
        ...     def detect(self, text, context=None):
        ...         confidence = self._analyze(text)
        ...         return DetectionResult(
        ...             is_attack=confidence >= self.threshold,
        ...             confidence=confidence,
        ...             attack_type=AttackType.PROMPT_INJECTION
        ...         )
        ...     
        ...     def get_detector_id(self):
        ...         return "my_detector"
        ...     
        ...     def get_supported_attack_types(self):
        ...         return [AttackType.PROMPT_INJECTION]
        
        >>> detector = MyDetector(config={'threshold': 0.5})
        >>> result = detector.detect_with_preprocessing("test input")
    
    Note:
        Do not call detect() directly. Use detect_with_preprocessing() to ensure
        proper preprocessing, error handling, and postprocessing are applied.
    """
    
    # Framework version for compatibility tracking
    VERSION = "2.3.0"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the detector with configuration parameters.
        
        Args:
            config: Optional configuration dictionary containing detector-specific
                   settings. Common keys include:
                   - threshold: Float in [0.0, 1.0] for attack classification
                   - Custom parameters defined by subclasses
        
        Raises:
            ValueError: If configuration contains invalid values (e.g., threshold
                       outside valid range or non-numeric type)
        
        Example:
            >>> detector = MyDetector(config={
            ...     'threshold': 0.7,
            ...     'custom_param': 'value'
            ... })
        """
        self.config: Dict[str, Any] = config or {}
        self.threshold: float = self.config.get('threshold', 0.4)
        self._validate_config()
    
    @abstractmethod
    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        """
        Execute the core detection algorithm.
        
        This abstract method must be implemented by subclasses to perform
        the actual security analysis. It receives preprocessed text and optional
        context information, and returns a DetectionResult with the findings.
        
        Args:
            text: Preprocessed input text ready for analysis. The text has already
                 been through _preprocess() which handles whitespace normalization
                 and line ending standardization.
            context: Optional dictionary containing contextual information that
                    may aid detection (e.g., user ID, session ID, historical data).
        
        Returns:
            DetectionResult containing the detection outcome, confidence score,
            attack classification, and any diagnostic details.
        
        Raises:
            NotImplementedError: If the subclass does not implement this method.
        
        Note:
            This method should NOT be called directly. Use detect_with_preprocessing()
            to ensure proper preprocessing, error handling, and postprocessing.
        
        Example Implementation:
            def detect(self, text, context=None):
                confidence = self._ml_model.predict(text)
                return DetectionResult(
                    is_attack=confidence >= self.threshold,
                    confidence=confidence,
                    attack_type=AttackType.PROMPT_INJECTION,
                    details={"model_score": confidence}
                )
        """
        pass
    
    @abstractmethod
    def get_detector_id(self) -> str:
        """
        Return the unique identifier for this detector.
        
        The identifier should be stable across versions and unique within the
        detector registry. Use lowercase with underscores for consistency.
        
        Returns:
            String identifier in format like "detector_name_v1"
        
        Example:
            >>> detector.get_detector_id()
            'prompt_injection_detector_v2'
        """
        pass
    
    @abstractmethod
    def get_supported_attack_types(self) -> List[AttackType]:
        """
        Return the list of attack types this detector can identify.
        
        This information is used for routing requests to appropriate detectors
        and for filtering detection results by attack category.
        
        Returns:
            List of AttackType enum values this detector is capable of detecting.
        
        Example:
            >>> detector.get_supported_attack_types()
            [AttackType.PROMPT_INJECTION, AttackType.JAILBREAK]
        """
        pass
    
    def get_metadata(self) -> DetectorMetadata:
        """
        Retrieve metadata describing this detector.
        
        Provides a default implementation using the detector's ID and class name.
        Subclasses may override to provide additional descriptive information.
        
        Returns:
            DetectorMetadata containing identification and capability information.
        
        Example:
            >>> metadata = detector.get_metadata()
            >>> print(f"{metadata.name} v{metadata.version}")
            'MyDetector v2.3.0'
        """
        return DetectorMetadata(
            id=self.get_detector_id(),
            name=self.__class__.__name__,
            version=self.VERSION,
            supported_types=self.get_supported_attack_types()
        )
    
    def configure(self, config: Dict[str, Any]) -> None:
        """
        Update detector configuration at runtime.
        
        Allows dynamic reconfiguration without recreating the detector instance.
        Configuration updates are merged with existing settings and validated.
        
        Args:
            config: Dictionary of configuration updates to apply. Updates are
                   merged with existing config, so only changed values need
                   to be specified.
        
        Raises:
            ValueError: If any configuration value fails validation.
        
        Example:
            >>> # Adjust threshold for stricter detection
            >>> detector.configure({'threshold': 0.6})
            >>> # Add custom parameter
            >>> detector.configure({'custom_param': 'new_value'})
        """
        self.config.update(config)
        self.threshold = self.config.get('threshold', self.threshold)
        self._validate_config()
    
    def _validate_config(self) -> None:
        """
        Validate configuration parameters.
        
        Checks that the threshold is a numeric value within the valid range
        [0.0, 1.0]. Subclasses may override to add additional validation logic
        for their custom configuration parameters.
        
        Raises:
            ValueError: If threshold is not a number or outside [0.0, 1.0] range.
        
        Example Override:
            def _validate_config(self):
                super()._validate_config()
                if 'max_length' in self.config:
                    if self.config['max_length'] < 1:
                        raise ValueError("max_length must be positive")
        """
        if not isinstance(self.threshold, (int, float)):
            raise ValueError(
                f"threshold must be a number, got {type(self.threshold).__name__}"
            )
        if not 0 <= self.threshold <= 1:
            raise ValueError(f"threshold must be in [0,1], got {self.threshold}")
    
    def detect_with_preprocessing(
        self, 
        text: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Execute the complete detection workflow.
        
        This is the primary entry point for detection operations. It implements
        the template method pattern by orchestrating the full workflow:
        validation → preprocessing → detection → postprocessing.
        
        Args:
            text: Raw input text to analyze. Will be validated and preprocessed
                 before detection.
            context: Optional contextual information to aid detection.
        
        Returns:
            DetectionResult with final determination, including processing time
            and detector identification. Returns empty result with error message
            if input validation fails or detection throws an exception.
        
        Example:
            >>> result = detector.detect_with_preprocessing("user input text")
            >>> if result.is_attack:
            ...     print(f"Detected {result.attack_type} with {result.confidence:.0%} confidence")
            Detected AttackType.PROMPT_INJECTION with 95% confidence
        """
        # Validate input to catch common errors early
        if not text or not isinstance(text, str):
            return self._create_empty_result(
                error_message="Invalid input: text must be a non-empty string"
            )
        
        # Normalize text for consistent analysis
        processed_text = self._preprocess(text)
        
        # Execute detection with timing for performance monitoring
        start_time = time.time()
        try:
            result = self.detect(processed_text, context)
        except Exception as e:
            return self._create_empty_result(
                error_message=f"Detection error: {str(e)}"
            )
        processing_time = (time.time() - start_time) * 1000
        
        # Apply threshold and add metadata
        return self._postprocess(result, processing_time)
    
    def _preprocess(self, text: str) -> str:
        """
        Normalize input text before detection.
        
        Performs basic text normalization including whitespace trimming and
        line ending standardization. Subclasses may override to add custom
        preprocessing (e.g., tokenization, encoding normalization).
        
        Args:
            text: Raw input text with potential inconsistent formatting.
        
        Returns:
            Normalized text ready for analysis.
        
        Example Override:
            def _preprocess(self, text):
                text = super()._preprocess(text)
                # Convert to lowercase for case-insensitive matching
                return text.lower()
        """
        # Remove leading/trailing whitespace for consistent handling
        processed = text.strip()
        # Normalize line endings to Unix-style for cross-platform consistency
        processed = processed.replace('\r\n', '\n').replace('\r', '\n')
        return processed
    
    def _postprocess(
        self, 
        result: DetectionResult, 
        processing_time_ms: float
    ) -> DetectionResult:
        """
        Finalize detection results with metadata and threshold application.
        
        Adds performance metrics and detector identification to the result,
        and applies the configured threshold to determine is_attack status.
        
        Args:
            result: Raw detection result from the subclass implementation.
            processing_time_ms: Execution duration in milliseconds.
        
        Returns:
            Enriched DetectionResult with timing, identification, and threshold
            application applied.
        
        Note:
            If confidence is below threshold, clears attack type information
            to prevent false positives from propagating.
        """
        result.processing_time_ms = processing_time_ms
        result.detector_id = self.get_detector_id()
        
        # Apply threshold to determine final attack classification
        if result.confidence >= self.threshold:
            result.is_attack = True
        else:
            result.is_attack = False
            result.attack_type = None
            result.attack_types = []
        
        return result
    
    def _create_empty_result(
        self, 
        error_message: Optional[str] = None
    ) -> DetectionResult:
        """
        Create a default result for error conditions.
        
        Used when input validation fails or detection encounters an exception.
        Returns a clean result marked as non-attack with error information.
        
        Args:
            error_message: Description of what went wrong, if applicable.
        
        Returns:
            DetectionResult with is_attack=False and error information set.
        """
        return DetectionResult(
            is_attack=False,
            confidence=0.0,
            attack_type=None,
            attack_types=[],
            processing_time_ms=0.0,
            detector_id=self.get_detector_id() if hasattr(self, 'get_detector_id') else "",
            error_message=error_message
        )
    
    def __repr__(self) -> str:
        """Return developer-friendly string representation."""
        return f"{self.__class__.__name__}(id={self.get_detector_id()}, threshold={self.threshold})"
    
    def __str__(self) -> str:
        """Return human-readable description."""
        metadata = self.get_metadata()
        return f"{metadata.name} v{metadata.version} [id={metadata.id}]"
