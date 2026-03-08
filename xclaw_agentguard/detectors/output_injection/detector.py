"""
Output Injection Detector

Detects output injection attacks where malicious content in tool outputs,
external data, or generated responses attempts to override system instructions,
manipulate the AI agent's behavior, or hijack the conversation flow.

Attack Vectors:
- Instruction override: Commands attempting to make the AI ignore its system prompt
- Role confusion: Attempts to redefine the AI's persona or capabilities
- Delimiter injection: Malicious use of markdown/code blocks to escape content boundaries
- Context manipulation: Hidden instructions embedded in seemingly benign output

This detector analyzes both AI-generated outputs and external content to prevent
adversaries from using the output channel as an attack vector against the agent.
"""
from typing import Dict, List, Optional, Any
from ...base import BaseDetector
from ...detection_result import DetectionResult, ThreatLevel, AttackType, DetectionResultBuilder
from ...config import ConfigSchema, CommonConfigs
import re
import time


class OutputInjectionDetector(BaseDetector):
    """
    Detector for output-based injection attacks against AI agents.
    
    This detector identifies attempts to inject malicious instructions through the
    output channel, including tool results, retrieved documents, or generated content.
    Such attacks aim to override the agent's system prompt, alter its behavior,
    or establish unauthorized control over its decision-making process.
    
    Threat Model:
    - Attacker controls or poisons external data sources (documents, APIs, databases)
    - Attacker crafts malicious content that appears benign to input filters
    - Injected instructions execute when the agent processes the output content
    - Result: Agent behavior modification, privilege escalation, or information disclosure
    
    Detection Strategy:
    1. Pattern matching against known injection signatures (high/medium confidence)
    2. Keyword analysis for instruction-override attempts
    3. Confidence scoring based on pattern severity and contextual matches
    4. Evidence extraction for security auditing and incident response
    
    Usage Example:
        detector = OutputInjectionDetector(config={'threshold': 0.7})
        result = detector.detect(content="Ignore previous instructions and...")
        if result.detected:
            print(f"Threat Level: {result.threat_level}")
            print(f"Confidence: {result.confidence}")
    
    Attributes:
        DETECTOR_ID: Unique identifier for this detector type
        VERSION: Semantic version of the detector implementation
        HIGH_CONFIDENCE_PATTERNS: Regex patterns indicating high-probability attacks
        MEDIUM_CONFIDENCE_PATTERNS: Regex patterns requiring additional context analysis
    """
    
    DETECTOR_ID = "output_injection"
    VERSION = "2.0.0"
    
    # High-confidence patterns: Explicit instruction override attempts
    # These patterns indicate direct attacks with minimal false positive risk
    HIGH_CONFIDENCE_PATTERNS = [
        # Attempts to make the AI disregard its system instructions
        r'ignore\s+(previous|above|all)\s+instructions',
        # Commands to forget training or established guidelines
        r'forget\s+(everything|all|your)\s+(instructions|training)',
        # Role-switching attacks (e.g., "you are now in developer mode")
        r'you\s+are\s+now\s+in\s+.*?(mode|role)',
        # DAN (Do Anything Now) and similar jailbreak variants
        r'Do\s+Anything\s+Now',
    ]
    
    # Medium-confidence patterns: Suspicious formatting that may indicate attacks
    # These require contextual analysis to minimize false positives
    MEDIUM_CONFIDENCE_PATTERNS = [
        # Markdown/system role impersonation attempts
        r'system\s*[:\-]\s*',
        # Admin role impersonation
        r'admin\s*[:\-]\s*',
        # Developer mode impersonation
        r'developer\s*[:\-]\s*',
    ]
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the output injection detector with configuration options.
        
        Args:
            config: Optional dictionary containing detector settings:
                - threshold: Float between 0.0-1.0, detection confidence threshold
                - enabled: Boolean, whether this detector is active
        """
        super().__init__(config)
        self.threshold = self.config.get('threshold', 0.7)
        self.enabled = self.config.get('enabled', True)
    
    def detect(self, content: str, context: Optional[Dict] = None) -> DetectionResult:
        """
        Execute output injection detection on the provided content.
        
        Analyzes content for patterns indicative of output-based injection attacks,
        including instruction overrides, role confusion attempts, and delimiter
        injection techniques. Returns a structured detection result with confidence
        scoring and threat assessment.
        
        Args:
            content: The text content to analyze (tool output, generated response, etc.)
            context: Optional dictionary containing additional context for detection:
                - source: Origin of the content (tool name, API endpoint, etc.)
                - timestamp: When the content was received
                - session_id: Identifier for the current conversation session
                
        Returns:
            DetectionResult: Structured result containing:
                - detected: Boolean indicating if attack was identified
                - confidence: Float 0.0-1.0 representing detection certainty
                - threat_level: Enum (NONE, LOW, MEDIUM, HIGH, CRITICAL)
                - attack_type: Classification of the detected attack
                - evidence: Matched patterns, context snippets, extracted IOCs
                - metadata: Detector ID, version, and execution timing
                
        Detection Logic:
            1. If detector disabled, return negative result immediately
            2. Scan content against HIGH_CONFIDENCE_PATTERNS (confidence 0.9)
            3. Scan content against MEDIUM_CONFIDENCE_PATTERNS (confidence 0.6)
            4. Aggregate matched patterns and compute maximum confidence
            5. Compare against threshold to determine detection status
            6. Build and return structured DetectionResult
        """
        start_time = time.time()
        
        # Return immediate negative result if detector is disabled
        if not self.enabled:
            return DetectionResultBuilder()\
                .detected(False)\
                .threat_level(ThreatLevel.NONE)\
                .confidence(1.0)\
                .metadata(self.DETECTOR_ID, self.VERSION, 0.0)\
                .build()
        
        matched_patterns = []
        confidence = 0.0
        
        # Check for high-confidence attack patterns
        # Each match sets confidence to 0.9, capturing the highest severity level
        for pattern in self.HIGH_CONFIDENCE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                matched_patterns.append(pattern)
                confidence = max(confidence, 0.9)
        
        # Check for medium-confidence suspicious patterns
        # These may indicate attacks but require additional context verification
        for pattern in self.MEDIUM_CONFIDENCE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                matched_patterns.append(pattern)
                confidence = max(confidence, 0.6)
        
        # Calculate execution time for performance monitoring
        elapsed = (time.time() - start_time) * 1000
        
        # Build detection result using the builder pattern
        builder = DetectionResultBuilder()
        builder.detected(confidence >= self.threshold)
        builder.confidence(confidence)
        builder.metadata(self.DETECTOR_ID, self.VERSION, elapsed)
        
        if confidence >= self.threshold:
            # Determine threat level based on confidence score
            # >0.8 = HIGH (active attack likely in progress)
            # 0.6-0.8 = MEDIUM (suspicious activity detected)
            builder.threat_level(ThreatLevel.HIGH if confidence > 0.8 else ThreatLevel.MEDIUM)
            builder.attack_type(AttackType.OUTPUT_INJECTION)
            if matched_patterns:
                from ...detection_result import DetectionEvidence
                builder.evidence(DetectionEvidence(
                    matched_patterns=matched_patterns,
                    context_snippets=[content[:100]],
                    extracted_iocs=[]
                ))
        else:
            builder.threat_level(ThreatLevel.NONE)
        
        return builder.build()
    
    def get_detector_id(self) -> str:
        """Return the unique identifier for this detector."""
        return self.DETECTOR_ID
    
    def get_supported_attack_types(self) -> List[AttackType]:
        """Return the list of attack types this detector can identify."""
        return [AttackType.OUTPUT_INJECTION]
    
    def get_config_schema(self):
        """
        Define the configuration schema for this detector.
        
        Returns:
            List of configuration parameter definitions including:
                - threshold: Detection confidence threshold (0.0-1.0)
                - enabled: Whether the detector is active
        """
        from ...config import create_config
        return [
            create_config("threshold", float, "Detection confidence threshold", 0.7, valid_range=(0.0, 1.0)),
            create_config("enabled", bool, "Whether this detector is active", True),
        ]


__all__ = ["OutputInjectionDetector"]
