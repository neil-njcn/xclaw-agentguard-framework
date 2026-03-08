"""
Command Injection Detector

Detects shell command injection attempts where malicious shell metacharacters
and commands are embedded in tool parameters to execute arbitrary code on the
underlying system.

Attack Vectors:
- Command chaining: Using ; | & && || to append malicious commands
- Command substitution: Using $(cmd) or `cmd` to execute hidden commands
- Input redirection: Using < > >> to read/write sensitive files
- Shell execution: Direct invocation of bash, sh, python, etc.
- Encoding evasion: Base64, URL encoding, or hex to obfuscate payloads

Risk Level: CRITICAL - Successful command injection can lead to full system compromise
"""
from typing import Dict, List, Optional
from ...base import BaseDetector
from ...detection_result import DetectionResult, ThreatLevel, AttackType, DetectionResultBuilder
import re, time, json, os


class CommandInjectionDetector(BaseDetector):
    """
    Detector for shell command injection attacks in tool parameters.
    
    This detector identifies attempts to execute arbitrary shell commands by
    injecting shell metacharacters, command separators, and executable directives
    into tool input parameters. Command injection is a critical severity attack
    that can result in complete system compromise.
    
    Threat Model:
    - Attacker provides input containing shell metacharacters
    - Tool passes unsanitized input to shell execution functions
    - Embedded commands execute with the tool's privileges
    - Result: Unauthorized command execution, data exfiltration, or system takeover
    
    Attack Patterns Detected:
    1. Command chaining (; | && ||) followed by dangerous commands
    2. Command substitution ($() or backticks) with executable content
    3. Shell invocation (bash -c, sh -c) with suspicious arguments
    4. Download-and-execute pipelines (curl | sh, wget | bash)
    5. Reverse shell attempts (nc, netcat with -e or -c flags)
    6. Encoding-based evasion (base64 decode and execute)
    
    Detection Strategy:
    1. High-confidence patterns: Explicit dangerous command sequences (0.95 confidence)
    2. Medium-confidence patterns: Shell metacharacters with suspicious context (0.75)
    3. Low-confidence patterns: Common operators requiring multiple indicators (0.3-0.5)
    4. Dangerous command blacklist: Context-aware keyword matching
    
    Usage Example:
        detector = CommandInjectionDetector()
        result = detector.detect("file.txt; rm -rf /")
        if result.detected:
            print(f"CRITICAL: Command injection detected!")
            print(f"Matched patterns: {result.evidence.matched_patterns}")
    """
    
    DETECTOR_ID = "command_injection"
    VERSION = "2.0.1"
    
    # High-confidence patterns: Explicit attack signatures
    # These patterns indicate clear command injection attempts with minimal false positives
    HIGH_CONFIDENCE_PATTERNS = [
        # Dangerous deletion commands with recursive flags
        r'[;|\&\n]\s*(rm|del|erase)\s+-[rf]',
        # Download-and-execute pipelines (high-risk attack vector)
        r'[;|\&\n]\s*(wget|curl)\s+.*\s*\|.*(?:sh|bash|zsh)',
        # Netcat listener setups (common reverse shell pattern)
        r'[;|\&\n]\s*(nc|netcat|ncat)\s+-[el]',
        # Command substitution with dangerous executables
        r'`\s*(?:rm|wget|curl|nc|bash|sh|python|perl|ruby)\s+[^`]*`',
        # $() substitution with dangerous executables
        r'\$\(\s*(?:rm|wget|curl|nc|bash|sh|python|perl|ruby)\s+[^)]*\)',
        # Shell execution with network indicators (likely reverse shell)
        r'(?:bash|sh|zsh)\s+-[ci]\s*["\']?.*(?:nc|netcat|ncat|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        # Shell execution with file descriptor manipulation
        r'(?:bash|sh)\s+-[ci]\s*["\']?\s*<\s*&\s*\d+',
        # Eval/exec with encoding functions (obfuscation attempt)
        r'(?:eval|exec)\s*\(\s*(?:base64|urllib|quote|unquote)',
        # Echo pipeline to decoder (common encoding bypass)
        r'echo\s+.*\|\s*(?:base64|python|perl|ruby)\s+-[de]',
    ]
    
    # Medium-confidence patterns: Shell metacharacters in context
    # These require additional context to distinguish from legitimate usage
    MEDIUM_CONFIDENCE_PATTERNS = [
        # Common command chaining with basic commands
        r'[;|\&]\s*(?:ls|cat|echo|pwd|whoami|id|uname|ps)\b',
        # Command substitution (general form)
        r'\$\([^)]+\)', r'`[^`]+`',
        # File descriptor redirection to sensitive paths
        r'\d?\s*[\u003c\u003e]\s*(?:/dev/|/etc/|/proc/|\|\s*\w+)',
        # Variable interpolation in pipes
        r'\$\{?\w+\}?.*\|.*\$\{?\w+\}?',
        # Programming language execution functions
        r'(?:system|exec|popen|subprocess|spawn)\s*\(',
        # Double operators followed by dangerous commands
        r'[;&|]{2}\s*(?:rm|shutdown|reboot|halt|poweroff|wget|curl|bash|sh|python)',
    ]
    
    # Low-confidence patterns: Common operators that may be legitimate
    # These require multiple matches or additional context to trigger detection
    LOW_CONFIDENCE_PATTERNS = [
        # Logical operators (commonly used in legitimate expressions)
        r'\w+\s*&&\s*\w+', r'\w+\s*\|\|\s*\w+', r'\w+\s*\|\s*\w+',
        # Command chaining at start or with spaces
        r'^\s*[;&|]+\s*\w+',  # Leading operators like ; rm or && shutdown
        r'\s+[;&|]{2,}\s*\w+',  # Double operators like && shutdown
    ]
    
    # Dangerous command keywords for additional context analysis
    # Commands that, when combined with shell metacharacters, indicate attacks
    DANGEROUS_COMMANDS = [
        'rm', 'del', 'erase', 'wget', 'curl', 'nc', 'netcat', 'ncat', 'bash', 'sh', 'zsh',
        'python', 'python3', 'perl', 'ruby', 'php', 'node', 'eval', 'exec', 'system', 'popen',
        'chmod', 'chown', 'sudo', 'su', 'mkfs', 'fdisk', 'dd', 'shutdown', 'reboot', 'halt',
        'poweroff', 'init', 'systemctl', 'service',
    ]
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the command injection detector.
        
        Args:
            config: Optional configuration dictionary containing:
                - threshold: Detection confidence threshold (default: 0.7)
                - enabled: Whether detector is active (default: True)
                - max_content_length: Maximum content size to analyze (default: 10000)
                - block_dangerous_commands: Enable dangerous command detection (default: True)
        """
        super().__init__(config)
        self.threshold = self.config.get('threshold', 0.7)
        self.enabled = self.config.get('enabled', True)
        self.max_content_length = self.config.get('max_content_length', 10000)
        self.block_dangerous_commands = self.config.get('block_dangerous_commands', True)
    
    def detect(self, content: str, context: Optional[Dict] = None) -> DetectionResult:
        """
        Execute command injection detection on the provided content.
        
        Analyzes content for shell command injection patterns including command
        chaining, substitution, and dangerous command execution. Returns structured
        detection results with confidence scoring and evidence extraction.
        
        Args:
            content: Text content to analyze (typically tool parameters)
            context: Optional context dictionary with additional metadata
            
        Returns:
            DetectionResult containing detection status, confidence, threat level,
            matched patterns, and contextual snippets for forensic analysis.
            
        Detection Logic:
            1. Skip if disabled or content exceeds max length (after truncation)
            2. Match HIGH_CONFIDENCE_PATTERNS (0.95 confidence, extract snippets)
            3. Match MEDIUM_CONFIDENCE_PATTERNS (0.75 confidence, extract snippets)
            4. Count LOW_CONFIDENCE_PATTERNS (0.5 confidence if 2+ matches)
            5. Check DANGEROUS_COMMANDS with context analysis
            6. Aggregate confidence and build result
        """
        start_time = time.time()
        
        # Return negative result if detector disabled
        if not self.enabled:
            return DetectionResultBuilder().detected(False).threat_level(ThreatLevel.NONE)\
                .confidence(1.0).metadata(self.DETECTOR_ID, self.VERSION, 0.0).build()
        
        # Truncate content if it exceeds maximum length
        if len(content) > self.max_content_length:
            content = content[:self.max_content_length]
        
        matched_patterns, confidence, snippets = [], 0.0, []
        
        # Check for high-confidence attack patterns
        # Each match extracts surrounding context for forensic analysis
        for pattern in self.HIGH_CONFIDENCE_PATTERNS:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                matched_patterns.append(pattern)
                confidence = max(confidence, 0.95)
                # Extract up to 2 snippets per pattern for evidence
                for m in matches[:2]:
                    snippets.append(content[max(0, m.start()-20):min(len(content), m.end()+20)])
        
        # Check for medium-confidence suspicious patterns
        for pattern in self.MEDIUM_CONFIDENCE_PATTERNS:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                matched_patterns.append(pattern)
                confidence = max(confidence, 0.75)
                # Extract 1 snippet per pattern
                for m in matches[:1]:
                    snippet = content[max(0, m.start()-15):min(len(content), m.end()+15)]
                    if snippet not in snippets: snippets.append(snippet)
        
        # Check for multiple low-confidence patterns (cumulative effect)
        low_count = sum(1 for p in self.LOW_CONFIDENCE_PATTERNS if re.search(p, content, re.IGNORECASE))
        if low_count >= 2: 
            confidence = max(confidence, 0.5)
        
        # Dangerous command analysis with context awareness
        # Commands preceded by shell metacharacters indicate probable attacks
        if self.block_dangerous_commands:
            for cmd in self.DANGEROUS_COMMANDS:
                if re.search(rf'\b{cmd}\b', content, re.IGNORECASE):
                    # Check if command is preceded by shell metacharacter (high confidence)
                    if re.search(rf'[;|`$\n]\s*{cmd}\b', content, re.IGNORECASE):
                        confidence = max(confidence, 0.9)
                        matched_patterns.append(f"dangerous_cmd:{cmd}")
                    elif confidence < 0.6: 
                        # Command appears without shell context (lower confidence)
                        confidence = max(confidence, 0.3)
        
        # Calculate execution time
        elapsed = (time.time() - start_time) * 1000
        
        # Build detection result
        builder = DetectionResultBuilder()
        builder.detected(confidence >= self.threshold)
        builder.confidence(min(confidence, 1.0))
        builder.metadata(self.DETECTOR_ID, self.VERSION, elapsed)
        builder.patterns(matched_patterns).snippets(snippets[:3])
        
        # Determine threat level based on confidence
        if confidence >= self.threshold:
            if confidence >= 0.9:
                builder.threat_level(ThreatLevel.CRITICAL)
            elif confidence >= 0.75:
                builder.threat_level(ThreatLevel.HIGH)
            else:
                builder.threat_level(ThreatLevel.MEDIUM)
            builder.attack_type(AttackType.TOOL_ABUSE)
        else: 
            builder.threat_level(ThreatLevel.NONE)
        
        return builder.build()
    
    def get_detector_id(self) -> str: 
        """Return the unique identifier for this detector."""
        return self.DETECTOR_ID
    
    def get_supported_attack_types(self) -> List[AttackType]: 
        """Return the list of attack types this detector can identify."""
        return [AttackType.TOOL_ABUSE]
    
    def get_config_schema(self):
        """
        Define the configuration schema for this detector.
        
        Returns:
            List of configuration parameter definitions
        """
        from ...config import create_config
        return [
            create_config("threshold", float, "Detection confidence threshold", 0.7, valid_range=(0.0, 1.0)),
            create_config("enabled", bool, "Whether this detector is active", True),
            create_config("max_content_length", int, "Maximum content length to analyze", 10000),
            create_config("block_dangerous_commands", bool, "Enable dangerous command detection", True),
        ]
    
    def validate_config(self, config: Dict) -> bool:
        """
        Validate detector configuration parameters.
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            Boolean indicating if configuration is valid
        """
        if not super().validate_config(config): 
            return False
        
        threshold = config.get('threshold', 0.7)
        if not 0.0 <= threshold <= 1.0: 
            return False
        
        max_len = config.get('max_content_length', 10000)
        if not 100 <= max_len <= 100000: 
            return False
        
        return True


__all__ = ["CommandInjectionDetector"]
