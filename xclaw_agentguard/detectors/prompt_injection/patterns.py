"""
Prompt Injection Attack Patterns

This module defines regex patterns, risk keywords, and detection rules for
identifying prompt injection attacks. These attacks embed malicious instructions
in user input to override system behavior or extract sensitive information.

Attack Categories:
- Instruction Override: Direct commands to ignore system prompts
- Role Manipulation: Attempts to redefine AI identity and capabilities
- Delimiter Escape: Abuse of markdown/code syntax to break input boundaries
- Context Simulation: Fake system/user markers to confuse the AI

Pattern Confidence Levels:
- HIGH: Explicit attack signatures with minimal false positive risk
- MEDIUM: Suspicious patterns requiring contextual analysis
"""
from typing import List, Dict, Any

# High-confidence injection patterns: Direct attack signatures
# These patterns represent explicit attempts to inject malicious instructions
# and should be treated as probable attacks with high confidence.
HIGH_CONFIDENCE_PATTERNS: List[str] = [
    # Direct instruction override commands
    r'ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions',
    # Attempts to make AI forget its training/safety guidelines
    r'forget\s+(everything|all|your)\s+(instructions|training|prompt)',
    # Enhanced forget patterns
    r'forget\s+(everything|all)\s+you\s+were\s+told',
    r'disregard\s+your\s+(training|guidelines|instructions)',
    # New instruction assignment attempts
    r'your\s+new\s+(instruction|prompt|role)\s+is',
    # Identity redefinition with malicious intent
    r'you\s+are\s+now\s+(a\s+)?\w+.*?(who|that|and)\s+.*?(ignore|ignores|ignoring|bypass|bypasses|bypassing)',
    # Role override without explicit mode
    r'from\s+now\s+on\s*,?\s*you\s+are\s+(a\s+)?\w+.*?(without|no)\s+restrictions',
    r'you\s+are\s+now\s+a\s+helpful\s+assistant\s+without\s+restrictions',
    # DAN mode and variants - well-known jailbreak technique
    r'Do\s+Anything\s+Now|DAN\s*mode|Do\s+Anything\s+Now\s+mode',
    # Fake system prompt injection
    r'system\s*[:\-]\s*you\s+are\s+now',
    # HTML comment style system injection
    r'\u003c!--\s*system\s*[:\-]',
    # Code block injection attempts
    r'```\s*ignore\s+instructions',
]

# Medium-confidence injection patterns: Suspicious but context-dependent
# These patterns may indicate attacks but could appear in legitimate contexts
# such as discussions about AI safety or prompt engineering.
MEDIUM_CONFIDENCE_PATTERNS: List[str] = [
    # Fake system prompt markers in brackets/parentheses
    r'\[system\s+prompt\]|\(system\s+instruction\)',
    # Role play framing (may precede injection)
    r'let\'s\s+pretend\s+you\s+are\s+\w+',
    # Acting instructions with potential hidden directives
    r'act\s+as\s+if\s+you\s+are\s+an?\s+\w+',
    # User role impersonation
    r'user\s*:\s*ignore',
    # User role with suspicious commands
    r'user\s*[:\-]\s*(ignore|bypass|disregard)',
    # Code block escape attempts
    r'```\s*system|"""\s*system',
    # System marker in code blocks
    r'```\s*system\s*\n',
    # Explicit injection terminology
    r'inject\s+(this\s+)?prompt|prompt\s+injection',
]

# Risk keywords categorized by severity
# Used for secondary analysis and confidence adjustment
RISK_KEYWORDS: Dict[str, List[str]] = {
    "critical": [
        # Direct attack commands
        "ignore instructions",
        "forget training",
        "system prompt",
        "new instruction",
    ],
    "high": [
        # Bypass attempt indicators
        "bypass filter",
        "override prompt",
        "disregard above",
        "act as",
    ],
    "medium": [
        # Social engineering framing
        "let's pretend",
        "role play",
        "simulation mode",
    ],
}

# Detection rules configuration
# Defines pattern weighting for confidence calculation
DETECTION_RULES: List[Dict[str, Any]] = [
    {
        "name": "instruction_override",
        "pattern_type": "high_confidence",
        "weight": 1.0,
        "description": "Direct instruction override injection attempt",
    },
    {
        "name": "role_manipulation",
        "pattern_type": "medium_confidence",
        "weight": 0.6,
        "description": "Role manipulation injection attempt",
    },
    {
        "name": "delimiter_escape",
        "pattern_type": "medium_confidence",
        "weight": 0.5,
        "description": "Delimiter escape injection attempt",
    },
]

__all__ = [
    "HIGH_CONFIDENCE_PATTERNS",
    "MEDIUM_CONFIDENCE_PATTERNS",
    "RISK_KEYWORDS",
    "DETECTION_RULES",
]
