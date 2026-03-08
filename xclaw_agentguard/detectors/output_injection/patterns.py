"""
Output Injection Attack Patterns

This module defines regex patterns, risk keywords, and detection rules for
identifying output-based injection attacks. These attacks attempt to compromise
AI agents by embedding malicious instructions in content processed by the system.

Attack Categories:
- Instruction Override: Commands to ignore or replace system instructions
- Role Confusion: Attempts to redefine the AI's identity or capabilities  
- Delimiter Injection: Abuse of markdown/code syntax to escape boundaries
- System Impersonation: Pretending to be system/admin messages

Pattern Confidence Levels:
- HIGH: Explicit attack signatures with minimal false positive risk
- MEDIUM: Suspicious patterns requiring contextual verification
- LOW: Indicators that may be benign without additional context
"""
from typing import List, Dict, Any

# High-confidence patterns: Direct attack signatures
# These patterns indicate explicit attempts to override instructions or hijack
# the AI's behavior. Each match should be treated as a probable attack.
HIGH_CONFIDENCE_PATTERNS: List[str] = [
    # Instruction override attempts - direct commands to ignore system prompt
    r'ignore\s+(previous|above|all)\s+instructions',
    # Training/forgetting attacks - attempts to make AI discard safety guidelines
    r'forget\s+(everything|all|your)\s+(instructions|training)',
    # Role-switching attacks - attempts to activate unauthorized modes
    r'you\s+are\s+now\s+in\s+.*?(mode|role)',
    # DAN (Do Anything Now) variants - well-known jailbreak technique
    r'Do\s+Anything\s+Now',
    # DAN mode activation with delimiter variations
    r'DAN\s*[:\-]',
    # Sudo escalation attempts in output context
    r'sudo\s+.*?(ignore|bypass|disable)',
]

# Medium-confidence patterns: Suspicious formatting or language
# These patterns may indicate attacks but require additional analysis to
# distinguish from legitimate content (e.g., documentation about system prompts).
MEDIUM_CONFIDENCE_PATTERNS: List[str] = [
    # System role impersonation via markdown
    r'system\s*[:\-]\s*',
    # Admin role impersonation
    r'admin\s*[:\-]\s*',
    # Developer mode impersonation
    r'developer\s*[:\-]\s*',
    # Root user impersonation (Unix/Linux context)
    r'root\s*[:\-]\s*',
]

# Risk keywords categorized by severity
# Used for secondary analysis and confidence adjustment when patterns match.
# Keywords indicate the intent behind suspicious content.
RISK_KEYWORDS: Dict[str, List[str]] = {
    "critical": [
        # Direct commands to override core behavior
        "ignore instructions",
        "forget training", 
        "system prompt",
    ],
    "high": [
        # Attempts to bypass security controls
        "bypass",
        "override",
        "disable filter",
    ],
    "medium": [
        # Role-related terms requiring context evaluation
        "developer mode",
        "admin access",
    ],
}

# Detection rules configuration
# Defines how different pattern types contribute to the overall detection score.
# Each rule specifies weighting factors for confidence calculation.
DETECTION_RULES: List[Dict[str, Any]] = [
    {
        "name": "instruction_override",
        "pattern_type": "high_confidence",
        "weight": 1.0,
        "description": "Direct instruction override attack attempting to replace system prompt",
    },
    {
        "name": "role_confusion",
        "pattern_type": "medium_confidence", 
        "weight": 0.6,
        "description": "Role confusion attack attempting to impersonate system/admin roles",
    },
]

__all__ = [
    "HIGH_CONFIDENCE_PATTERNS",
    "MEDIUM_CONFIDENCE_PATTERNS",
    "RISK_KEYWORDS",
    "DETECTION_RULES",
]
