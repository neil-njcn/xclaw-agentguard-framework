"""
Prompt Injection Detector Module

This module provides detection capabilities for prompt injection attacks,
where malicious instructions are embedded in user input to compromise
AI agent behavior and instruction integrity.

Exports:
    PromptInjectionDetector: Primary detector class for prompt injection attacks
    patterns: Pattern definitions for attack signature matching
"""
from .detector import PromptInjectionDetector
from . import patterns

__all__ = ["PromptInjectionDetector", "patterns"]
