"""
Output Injection Detector Module

This module provides detection capabilities for output-based injection attacks,
where malicious instructions are embedded in tool outputs, external data, or
generated responses to compromise AI agent behavior.

Exports:
    OutputInjectionDetector: Primary detector class for output injection attacks
    patterns: Pattern definitions for attack signature matching
"""
from .detector import OutputInjectionDetector
from . import patterns

__all__ = ["OutputInjectionDetector", "patterns"]
