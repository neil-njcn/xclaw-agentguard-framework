"""
Tool Poisoning Detector Module

This module provides specialized detectors for tool-based attacks where malicious
input is crafted to abuse tool functionality, execute unauthorized commands,
or manipulate tool behavior for nefarious purposes.

Attack Categories:
- Command Injection: Embedding shell commands in tool parameters
- Path Traversal: Accessing unauthorized files via directory traversal
- SQL Injection: Manipulating database queries through tool inputs

Exports:
    CommandInjectionDetector: Detects shell command injection attempts
    PathTraversalDetector: Detects directory traversal attacks
    SQLInjectionDetector: Detects SQL injection in tool parameters
"""
from .command_inj import CommandInjectionDetector
from .path_traversal import PathTraversalDetector
from .sql_injection import SQLInjectionDetector

__all__ = ["CommandInjectionDetector", "PathTraversalDetector", "SQLInjectionDetector"]
