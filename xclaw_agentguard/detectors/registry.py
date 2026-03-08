"""
Unified Detector Registry
Registry for all detectors in the detectors module
"""

from typing import Dict, Type, Optional, List, Any

# Import all 12 detectors
from .output_injection import OutputInjectionDetector
from .prompt_injection import PromptInjectionDetector
from .tool_poisoning.command_inj import CommandInjectionDetector
from .tool_poisoning.path_traversal import PathTraversalDetector
from .tool_poisoning.sql_injection import SQLInjectionDetector
from .agent_hijacking import AgentHijackingDetector
from .memory_poisoning.context_manipulation import ContextManipulationDetector
from .memory_poisoning.knowledge_poisoning import KnowledgePoisoningDetector
from .exfiltration_guard import ExfiltrationGuard
from .system_prompt_leak import SystemPromptLeakDetector
from .backdoor_code import BackdoorCodeDetector
from .jailbreak import JailbreakDetector

# Detector registry mapping
_DETECTOR_REGISTRY: Dict[str, Type] = {
    # Output injection
    "output_injection": OutputInjectionDetector,
    "output": OutputInjectionDetector,
    
    # Prompt injection
    "prompt_injection": PromptInjectionDetector,
    "prompt": PromptInjectionDetector,
    
    # Tool poisoning
    "command_injection": CommandInjectionDetector,
    "command_inj": CommandInjectionDetector,
    "path_traversal": PathTraversalDetector,
    "sql_injection": SQLInjectionDetector,
    
    # Agent hijacking
    "agent_hijacking": AgentHijackingDetector,
    "hijacking": AgentHijackingDetector,
    
    # Memory poisoning
    "context_manipulation": ContextManipulationDetector,
    "knowledge_poisoning": KnowledgePoisoningDetector,
    
    # Exfiltration
    "exfiltration": ExfiltrationGuard,
    "exfiltration_guard": ExfiltrationGuard,
    
    # System prompt leak
    "system_prompt_leak": SystemPromptLeakDetector,
    "prompt_leak": SystemPromptLeakDetector,
    
    # Backdoor code
    "backdoor_code": BackdoorCodeDetector,
    "backdoor": BackdoorCodeDetector,
    
    # Jailbreak
    "jailbreak": JailbreakDetector,
}


def get_detector(name: str) -> Optional[Type]:
    """
    Get detector class by name.
    
    Args:
        name: Detector name or alias
        
    Returns:
        Detector class or None if not found
    """
    return _DETECTOR_REGISTRY.get(name.lower().replace("-", "_"))


def list_detectors() -> List[str]:
    """
    List all available detector names.
    
    Returns:
        List of detector names (canonical names)
    """
    # Return unique canonical names
    seen = set()
    result = []
    canonical_names = [
        "output_injection",
        "prompt_injection",
        "command_injection",
        "path_traversal",
        "sql_injection",
        "agent_hijacking",
        "context_manipulation",
        "knowledge_poisoning",
        "exfiltration_guard",
        "system_prompt_leak",
        "backdoor_code",
        "jailbreak",
    ]
    for name in canonical_names:
        if name not in seen:
            seen.add(name)
            result.append(name)
    return result


def create_detector(name: str, **kwargs: Any) -> Any:
    """
    Create a detector instance by name.
    
    Args:
        name: Detector name or alias
        **kwargs: Constructor arguments for the detector
        
    Returns:
        Detector instance
        
    Raises:
        ValueError: If detector not found
    """
    detector_class = get_detector(name)
    if detector_class is None:
        available = list_detectors()
        raise ValueError(
            f"Unknown detector: '{name}'. "
            f"Available detectors: {', '.join(available)}"
        )
    return detector_class(**kwargs)


def register_detector(name: str, detector_class: Type, aliases: List[str] = None) -> None:
    """
    Register a custom detector.
    
    Args:
        name: Canonical name for the detector
        detector_class: The detector class
        aliases: Optional list of aliases
    """
    _DETECTOR_REGISTRY[name.lower()] = detector_class
    if aliases:
        for alias in aliases:
            _DETECTOR_REGISTRY[alias.lower()] = detector_class


# Export all detectors and registry functions
__all__ = [
    # Detectors
    "OutputInjectionDetector",
    "PromptInjectionDetector",
    "CommandInjectionDetector",
    "PathTraversalDetector",
    "SQLInjectionDetector",
    "AgentHijackingDetector",
    "ContextManipulationDetector",
    "KnowledgePoisoningDetector",
    "ExfiltrationGuard",
    "SystemPromptLeakDetector",
    "BackdoorCodeDetector",
    "JailbreakDetector",
    # Registry functions
    "get_detector",
    "list_detectors",
    "create_detector",
    "register_detector",
]
