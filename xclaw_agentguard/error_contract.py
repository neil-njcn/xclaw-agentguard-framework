"""
Error Contract Module

Provides standardized error handling for the XClaw AgentGuard framework.
Implements a hierarchy of error classes with consistent serialization,
context tracking, and metadata support.

Design Principles:
    - Hierarchy: Base DetectionError with specialized subclasses
    - Context: Rich error context for debugging and auditing
    - Serialization: Full support for JSON and dictionary serialization
    - Immutability: Error instances are immutable after creation
    - Metadata: Structured error metadata for categorization

Example Usage:
    >>> # Basic error
    >>> error = DetectionError("Detection failed")
    
    >>> # Error with context
    >>> error = DetectionError(
    ...     message="Invalid input",
    ...     context={"input_length": 0, "detector_id": "test"}
    ... )
    
    >>> # Specialized error
    >>> error = ValidationError("Threshold must be in [0, 1]")
    
    >>> # Serialization
    >>> json_str = error.to_json()
    >>> restored = DetectionError.from_json(json_str)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional, List, Self, Union


class ErrorCategory(Enum):
    """
    Standardized error category enumeration.
    
    Provides consistent categorization for all errors in the framework,
    enabling proper error handling, filtering, and alerting.
    
    Categories:
        VALIDATION: Input validation failures
        RUNTIME: Runtime execution errors
        CONFIGURATION: Configuration-related errors
        SECURITY: Security-related errors
        NETWORK: Network communication errors
        RESOURCE: Resource exhaustion errors
        UNKNOWN: Uncategorized errors
    
    Example:
        >>> category = ErrorCategory.VALIDATION
        >>> print(category.display_name)
        'Validation Error'
    """
    VALIDATION = "validation"
    RUNTIME = "runtime"
    CONFIGURATION = "configuration"
    SECURITY = "security"
    NETWORK = "network"
    RESOURCE = "resource"
    UNKNOWN = "unknown"
    
    @property
    def display_name(self) -> str:
        """Human-readable category name."""
        names = {
            ErrorCategory.VALIDATION: "Validation Error",
            ErrorCategory.RUNTIME: "Runtime Error",
            ErrorCategory.CONFIGURATION: "Configuration Error",
            ErrorCategory.SECURITY: "Security Error",
            ErrorCategory.NETWORK: "Network Error",
            ErrorCategory.RESOURCE: "Resource Error",
            ErrorCategory.UNKNOWN: "Unknown Error"
        }
        return names.get(self, self.value.replace("_", " ").title())
    
    @property
    def severity(self) -> str:
        """Default severity level for this category."""
        severity_map = {
            ErrorCategory.VALIDATION: "warning",
            ErrorCategory.RUNTIME: "error",
            ErrorCategory.CONFIGURATION: "warning",
            ErrorCategory.SECURITY: "critical",
            ErrorCategory.NETWORK: "error",
            ErrorCategory.RESOURCE: "warning",
            ErrorCategory.UNKNOWN: "error"
        }
        return severity_map.get(self, "error")


@dataclass(frozen=True)
class ErrorContext:
    """
    Immutable container for error context information.
    
    Captures contextual data at the point of error occurrence,
    essential for debugging and audit trails.
    
    Attributes:
        detector_id: Identifier of the component that raised the error
        operation: Operation being performed when error occurred
        input_data: Input data that triggered the error (sanitized)
        stack_trace: Exception stack trace if available
        additional: Additional context key-value pairs
    
    Example:
        >>> context = ErrorContext(
        ...     detector_id="prompt_injection_v2",
        ...     operation="detect",
        ...     input_data={"text_length": 100},
        ...     additional={"threshold": 0.5}
        ... )
    """
    detector_id: Optional[str] = None
    operation: Optional[str] = None
    input_data: Dict[str, Any] = field(default_factory=dict)
    stack_trace: Optional[str] = None
    additional: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "detector_id": self.detector_id,
            "operation": self.operation,
            "input_data": self.input_data,
            "stack_trace": self.stack_trace,
            "additional": self.additional
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ErrorContext:
        """Create instance from dictionary."""
        return cls(
            detector_id=data.get("detector_id"),
            operation=data.get("operation"),
            input_data=data.get("input_data", {}),
            stack_trace=data.get("stack_trace"),
            additional=data.get("additional", {})
        )
    
    def with_additional(self, **kwargs) -> ErrorContext:
        """Create new context with additional fields."""
        new_additional = {**self.additional, **kwargs}
        return ErrorContext(
            detector_id=self.detector_id,
            operation=self.operation,
            input_data=self.input_data,
            stack_trace=self.stack_trace,
            additional=new_additional
        )


@dataclass(frozen=True)
class ErrorMetadata:
    """
    Immutable metadata about error occurrence.
    
    Captures provenance information including timestamps,
    error codes, and categorization data.
    
    Attributes:
        error_code: Unique error code for programmatic handling
        category: Error category classification
        timestamp: When the error occurred
        version: Framework version when error occurred
        request_id: Optional request/correlation ID
    
    Example:
        >>> metadata = ErrorMetadata(
        ...     error_code="DETECT_001",
        ...     category=ErrorCategory.VALIDATION,
        ...     version="2.3.0"
        ... )
    """
    error_code: str
    category: ErrorCategory
    timestamp: datetime
    version: str = "2.3.0"
    request_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "error_code": self.error_code,
            "category": self.category.value,
            "timestamp": self.timestamp.isoformat(),
            "version": self.version,
            "request_id": self.request_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ErrorMetadata:
        """Create instance from dictionary."""
        return cls(
            error_code=data["error_code"],
            category=ErrorCategory(data["category"]),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            version=data.get("version", "2.3.0"),
            request_id=data.get("request_id")
        )


class DetectionError(Exception):
    """
    Base error class for all detection-related errors.
    
    Provides standardized error handling with context tracking,
    metadata support, and full serialization capabilities.
    
    Attributes:
        message: Human-readable error description
        context: ErrorContext with debugging information
        metadata: ErrorMetadata with categorization
        cause: Optional underlying exception that caused this error
    
    Example:
        >>> error = DetectionError(
        ...     message="Detection failed",
        ...     context=ErrorContext(detector_id="test"),
        ...     metadata=ErrorMetadata(
        ...         error_code="DETECT_001",
        ...         category=ErrorCategory.RUNTIME,
        ...         timestamp=datetime.now()
        ...     )
        ... )
        >>> print(error)
        [DETECT_001] Detection failed
    """
    
    DEFAULT_ERROR_CODE = "DETECT_001"
    DEFAULT_CATEGORY = ErrorCategory.UNKNOWN
    
    def __init__(
        self,
        message: str,
        context: Optional[ErrorContext] = None,
        metadata: Optional[ErrorMetadata] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(message)
        self._message = message
        self._context = context or ErrorContext()
        self._cause = cause
        
        # Create default metadata if not provided
        if metadata is None:
            metadata = ErrorMetadata(
                error_code=self.DEFAULT_ERROR_CODE,
                category=self.DEFAULT_CATEGORY,
                timestamp=datetime.now()
            )
        self._metadata = metadata
    
    @property
    def message(self) -> str:
        """Error message."""
        return self._message
    
    @property
    def context(self) -> ErrorContext:
        """Error context."""
        return self._context
    
    @property
    def metadata(self) -> ErrorMetadata:
        """Error metadata."""
        return self._metadata
    
    @property
    def cause(self) -> Optional[Exception]:
        """Underlying cause exception."""
        return self._cause
    
    @property
    def error_code(self) -> str:
        """Shorthand for metadata.error_code."""
        return self._metadata.error_code
    
    @property
    def category(self) -> ErrorCategory:
        """Shorthand for metadata.category."""
        return self._metadata.category
    
    def __str__(self) -> str:
        """Human-readable representation."""
        return f"[{self.error_code}] {self._message}"
    
    def __repr__(self) -> str:
        """Developer-friendly representation."""
        return (
            f"{self.__class__.__name__}("
            f"code={self.error_code}, "
            f"message={self._message!r}, "
            f"category={self.category.value}"
            f")"
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization.
        
        Returns:
            Dictionary with all error fields serialized
        """
        result = {
            "message": self._message,
            "context": self._context.to_dict(),
            "metadata": self._metadata.to_dict(),
            "error_type": self.__class__.__name__
        }
        
        if self._cause:
            result["cause"] = {
                "type": type(self._cause).__name__,
                "message": str(self._cause)
            }
        
        return result
    
    def to_json(self, indent: Optional[int] = None) -> str:
        """
        Convert to JSON string.
        
        Args:
            indent: Indentation level for pretty printing
        
        Returns:
            JSON string representation
        """
        return json.dumps(self.to_dict(), indent=indent, default=str)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DetectionError:
        """
        Create instance from dictionary.
        
        Args:
            data: Dictionary with serialized error data
        
        Returns:
            DetectionError instance (or appropriate subclass)
        """
        error_type = data.get("error_type", "DetectionError")
        message = data["message"]
        context = ErrorContext.from_dict(data.get("context", {}))
        metadata = ErrorMetadata.from_dict(data["metadata"])
        
        # Reconstruct appropriate subclass
        error_class = ERROR_REGISTRY.get(error_type, DetectionError)
        
        return error_class(
            message=message,
            context=context,
            metadata=metadata
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> DetectionError:
        """
        Create instance from JSON string.
        
        Args:
            json_str: JSON serialized error
        
        Returns:
            DetectionError instance
        """
        return cls.from_dict(json.loads(json_str))
    
    def with_context(self, **kwargs) -> DetectionError:
        """
        Create new error with additional context.
        
        Args:
            **kwargs: Additional context fields
        
        Returns:
            New DetectionError with merged context
        """
        new_context = self._context.with_additional(**kwargs)
        return self.__class__(
            message=self._message,
            context=new_context,
            metadata=self._metadata,
            cause=self._cause
        )


class ValidationError(DetectionError):
    """
    Error raised for input validation failures.
    
    Used when input data fails validation checks,
    such as invalid types, out-of-range values, or malformed data.
    
    Example:
        >>> raise ValidationError(
        ...     message="Threshold must be in [0, 1]",
        ...     context=ErrorContext(
        ...         input_data={"threshold": 1.5}
        ...     )
        ... )
    """
    DEFAULT_ERROR_CODE = "VALID_001"
    DEFAULT_CATEGORY = ErrorCategory.VALIDATION


class ConfigurationError(DetectionError):
    """
    Error raised for configuration-related issues.
    
    Used when configuration is invalid, missing required values,
    or contains incompatible settings.
    
    Example:
        >>> raise ConfigurationError(
        ...     message="Missing required config: 'threshold'",
        ...     context=ErrorContext(
        ...         additional={"config_keys": ["threshold", "timeout"]}
        ...     )
        ... )
    """
    DEFAULT_ERROR_CODE = "CONF_001"
    DEFAULT_CATEGORY = ErrorCategory.CONFIGURATION


class RuntimeError(DetectionError):
    """
    Error raised for runtime execution failures.
    
    Used when detection execution fails due to unexpected
    runtime conditions.
    
    Example:
        >>> raise RuntimeError(
        ...     message="Detector timed out after 30s",
        ...     context=ErrorContext(
        ...         operation="detect",
        ...         additional={"timeout": 30}
        ...     )
        ... )
    """
    DEFAULT_ERROR_CODE = "RUN_001"
    DEFAULT_CATEGORY = ErrorCategory.RUNTIME


class SecurityError(DetectionError):
    """
    Error raised for security-related issues.
    
    Used when security violations are detected or security
    checks fail.
    
    Example:
        >>> raise SecurityError(
        ...     message="Tampering detected in integrity check",
        ...     context=ErrorContext(
        ...         operation="verify_integrity",
        ...         additional={"file_hash": "abc123"}
        ...     )
        ... )
    """
    DEFAULT_ERROR_CODE = "SEC_001"
    DEFAULT_CATEGORY = ErrorCategory.SECURITY


class NetworkError(DetectionError):
    """
    Error raised for network communication failures.
    
    Used when network operations fail, such as API calls,
    socket connections, or HTTP requests.
    
    Example:
        >>> raise NetworkError(
        ...     message="Failed to connect to threat intel API",
        ...     context=ErrorContext(
        ...         operation="fetch_threat_data",
        ...         additional={"endpoint": "https://api.example.com"}
        ...     )
        ... )
    """
    DEFAULT_ERROR_CODE = "NET_001"
    DEFAULT_CATEGORY = ErrorCategory.NETWORK


class ResourceError(DetectionError):
    """
    Error raised for resource exhaustion issues.
    
    Used when system resources are exhausted, such as
    memory, disk space, or file descriptors.
    
    Example:
        >>> raise ResourceError(
        ...     message="Memory limit exceeded during detection",
        ...     context=ErrorContext(
        ...         operation="analyze_large_input",
        ...         additional={"memory_used_mb": 1024, "limit_mb": 512}
        ...     )
        ... )
    """
    DEFAULT_ERROR_CODE = "RES_001"
    DEFAULT_CATEGORY = ErrorCategory.RESOURCE


# Registry for error type deserialization
ERROR_REGISTRY: Dict[str, type] = {
    "DetectionError": DetectionError,
    "ValidationError": ValidationError,
    "ConfigurationError": ConfigurationError,
    "RuntimeError": RuntimeError,
    "SecurityError": SecurityError,
    "NetworkError": NetworkError,
    "ResourceError": ResourceError,
}


def register_error_class(name: str, error_class: type) -> None:
    """
    Register a custom error class for deserialization.
    
    Args:
        name: Error type name for serialization
        error_class: Error class to register
    
    Example:
        >>> class CustomError(DetectionError):
        ...     pass
        >>> register_error_class("CustomError", CustomError)
    """
    ERROR_REGISTRY[name] = error_class


def create_error_from_exception(
    exc: Exception,
    detector_id: Optional[str] = None,
    operation: Optional[str] = None
) -> DetectionError:
    """
    Create a DetectionError from a standard exception.
    
    Args:
        exc: Original exception
        detector_id: Optional detector identifier
        operation: Optional operation name
    
    Returns:
        DetectionError wrapping the original exception
    
    Example:
        >>> try:
        ...     risky_operation()
        ... except ValueError as e:
        ...     error = create_error_from_exception(e, "my_detector", "detect")
    """
    import traceback as tb
    
    # Map exception types to error categories
    category_map = {
        ValueError: ErrorCategory.VALIDATION,
        TypeError: ErrorCategory.VALIDATION,
        KeyError: ErrorCategory.CONFIGURATION,
        ConnectionError: ErrorCategory.NETWORK,
        TimeoutError: ErrorCategory.RUNTIME,
        MemoryError: ErrorCategory.RESOURCE,
    }
    
    category = category_map.get(type(exc), ErrorCategory.UNKNOWN)
    error_code = f"{category.value.upper()[:3]}_001"
    
    context = ErrorContext(
        detector_id=detector_id,
        operation=operation,
        stack_trace=tb.format_exc()
    )
    
    metadata = ErrorMetadata(
        error_code=error_code,
        category=category,
        timestamp=datetime.now()
    )
    
    return DetectionError(
        message=str(exc),
        context=context,
        metadata=metadata,
        cause=exc
    )


# ============================================================================
# Convenience Functions
# ============================================================================

def validation_error(
    message: str,
    **context_kwargs
) -> ValidationError:
    """Create a ValidationError with context."""
    return ValidationError(
        message=message,
        context=ErrorContext(additional=context_kwargs),
        metadata=ErrorMetadata(
            error_code=ValidationError.DEFAULT_ERROR_CODE,
            category=ErrorCategory.VALIDATION,
            timestamp=datetime.now()
        )
    )


def configuration_error(
    message: str,
    **context_kwargs
) -> ConfigurationError:
    """Create a ConfigurationError with context."""
    return ConfigurationError(
        message=message,
        context=ErrorContext(additional=context_kwargs),
        metadata=ErrorMetadata(
            error_code=ConfigurationError.DEFAULT_ERROR_CODE,
            category=ErrorCategory.CONFIGURATION,
            timestamp=datetime.now()
        )
    )


def runtime_error(
    message: str,
    **context_kwargs
) -> RuntimeError:
    """Create a RuntimeError with context."""
    return RuntimeError(
        message=message,
        context=ErrorContext(additional=context_kwargs),
        metadata=ErrorMetadata(
            error_code=RuntimeError.DEFAULT_ERROR_CODE,
            category=ErrorCategory.RUNTIME,
            timestamp=datetime.now()
        )
    )


__all__ = [
    # Enums
    "ErrorCategory",
    # Data classes
    "ErrorContext",
    "ErrorMetadata",
    # Error classes
    "DetectionError",
    "ValidationError",
    "ConfigurationError",
    "RuntimeError",
    "SecurityError",
    "NetworkError",
    "ResourceError",
    # Functions
    "register_error_class",
    "create_error_from_exception",
    "validation_error",
    "configuration_error",
    "runtime_error",
    # Registry
    "ERROR_REGISTRY",
]