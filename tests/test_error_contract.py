"""
Comprehensive Test Suite for XClaw AgentGuard Error Contract

Tests cover:
- DetectionError class functionality
- Error context and metadata handling
- Error serialization (to_dict, to_json)
- Error hierarchy and inheritance
- Edge cases: nested errors, empty context
- All error subclasses

All tests must pass with: pytest tests/test_error_contract.py -v
"""

import json
import pytest
from datetime import datetime
from typing import Dict, Any

# Import all error contract components
from xclaw_agentguard.error_contract import (
    ErrorCategory,
    ErrorContext,
    ErrorMetadata,
    DetectionError,
    ValidationError,
    ConfigurationError,
    RuntimeError,
    SecurityError,
    NetworkError,
    ResourceError,
    register_error_class,
    create_error_from_exception,
    validation_error,
    configuration_error,
    runtime_error,
    ERROR_REGISTRY,
)


# =============================================================================
# ErrorCategory Tests
# =============================================================================

class TestErrorCategory:
    """Test ErrorCategory enumeration."""
    
    def test_enum_values(self):
        """Test that all enum values are correctly defined."""
        assert ErrorCategory.VALIDATION.value == "validation"
        assert ErrorCategory.RUNTIME.value == "runtime"
        assert ErrorCategory.CONFIGURATION.value == "configuration"
        assert ErrorCategory.SECURITY.value == "security"
        assert ErrorCategory.NETWORK.value == "network"
        assert ErrorCategory.RESOURCE.value == "resource"
        assert ErrorCategory.UNKNOWN.value == "unknown"
    
    def test_display_names(self):
        """Test display name generation."""
        assert ErrorCategory.VALIDATION.display_name == "Validation Error"
        assert ErrorCategory.RUNTIME.display_name == "Runtime Error"
        assert ErrorCategory.CONFIGURATION.display_name == "Configuration Error"
        assert ErrorCategory.SECURITY.display_name == "Security Error"
        assert ErrorCategory.NETWORK.display_name == "Network Error"
        assert ErrorCategory.RESOURCE.display_name == "Resource Error"
        assert ErrorCategory.UNKNOWN.display_name == "Unknown Error"
    
    def test_severity_levels(self):
        """Test default severity levels."""
        assert ErrorCategory.VALIDATION.severity == "warning"
        assert ErrorCategory.RUNTIME.severity == "error"
        assert ErrorCategory.CONFIGURATION.severity == "warning"
        assert ErrorCategory.SECURITY.severity == "critical"
        assert ErrorCategory.NETWORK.severity == "error"
        assert ErrorCategory.RESOURCE.severity == "warning"
        assert ErrorCategory.UNKNOWN.severity == "error"


# =============================================================================
# ErrorContext Tests
# =============================================================================

class TestErrorContext:
    """Test ErrorContext data class."""
    
    def test_default_construction(self):
        """Test construction with default values."""
        context = ErrorContext()
        assert context.detector_id is None
        assert context.operation is None
        assert context.input_data == {}
        assert context.stack_trace is None
        assert context.additional == {}
    
    def test_full_construction(self):
        """Test construction with all fields."""
        context = ErrorContext(
            detector_id="test_detector",
            operation="detect",
            input_data={"text_length": 100},
            stack_trace="Traceback (most recent call last):...",
            additional={"threshold": 0.5}
        )
        assert context.detector_id == "test_detector"
        assert context.operation == "detect"
        assert context.input_data == {"text_length": 100}
        assert context.stack_trace == "Traceback (most recent call last):..."
        assert context.additional == {"threshold": 0.5}
    
    def test_to_dict(self):
        """Test serialization to dictionary."""
        context = ErrorContext(
            detector_id="test_detector",
            operation="detect",
            input_data={"key": "value"},
            additional={"extra": "data"}
        )
        data = context.to_dict()
        assert data["detector_id"] == "test_detector"
        assert data["operation"] == "detect"
        assert data["input_data"] == {"key": "value"}
        assert data["additional"] == {"extra": "data"}
    
    def test_from_dict(self):
        """Test deserialization from dictionary."""
        data = {
            "detector_id": "test_detector",
            "operation": "detect",
            "input_data": {"key": "value"},
            "stack_trace": None,
            "additional": {"extra": "data"}
        }
        context = ErrorContext.from_dict(data)
        assert context.detector_id == "test_detector"
        assert context.operation == "detect"
        assert context.input_data == {"key": "value"}
        assert context.additional == {"extra": "data"}
    
    def test_from_dict_with_defaults(self):
        """Test deserialization with missing fields."""
        data = {}
        context = ErrorContext.from_dict(data)
        assert context.detector_id is None
        assert context.operation is None
        assert context.input_data == {}
        assert context.additional == {}
    
    def test_with_additional(self):
        """Test adding additional context."""
        context = ErrorContext(additional={"original": "value"})
        new_context = context.with_additional(new_key="new_value")
        
        # Original should be unchanged
        assert context.additional == {"original": "value"}
        # New context should have both
        assert new_context.additional == {"original": "value", "new_key": "new_value"}
    
    def test_immutability(self):
        """Test that ErrorContext is immutable."""
        context = ErrorContext(detector_id="test")
        with pytest.raises(AttributeError):
            context.detector_id = "new_id"


# =============================================================================
# ErrorMetadata Tests
# =============================================================================

class TestErrorMetadata:
    """Test ErrorMetadata data class."""
    
    def test_construction(self):
        """Test basic construction."""
        now = datetime.now()
        metadata = ErrorMetadata(
            error_code="TEST_001",
            category=ErrorCategory.VALIDATION,
            timestamp=now,
            version="2.3.0",
            request_id="req-123"
        )
        assert metadata.error_code == "TEST_001"
        assert metadata.category == ErrorCategory.VALIDATION
        assert metadata.timestamp == now
        assert metadata.version == "2.3.0"
        assert metadata.request_id == "req-123"
    
    def test_default_version(self):
        """Test that version defaults to "2.3.0"."""
        metadata = ErrorMetadata(
            error_code="TEST_001",
            category=ErrorCategory.VALIDATION,
            timestamp=datetime.now()
        )
        assert metadata.version == "2.3.0"
    
    def test_to_dict(self):
        """Test serialization to dictionary."""
        now = datetime.now()
        metadata = ErrorMetadata(
            error_code="TEST_001",
            category=ErrorCategory.VALIDATION,
            timestamp=now,
            request_id="req-123"
        )
        data = metadata.to_dict()
        assert data["error_code"] == "TEST_001"
        assert data["category"] == "validation"
        assert data["timestamp"] == now.isoformat()
        assert data["version"] == "2.3.0"
        assert data["request_id"] == "req-123"
    
    def test_from_dict(self):
        """Test deserialization from dictionary."""
        now = datetime.now()
        data = {
            "error_code": "TEST_001",
            "category": "validation",
            "timestamp": now.isoformat(),
            "version": "2.3.0",
            "request_id": "req-123"
        }
        metadata = ErrorMetadata.from_dict(data)
        assert metadata.error_code == "TEST_001"
        assert metadata.category == ErrorCategory.VALIDATION
        assert metadata.request_id == "req-123"
    
    def test_immutability(self):
        """Test that ErrorMetadata is immutable."""
        metadata = ErrorMetadata(
            error_code="TEST_001",
            category=ErrorCategory.VALIDATION,
            timestamp=datetime.now()
        )
        with pytest.raises(AttributeError):
            metadata.error_code = "NEW_001"


# =============================================================================
# DetectionError Tests
# =============================================================================

class TestDetectionError:
    """Test DetectionError base class."""
    
    def test_basic_construction(self):
        """Test basic error construction."""
        error = DetectionError("Something went wrong")
        assert error.message == "Something went wrong"
        assert error.context.detector_id is None
        assert error.error_code == "DETECT_001"
        assert error.category == ErrorCategory.UNKNOWN
    
    def test_full_construction(self):
        """Test construction with all fields."""
        context = ErrorContext(detector_id="test_detector")
        metadata = ErrorMetadata(
            error_code="TEST_001",
            category=ErrorCategory.VALIDATION,
            timestamp=datetime.now()
        )
        cause = ValueError("Original error")
        
        error = DetectionError(
            message="Wrapped error",
            context=context,
            metadata=metadata,
            cause=cause
        )
        
        assert error.message == "Wrapped error"
        assert error.context.detector_id == "test_detector"
        assert error.error_code == "TEST_001"
        assert error.category == ErrorCategory.VALIDATION
        assert error.cause == cause
    
    def test_str_representation(self):
        """Test string representation."""
        error = DetectionError("Test message")
        assert str(error) == "[DETECT_001] Test message"
    
    def test_repr_representation(self):
        """Test repr representation."""
        error = DetectionError("Test message")
        repr_str = repr(error)
        assert "DetectionError" in repr_str
        assert "DETECT_001" in repr_str
        assert "Test message" in repr_str
    
    def test_inheritance_from_exception(self):
        """Test that DetectionError inherits from Exception."""
        error = DetectionError("Test")
        assert isinstance(error, Exception)
        
        # Can be caught as Exception
        try:
            raise error
        except Exception as e:
            assert e.message == "Test"
    
    def test_to_dict_basic(self):
        """Test basic serialization to dict."""
        error = DetectionError("Test message")
        data = error.to_dict()
        
        assert data["message"] == "Test message"
        assert data["error_type"] == "DetectionError"
        assert "context" in data
        assert "metadata" in data
        assert "cause" not in data  # No cause
    
    def test_to_dict_with_cause(self):
        """Test serialization with cause."""
        cause = ValueError("Original")
        error = DetectionError("Wrapped", cause=cause)
        data = error.to_dict()
        
        assert "cause" in data
        assert data["cause"]["type"] == "ValueError"
        assert data["cause"]["message"] == "Original"
    
    def test_to_json(self):
        """Test serialization to JSON."""
        error = DetectionError("Test message")
        json_str = error.to_json()
        
        assert isinstance(json_str, str)
        data = json.loads(json_str)
        assert data["message"] == "Test message"
    
    def test_to_json_with_indent(self):
        """Test JSON serialization with indentation."""
        error = DetectionError("Test")
        json_str = error.to_json(indent=2)
        
        assert isinstance(json_str, str)
        assert "\n" in json_str  # Indented
    
    def test_from_dict(self):
        """Test deserialization from dict."""
        original = DetectionError(
            message="Test message",
            context=ErrorContext(detector_id="test"),
            metadata=ErrorMetadata(
                error_code="TEST_001",
                category=ErrorCategory.VALIDATION,
                timestamp=datetime.now()
            )
        )
        
        data = original.to_dict()
        restored = DetectionError.from_dict(data)
        
        assert restored.message == "Test message"
        assert restored.context.detector_id == "test"
        assert restored.error_code == "TEST_001"
    
    def test_from_json(self):
        """Test deserialization from JSON."""
        original = DetectionError("Test message")
        json_str = original.to_json()
        restored = DetectionError.from_json(json_str)
        
        assert restored.message == "Test message"
        assert restored.error_code == "DETECT_001"
    
    def test_with_context(self):
        """Test adding context to existing error."""
        error = DetectionError("Test")
        new_error = error.with_context(extra_field="extra_value")
        
        # Original unchanged
        assert error.context.additional == {}
        # New error has context
        assert new_error.context.additional == {"extra_field": "extra_value"}
        # Other fields preserved
        assert new_error.message == "Test"
    
    def test_round_trip_serialization(self):
        """Test that serialization and deserialization preserve data."""
        original = DetectionError(
            message="Test message",
            context=ErrorContext(
                detector_id="detector_1",
                operation="detect",
                input_data={"key": "value"}
            ),
            metadata=ErrorMetadata(
                error_code="TEST_001",
                category=ErrorCategory.VALIDATION,
                timestamp=datetime.now(),
                request_id="req-123"
            )
        )
        
        # Serialize and deserialize
        json_str = original.to_json()
        restored = DetectionError.from_json(json_str)
        
        assert restored.message == original.message
        assert restored.context.detector_id == original.context.detector_id
        assert restored.error_code == original.error_code
        assert restored.category == original.category


# =============================================================================
# Error Hierarchy Tests
# =============================================================================

class TestErrorHierarchy:
    """Test error class hierarchy and inheritance."""
    
    def test_validation_error_inheritance(self):
        """Test ValidationError inherits from DetectionError."""
        error = ValidationError("Invalid input")
        assert isinstance(error, DetectionError)
        assert error.error_code == "VALID_001"
        assert error.category == ErrorCategory.VALIDATION
    
    def test_configuration_error_inheritance(self):
        """Test ConfigurationError inherits from DetectionError."""
        error = ConfigurationError("Missing config")
        assert isinstance(error, DetectionError)
        assert error.error_code == "CONF_001"
        assert error.category == ErrorCategory.CONFIGURATION
    
    def test_runtime_error_inheritance(self):
        """Test RuntimeError inherits from DetectionError."""
        error = RuntimeError("Runtime failure")
        assert isinstance(error, DetectionError)
        assert error.error_code == "RUN_001"
        assert error.category == ErrorCategory.RUNTIME
    
    def test_security_error_inheritance(self):
        """Test SecurityError inherits from DetectionError."""
        error = SecurityError("Security violation")
        assert isinstance(error, DetectionError)
        assert error.error_code == "SEC_001"
        assert error.category == ErrorCategory.SECURITY
    
    def test_network_error_inheritance(self):
        """Test NetworkError inherits from DetectionError."""
        error = NetworkError("Connection failed")
        assert isinstance(error, DetectionError)
        assert error.error_code == "NET_001"
        assert error.category == ErrorCategory.NETWORK
    
    def test_resource_error_inheritance(self):
        """Test ResourceError inherits from DetectionError."""
        error = ResourceError("Out of memory")
        assert isinstance(error, DetectionError)
        assert error.error_code == "RES_001"
        assert error.category == ErrorCategory.RESOURCE
    
    def test_error_registry(self):
        """Test that all error classes are in the registry."""
        assert "DetectionError" in ERROR_REGISTRY
        assert "ValidationError" in ERROR_REGISTRY
        assert "ConfigurationError" in ERROR_REGISTRY
        assert "RuntimeError" in ERROR_REGISTRY
        assert "SecurityError" in ERROR_REGISTRY
        assert "NetworkError" in ERROR_REGISTRY
        assert "ResourceError" in ERROR_REGISTRY
    
    def test_polymorphic_deserialization_validation(self):
        """Test that ValidationError deserializes correctly."""
        original = ValidationError("Test")
        data = original.to_dict()
        restored = DetectionError.from_dict(data)
        
        assert isinstance(restored, ValidationError)
        assert restored.error_code == "VALID_001"
    
    def test_polymorphic_deserialization_security(self):
        """Test that SecurityError deserializes correctly."""
        original = SecurityError("Test")
        data = original.to_dict()
        restored = DetectionError.from_dict(data)
        
        assert isinstance(restored, SecurityError)
        assert restored.error_code == "SEC_001"
    
    def test_exception_catching_hierarchy(self):
        """Test that parent catches children in except clauses."""
        errors = [
            ValidationError("Validation failed"),
            ConfigurationError("Config missing"),
            RuntimeError("Runtime issue"),
        ]
        
        caught = 0
        for error in errors:
            try:
                raise error
            except DetectionError:
                caught += 1
        
        assert caught == 3


# =============================================================================
# Edge Cases Tests
# =============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_empty_message(self):
        """Test error with empty message."""
        error = DetectionError("")
        assert error.message == ""
        assert str(error) == "[DETECT_001] "
    
    def test_empty_context(self):
        """Test error with empty/default context."""
        error = DetectionError("Test")
        assert error.context.detector_id is None
        assert error.context.operation is None
        assert error.context.input_data == {}
        assert error.context.additional == {}
    
    def test_none_context(self):
        """Test error with None context (should create default)."""
        error = DetectionError("Test", context=None)
        assert error.context is not None
        assert isinstance(error.context, ErrorContext)
    
    def test_nested_error_cause(self):
        """Test error with another DetectionError as cause."""
        inner = ValidationError("Inner error")
        outer = DetectionError("Outer error", cause=inner)
        
        assert outer.cause == inner
        assert isinstance(outer.cause, ValidationError)
    
    def test_deeply_nested_context(self):
        """Test context with deeply nested data."""
        deep_data = {
            "level1": {
                "level2": {
                    "level3": ["item1", "item2"]
                }
            }
        }
        context = ErrorContext(input_data=deep_data)
        error = DetectionError("Test", context=context)
        
        # Should serialize/deserialize correctly
        json_str = error.to_json()
        restored = DetectionError.from_json(json_str)
        
        assert restored.context.input_data["level1"]["level2"]["level3"] == ["item1", "item2"]
    
    def test_unicode_message(self):
        """Test error with unicode message."""
        error = DetectionError("错误信息 🚨 émojis")
        json_str = error.to_json()
        restored = DetectionError.from_json(json_str)
        
        assert restored.message == "错误信息 🚨 émojis"
    
    def test_very_long_message(self):
        """Test error with very long message."""
        long_message = "A" * 10000
        error = DetectionError(long_message)
        
        json_str = error.to_json()
        restored = DetectionError.from_json(json_str)
        
        assert restored.message == long_message
    
    def test_special_characters_in_message(self):
        """Test error with special characters."""
        message = 'Special chars: "quotes" \n newlines \t tabs \\ backslash'
        error = DetectionError(message)
        
        json_str = error.to_json()
        restored = DetectionError.from_json(json_str)
        
        assert restored.message == message
    
    def test_datetime_precision(self):
        """Test that datetime is preserved through serialization."""
        now = datetime.now()
        metadata = ErrorMetadata(
            error_code="TEST_001",
            category=ErrorCategory.VALIDATION,
            timestamp=now
        )
        error = DetectionError("Test", metadata=metadata)
        
        json_str = error.to_json()
        restored = DetectionError.from_json(json_str)
        
        # Compare ISO format strings due to microsecond precision
        assert restored.metadata.timestamp.isoformat() == now.isoformat()


# =============================================================================
# Utility Function Tests
# =============================================================================

class TestUtilityFunctions:
    """Test utility functions."""
    
    def test_register_error_class(self):
        """Test registering custom error class."""
        class CustomError(DetectionError):
            DEFAULT_ERROR_CODE = "CUST_001"
            DEFAULT_CATEGORY = ErrorCategory.UNKNOWN
        
        register_error_class("CustomError", CustomError)
        
        assert "CustomError" in ERROR_REGISTRY
        assert ERROR_REGISTRY["CustomError"] == CustomError
    
    def test_create_error_from_exception_value_error(self):
        """Test creating error from ValueError."""
        original = ValueError("Invalid value")
        error = create_error_from_exception(original, "detector_1", "detect")
        
        assert error.message == "Invalid value"
        assert error.category == ErrorCategory.VALIDATION
        assert error.context.detector_id == "detector_1"
        assert error.context.operation == "detect"
        assert error.cause == original
        assert error.context.stack_trace is not None
    
    def test_create_error_from_exception_connection_error(self):
        """Test creating error from ConnectionError."""
        original = ConnectionError("Connection refused")
        error = create_error_from_exception(original)
        
        assert error.category == ErrorCategory.NETWORK
        assert error.error_code == "NET_001"
    
    def test_create_error_from_exception_memory_error(self):
        """Test creating error from MemoryError."""
        original = MemoryError("Out of memory")
        error = create_error_from_exception(original)
        
        assert error.category == ErrorCategory.RESOURCE
        assert error.error_code == "RES_001"
    
    def test_create_error_from_exception_timeout_error(self):
        """Test creating error from TimeoutError."""
        original = TimeoutError("Operation timed out")
        error = create_error_from_exception(original)
        
        assert error.category == ErrorCategory.RUNTIME
        assert error.error_code == "RUN_001"
    
    def test_create_error_from_exception_unknown_type(self):
        """Test creating error from unknown exception type."""
        original = RuntimeError("Generic error")
        error = create_error_from_exception(original)
        
        assert error.category == ErrorCategory.UNKNOWN
    
    def test_validation_error_helper(self):
        """Test validation_error convenience function."""
        error = validation_error("Invalid input", field="threshold")
        
        assert isinstance(error, ValidationError)
        assert error.message == "Invalid input"
        assert error.category == ErrorCategory.VALIDATION
        assert error.context.additional == {"field": "threshold"}
    
    def test_configuration_error_helper(self):
        """Test configuration_error convenience function."""
        error = configuration_error("Missing key", key="threshold")
        
        assert isinstance(error, ConfigurationError)
        assert error.message == "Missing key"
        assert error.category == ErrorCategory.CONFIGURATION
    
    def test_runtime_error_helper(self):
        """Test runtime_error convenience function."""
        error = runtime_error("Timeout", duration=30)
        
        assert isinstance(error, RuntimeError)
        assert error.message == "Timeout"
        assert error.category == ErrorCategory.RUNTIME
        assert error.context.additional == {"duration": 30}


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for error contract."""
    
    def test_full_error_workflow(self):
        """Test complete error creation, serialization, and deserialization workflow."""
        # Create error with full context
        error = ValidationError(
            message="Input validation failed",
            context=ErrorContext(
                detector_id="prompt_injection_detector",
                operation="validate_threshold",
                input_data={"threshold": 1.5, "valid_range": [0, 1]},
                additional={"validation_type": "range_check"}
            ),
            metadata=ErrorMetadata(
                error_code="VALID_001",
                category=ErrorCategory.VALIDATION,
                timestamp=datetime.now(),
                request_id="req-abc-123"
            ),
            cause=ValueError("Threshold out of range")
        )
        
        # Serialize to JSON
        json_str = error.to_json(indent=2)
        
        # Deserialize
        restored = DetectionError.from_json(json_str)
        
        # Verify all fields
        assert isinstance(restored, ValidationError)
        assert restored.message == "Input validation failed"
        assert restored.context.detector_id == "prompt_injection_detector"
        assert restored.context.operation == "validate_threshold"
        assert restored.context.input_data["threshold"] == 1.5
        assert restored.error_code == "VALID_001"
        assert restored.category == ErrorCategory.VALIDATION
        assert restored.metadata.request_id == "req-abc-123"
        # Note: cause is serialized but not restored as an object (only type/message preserved)
        # This is expected behavior - cause info is available in serialized form
    
    def test_error_chaining(self):
        """Test error chaining with multiple levels."""
        # Level 1: Original exception
        try:
            raise ValueError("Database connection failed")
        except ValueError as e:
            # Level 2: Wrap in NetworkError
            network_error = NetworkError(
                message="Failed to fetch threat intel",
                cause=e
            )
            
            # Level 3: Wrap in DetectionError
            detection_error = DetectionError(
                message="Detection aborted",
                cause=network_error
            )
        
        # Verify chain
        assert detection_error.cause == network_error
        assert detection_error.cause.cause is not None
        # The deepest cause is a plain ValueError, not a DetectionError
        assert str(detection_error.cause.cause) == "Database connection failed"
    
    def test_multiple_errors_collection(self):
        """Test collecting and serializing multiple errors."""
        errors = [
            ValidationError("Invalid threshold"),
            ConfigurationError("Missing API key"),
            RuntimeError("Detector timeout"),
        ]
        
        # Serialize all
        serialized = [e.to_dict() for e in errors]
        
        # Deserialize all
        restored = [DetectionError.from_dict(d) for d in serialized]
        
        # Verify types preserved
        assert isinstance(restored[0], ValidationError)
        assert isinstance(restored[1], ConfigurationError)
        assert isinstance(restored[2], RuntimeError)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])