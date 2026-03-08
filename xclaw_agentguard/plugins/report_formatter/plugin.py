"""
XClaw AgentGuard Report Formatter Plugin

A comprehensive output formatting plugin that converts detection results into multiple 
standardized formats including JSON, Markdown, and CSV. Designed for integration with 
CI/CD pipelines, audit systems, and security dashboards.

Features:
    - Multi-format output support (JSON, Markdown, CSV)
    - Batch processing capabilities for bulk report generation
    - Configurable formatting options (indentation, delimiters)
    - Metadata serialization with automatic type handling
    - Thread-safe formatter instantiation

Usage Scenarios:
    - Exporting scan results to security information systems
    - Generating human-readable audit reports
    - Feeding detection data into automated response systems
    - Creating compliance documentation for security reviews

Example:
    >>> from xclaw_agentguard.plugins.report_formatter import ReportFormatterPlugin
    >>> result = detector.detect(some_input)
    >>> json_output = ReportFormatterPlugin.format_result(result, "json")
    >>> print(json_output)

Plugin Development Guide:
    To add a new formatter:
    1. Create a class inheriting from BaseFormatter
    2. Implement format() for single result formatting
    3. Implement format_batch() for batch result formatting
    4. Register the formatter in ReportFormatterPlugin.FORMATTERS dict
    5. Follow existing patterns for metadata serialization

Author: XClaw AgentGuard Team
Version: 1.0.0
"""

import json
import csv
import io
from typing import List, Dict, Any, Optional
from datetime import datetime

from xclaw_agentguard import DetectionResult


class BaseFormatter:
    """
    Abstract base class for all output formatters.
    
    Implement this class to create custom output formats. Subclasses must
    implement both format() and format_batch() methods to ensure consistent
    API across all formatter implementations.
    
    Attributes:
        None - Base class defines interface only
        
    Example:
        >>> class XMLFormatter(BaseFormatter):
        ...     def format(self, result: DetectionResult) -> str:
        ...         return f"<result>{result.detected}</result>"
        ...     def format_batch(self, results: List[tuple]) -> str:
        ...         return "<batch>...</batch>"
    """
    
    def format(self, result: DetectionResult) -> str:
        """
        Format a single DetectionResult into the target output format.
        
        Args:
            result: A DetectionResult instance containing threat detection data
            
        Returns:
            str: The formatted result string
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
            
        Example:
            >>> formatter = JSONFormatter()
            >>> output = formatter.format(detection_result)
        """
        raise NotImplementedError("Subclasses must implement format()")
    
    def format_batch(self, results: List[tuple]) -> str:
        """
        Format multiple detection results as a batch.
        
        Args:
            results: List of tuples containing (detector_name, input_text, result).
                    Each tuple represents one detection operation with its context.
                    
        Returns:
            str: The formatted batch output string
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
            
        Example:
            >>> results = [
            ...     ("prompt_injection", "input text", result1),
            ...     ("sql_injection", "more text", result2)
            ... ]
            >>> output = formatter.format_batch(results)
        """
        raise NotImplementedError("Subclasses must implement format_batch()")


class JSONFormatter(BaseFormatter):
    """
    JSON output formatter with configurable indentation.
    
    Produces RFC 8259 compliant JSON output suitable for API responses,
    log aggregation, and machine processing. Handles metadata serialization
    automatically using available conversion methods.
    
    Attributes:
        indent: Number of spaces for indentation (None for compact output)
        
    Configuration Options:
        - indent: Integer or None (default: 2 spaces)
            Controls JSON formatting. Use None for production logs,
            positive integer for human-readable output.
            
    Example:
        >>> # Pretty-printed output for debugging
        >>> formatter = JSONFormatter(indent=2)
        >>> 
        >>> # Compact output for production APIs
        >>> compact_formatter = JSONFormatter(indent=None)
    """
    
    def __init__(self, indent: Optional[int] = 2):
        """
        Initialize JSON formatter with specified indentation.
        
        Args:
            indent: Number of spaces per indentation level. Use None for 
                   compact single-line output. Default is 2 for readability.
        """
        self.indent = indent
    
    def format(self, result: DetectionResult) -> str:
        """
        Serialize a single DetectionResult to JSON format.
        
        Handles metadata serialization through method detection:
        1. Uses to_dict() if available (dataclass/dataclass-like)
        2. Falls back to __dict__ for object attributes
        3. Uses dict() constructor as final fallback
        
        Args:
            result: DetectionResult instance to serialize
            
        Returns:
            str: JSON-formatted string with the following structure:
                {
                    "detected": bool,
                    "threat_level": str | null,
                    "attack_types": [str],
                    "confidence": float,
                    "timestamp": str (ISO 8601),
                    "metadata": object
                }
                
        Example Output:
            {
                "detected": true,
                "threat_level": "HIGH",
                "attack_types": ["PROMPT_INJECTION"],
                "confidence": 0.95,
                "timestamp": "2024-01-15T09:30:00",
                "metadata": {"rule_id": "PI-001"}
            }
        """
        # Serialize metadata using available conversion methods
        metadata_dict = {}
        if result.metadata:
            if hasattr(result.metadata, 'to_dict'):
                metadata_dict = result.metadata.to_dict()
            elif hasattr(result.metadata, '__dict__'):
                metadata_dict = result.metadata.__dict__
            else:
                metadata_dict = dict(result.metadata)
        
        data = {
            "detected": result.detected,
            "threat_level": str(result.threat_level) if result.threat_level else None,
            "attack_types": [str(at) for at in result.attack_types] if result.attack_types else [],
            "confidence": result.confidence,
            "timestamp": result.timestamp.isoformat() if result.timestamp else None,
            "metadata": metadata_dict,
        }
        return json.dumps(data, indent=self.indent, ensure_ascii=False)
    
    def format_batch(self, results: List[tuple]) -> str:
        """
        Serialize multiple detection results to a JSON array.
        
        Args:
            results: List of tuples in format (detector_name, input_text, result).
                    Input text is truncated to 100 characters with ellipsis.
                    
        Returns:
            str: JSON array string where each element contains:
                - detector: Name of the detector that produced the result
                - input_preview: Truncated input text sample
                - detected: Boolean threat detection status
                - threat_level: Severity level as string
                - attack_types: List of attack classifications
                - confidence: Detection confidence score (0.0-1.0)
                
        Example Output:
            [
                {
                    "detector": "prompt_injection",
                    "input_preview": "Ignore previous instructions...",
                    "detected": true,
                    "threat_level": "HIGH",
                    "attack_types": ["PROMPT_INJECTION"],
                    "confidence": 0.92
                }
            ]
        """
        data = []
        for detector_name, input_text, result in results:
            data.append({
                "detector": detector_name,
                "input_preview": input_text[:100] + "..." if len(input_text) > 100 else input_text,
                "detected": result.detected,
                "threat_level": str(result.threat_level) if result.threat_level else None,
                "attack_types": [str(at) for at in result.attack_types] if result.attack_types else [],
                "confidence": result.confidence,
            })
        return json.dumps(data, indent=self.indent, ensure_ascii=False)


class MarkdownFormatter(BaseFormatter):
    """
    Markdown table formatter for human-readable reports.
    
    Generates GitHub-flavored Markdown suitable for documentation,
    issue trackers, and email reports. Produces hierarchical document
    structure with headers and tables.
    
    Features:
        - Single result reports with metadata sections
        - Batch summary tables with alignment
        - Automatic pipe character escaping in table cells
        - Timestamp generation for audit trails
        
    Usage Scenarios:
        - Security incident reports in GitHub issues
        - Executive summary emails
        - Wiki documentation updates
        
    Example:
        >>> formatter = MarkdownFormatter()
        >>> report = formatter.format_batch(scan_results)
        >>> # Save to file or post to GitHub issue
    """
    
    def format(self, result: DetectionResult) -> str:
        """
        Format a single DetectionResult as a Markdown document.
        
        Generates a structured report with the following sections:
        - Detection status (Yes/No)
        - Threat level classification
        - Attack type enumeration
        - Confidence percentage
        - ISO timestamp
        - Metadata key-value pairs (if present)
        
        Args:
            result: DetectionResult instance to format
            
        Returns:
            str: Markdown document with headers and bullet lists
            
        Example Output:
            ## Detection Result
            
            - **Detected**: Yes
            - **Threat Level**: HIGH
            - **Attack Types**: PROMPT_INJECTION, SQL_INJECTION
            - **Confidence**: 95.00%
            - **Timestamp**: 2024-01-15 09:30:00
            
            ### Metadata
            - **rule_id**: PI-001
            - **detector_version**: 1.2.0
        """
        attack_types_str = ", ".join(str(at) for at in result.attack_types) if result.attack_types else "None"
        lines = [
            "## Detection Result",
            "",
            f"- **Detected**: {'Yes' if result.detected else 'No'}",
            f"- **Threat Level**: {result.threat_level}",
            f"- **Attack Types**: {attack_types_str}",
            f"- **Confidence**: {result.confidence:.2%}",
            f"- **Timestamp**: {result.timestamp}",
        ]
        
        if result.metadata:
            lines.extend(["", "### Metadata"])
            # Convert dataclass to dict for iteration
            if hasattr(result.metadata, '__dict__'):
                metadata_dict = result.metadata.__dict__
            else:
                metadata_dict = dict(result.metadata)
            for key, value in metadata_dict.items():
                lines.append(f"- **{key}**: {value}")
        
        return "\n".join(lines)
    
    def format_batch(self, results: List[tuple]) -> str:
        """
        Format multiple results as a Markdown table.
        
        Creates a GitHub-flavored Markdown table with automatic
        header generation and pipe character escaping.
        
        Args:
            results: List of tuples (detector_name, input_text, result)
            
        Returns:
            str: Markdown document with title, timestamp, and data table.
                Table columns: Detector, Detected, Threat Level, Confidence, Input Preview
                
        Example Output:
            # Detection Report
            Generated: 2024-01-15T09:30:00
            
            | Detector | Detected | Threat Level | Confidence | Input Preview |
            |----------|----------|--------------|------------|---------------|
            | prompt_injection | Yes | HIGH | 92.0% | Ignore previous... |
        """
        lines = [
            "# Detection Report",
            f"Generated: {datetime.now().isoformat()}",
            "",
            "| Detector | Detected | Threat Level | Confidence | Input Preview |",
            "|----------|----------|--------------|------------|---------------|",
        ]
        
        for detector_name, input_text, result in results:
            # Escape pipe characters to prevent table corruption
            preview = input_text[:50].replace("|", "\\|") + "..." if len(input_text) > 50 else input_text.replace("|", "\\|")
            lines.append(
                f"| {detector_name} | {'Yes' if result.detected else 'No'} | "
                f"{result.threat_level or '-'} | {result.confidence:.1%} | {preview} |"
            )
        
        return "\n".join(lines)


class CSVFormatter(BaseFormatter):
    """
    CSV (Comma-Separated Values) formatter for spreadsheet compatibility.
    
    Generates RFC 4180 compliant CSV output suitable for import into
    Excel, Google Sheets, pandas DataFrames, and database loaders.
    
    Configuration Options:
        - delimiter: Field separator character (default: ",")
            Use ";" for European locale compatibility, "\t" for TSV format.
            
    Features:
        - Configurable delimiter for locale compatibility
        - Automatic header row generation
        - Proper CSV escaping for special characters
        - Stream-based output for memory efficiency
        
    Usage Scenarios:
        - Bulk data export for spreadsheet analysis
        - SIEM (Security Information and Event Management) ingestion
        - Compliance reporting to regulatory systems
        - Machine learning training data preparation
        
    Example:
        >>> # Standard CSV for US/UK
        >>> formatter = CSVFormatter(delimiter=",")
        >>> 
        >>> # Semicolon for European Excel
        >>> eu_formatter = CSVFormatter(delimiter=";")
        >>> 
        >>> # TSV for Unix command line tools
        >>> tsv_formatter = CSVFormatter(delimiter="\t")
    """
    
    def __init__(self, delimiter: str = ","):
        """
        Initialize CSV formatter with specified delimiter.
        
        Args:
            delimiter: Field separator character. Default is comma (",").
                      Common alternatives: semicolon (";") for Europe,
                      tab ("\t") for TSV format.
        """
        self.delimiter = delimiter
    
    def format(self, result: DetectionResult) -> str:
        """
        Format a single DetectionResult as CSV.
        
        Args:
            result: DetectionResult instance to serialize
            
        Returns:
            str: CSV string with header row and single data row.
                Columns: detected, threat_level, attack_types, confidence, timestamp
                
        Example Output:
            detected,threat_level,attack_types,confidence,timestamp
            True,HIGH,"PROMPT_INJECTION,SQL_INJECTION",0.95,2024-01-15T09:30:00
        """
        output = io.StringIO()
        writer = csv.writer(output, delimiter=self.delimiter)
        writer.writerow(["detected", "threat_level", "attack_types", "confidence", "timestamp"])
        attack_types_str = ", ".join(str(at) for at in result.attack_types) if result.attack_types else ""
        writer.writerow([
            result.detected,
            result.threat_level,
            attack_types_str,
            result.confidence,
            result.timestamp.isoformat() if result.timestamp else "",
        ])
        return output.getvalue()
    
    def format_batch(self, results: List[tuple]) -> str:
        """
        Format multiple results as CSV with consistent schema.
        
        Args:
            results: List of tuples (detector_name, input_text, result)
            
        Returns:
            str: CSV string with header and multiple data rows.
                Columns: detector, input_preview, detected, threat_level, confidence
                Input preview is truncated to 100 characters.
                
        Example Output:
            detector,input_preview,detected,threat_level,confidence
            prompt_injection,"Ignore previous instructions...",True,HIGH,0.92
            sql_injection,"SELECT * FROM users...",False,LOW,0.15
        """
        output = io.StringIO()
        writer = csv.writer(output, delimiter=self.delimiter)
        writer.writerow(["detector", "input_preview", "detected", "threat_level", "confidence"])
        
        for detector_name, input_text, result in results:
            preview = input_text[:100] + "..." if len(input_text) > 100 else input_text
            writer.writerow([
                detector_name,
                preview,
                result.detected,
                result.threat_level,
                result.confidence,
            ])
        
        return output.getvalue()


class ReportFormatterPlugin:
    """
    Central registry and factory for detection result formatters.
    
    This plugin provides a unified interface for formatting DetectionResult
    objects into various output formats. It maintains a registry of available
    formatters and provides convenience methods for common use cases.
    
    Attributes:
        PLUGIN_ID (str): Unique identifier for plugin registration ("report_formatter")
        PLUGIN_VERSION (str): Semantic version of the plugin ("1.0.0")
        PLUGIN_NAME (str): Human-readable plugin name ("Report Formatter")
        FORMATTERS (dict): Mapping of format names to formatter classes
        
    Supported Formats:
        - json: JSONFormatter - Machine-readable structured data
        - markdown: MarkdownFormatter - Human-readable documentation
        - csv: CSVFormatter - Spreadsheet compatible data
        
    Usage Examples:
        
        Basic single result formatting:
        >>> from xclaw_agentguard.plugins.report_formatter import ReportFormatterPlugin
        >>> result = detector.detect(user_input)
        >>> json_output = ReportFormatterPlugin.format_result(result, "json")
        
        Batch processing:
        >>> results = [
        ...     ("detector1", "input1", result1),
        ...     ("detector2", "input2", result2),
        ... ]
        >>> markdown_table = ReportFormatterPlugin.format_batch(results, "markdown")
        
        With configuration:
        >>> # Compact JSON for production
        >>> output = ReportFormatterPlugin.format_result(result, "json", indent=None)
        >>> 
        >>> # European CSV format
        >>> output = ReportFormatterPlugin.format_result(result, "csv", delimiter=";")
        
    Extending the Plugin:
        To add a new formatter:
        
        1. Create a formatter class:
           class XMLFormatter(BaseFormatter):
               def format(self, result): ...
               def format_batch(self, results): ...
        
        2. Register in FORMATTERS:
           ReportFormatterPlugin.FORMATTERS["xml"] = XMLFormatter
        
        3. Use immediately:
           output = ReportFormatterPlugin.format_result(result, "xml")
    """
    
    PLUGIN_ID = "report_formatter"
    PLUGIN_VERSION = "1.0.0"
    PLUGIN_NAME = "Report Formatter"
    
    FORMATTERS = {
        "json": JSONFormatter,
        "markdown": MarkdownFormatter,
        "csv": CSVFormatter,
    }
    
    @classmethod
    def get_formatter(cls, format_type: str, **kwargs) -> BaseFormatter:
        """
        Factory method to create a formatter instance.
        
        Retrieves the appropriate formatter class from the registry and
        instantiates it with the provided keyword arguments.
        
        Args:
            format_type: One of "json", "markdown", or "csv" (case-insensitive)
            **kwargs: Configuration options passed to the formatter constructor:
                     - JSONFormatter: indent (int | None)
                     - CSVFormatter: delimiter (str)
                     - MarkdownFormatter: no additional options
                     
        Returns:
            BaseFormatter: Configured formatter instance ready for use
            
        Raises:
            ValueError: If format_type is not in the supported formats list
            
        Example:
            >>> formatter = ReportFormatterPlugin.get_formatter("json", indent=4)
            >>> formatter = ReportFormatterPlugin.get_formatter("csv", delimiter=";")
        """
        format_type = format_type.lower()
        if format_type not in cls.FORMATTERS:
            raise ValueError(f"Unsupported format: {format_type}. Supported: {list(cls.FORMATTERS.keys())}")
        return cls.FORMATTERS[format_type](**kwargs)
    
    @classmethod
    def format_result(cls, result: DetectionResult, format_type: str = "json", **kwargs) -> str:
        """
        Convenience method: format a single DetectionResult.
        
        This is a one-liner for the common case of formatting a single result.
        Combines get_formatter() and format() into a single call.
        
        Args:
            result: DetectionResult instance to format
            format_type: Target format ("json", "markdown", "csv")
            **kwargs: Formatter-specific configuration options
            
        Returns:
            str: Formatted output string
            
        Raises:
            ValueError: If format_type is not supported
            
        Example:
            >>> result = detector.detect("suspicious input")
            >>> 
            >>> # JSON output for API
            >>> api_response = ReportFormatterPlugin.format_result(result, "json")
            >>> 
            >>> # Markdown for human review
            >>> report = ReportFormatterPlugin.format_result(result, "markdown")
        """
        formatter = cls.get_formatter(format_type, **kwargs)
        return formatter.format(result)
    
    @classmethod
    def format_batch(cls, results: List[tuple], format_type: str = "json", **kwargs) -> str:
        """
        Convenience method: format multiple results as a batch.
        
        Efficiently formats a collection of detection results into a single
        consolidated output document. Preferred over multiple format_result()
        calls when processing multiple inputs.
        
        Args:
            results: List of tuples in format (detector_name, input_text, result).
                    The detector_name identifies which detector produced the result,
                    input_text is the original input (may be truncated in output),
                    and result is the DetectionResult instance.
            format_type: Target format ("json", "markdown", "csv")
            **kwargs: Formatter-specific configuration options
            
        Returns:
            str: Formatted batch output containing all results
            
        Raises:
            ValueError: If format_type is not supported
            
        Example:
            >>> results = []
            >>> for detector_name, detector in detectors.items():
            ...     result = detector.detect(user_input)
            ...     results.append((detector_name, user_input, result))
            >>> 
            >>> # Generate comprehensive report
            >>> report = ReportFormatterPlugin.format_batch(results, "markdown")
            >>> print(report)  # Full detection summary table
        """
        formatter = cls.get_formatter(format_type, **kwargs)
        return formatter.format_batch(results)
    
    @classmethod
    def get_supported_formats(cls) -> List[str]:
        """
        Get the list of available output formats.
        
        Use this method to discover available formatters at runtime,
        for example when building a user interface or CLI help text.
        
        Returns:
            List[str]: Alphabetical list of format identifiers.
                      Currently: ["csv", "json", "markdown"]
                      
        Example:
            >>> formats = ReportFormatterPlugin.get_supported_formats()
            >>> print(f"Available formats: {', '.join(formats)}")
            Available formats: csv, json, markdown
        """
        return list(cls.FORMATTERS.keys())


# =============================================================================
# Convenience Functions
# =============================================================================
# These module-level functions provide a streamlined API for common use cases.
# They are thin wrappers around ReportFormatterPlugin methods for users who
# prefer functional-style APIs over class-based ones.
# =============================================================================

def format_json(result: DetectionResult, indent: int = 2) -> str:
    """
    Format a DetectionResult as pretty-printed JSON.
    
    Convenience function equivalent to:
        ReportFormatterPlugin.format_result(result, "json", indent=indent)
    
    Args:
        result: DetectionResult to format
        indent: Number of spaces for indentation (default: 2)
        
    Returns:
        str: JSON-formatted string
        
    Example:
        >>> result = detector.detect(user_input)
        >>> json_str = format_json(result, indent=4)
        >>> print(json_str)
    """
    return ReportFormatterPlugin.format_result(result, "json", indent=indent)


def format_markdown(result: DetectionResult) -> str:
    """
    Format a DetectionResult as Markdown documentation.
    
    Convenience function equivalent to:
        ReportFormatterPlugin.format_result(result, "markdown")
    
    Args:
        result: DetectionResult to format
        
    Returns:
        str: Markdown-formatted document
        
    Example:
        >>> result = detector.detect(user_input)
        >>> md = format_markdown(result)
        >>> # Post to GitHub issue or send via email
    """
    return ReportFormatterPlugin.format_result(result, "markdown")


def format_csv(result: DetectionResult) -> str:
    """
    Format a DetectionResult as CSV.
    
    Convenience function equivalent to:
        ReportFormatterPlugin.format_result(result, "csv")
    
    Args:
        result: DetectionResult to format
        
    Returns:
        str: CSV-formatted string with header row
        
    Example:
        >>> result = detector.detect(user_input)
        >>> csv = format_csv(result)
        >>> # Write to file or load into pandas
    """
    return ReportFormatterPlugin.format_result(result, "csv")


def format_batch(results: List[tuple], format_type: str = "markdown", **kwargs) -> str:
    """
    Format multiple detection results as a batch.
    
    Convenience function equivalent to:
        ReportFormatterPlugin.format_batch(results, format_type, **kwargs)
    
    Args:
        results: List of tuples (detector_name, input_text, result)
        format_type: Target format - "json", "markdown", or "csv" (default: "markdown")
        **kwargs: Additional formatter options (indent, delimiter, etc.)
        
    Returns:
        str: Formatted batch output
        
    Example:
        >>> results = [
        ...     ("prompt_guard", "input1", result1),
        ...     ("sql_detector", "input2", result2),
        ... ]
        >>> report = format_batch(results, "markdown")
        >>> print(report)  # Summary table of all detections
    """
    return ReportFormatterPlugin.format_batch(results, format_type, **kwargs)


__all__ = [
    # Plugin class
    "ReportFormatterPlugin",
    # Formatter classes for extension
    "BaseFormatter",
    "JSONFormatter",
    "MarkdownFormatter",
    "CSVFormatter",
    # Convenience functions
    "format_json",
    "format_markdown",
    "format_csv",
    "format_batch",
]
