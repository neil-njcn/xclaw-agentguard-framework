"""Dashboard API Endpoints

REST API for the AgentGuard dashboard.
"""

import os
import sys
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from flask import Blueprint, jsonify, request, current_app

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

api_bp = Blueprint("api", __name__, url_prefix="/api")

# In-memory state (would be replaced with proper state management in production)
_detector_states: Dict[str, Dict[str, Any]] = {}
_plugin_states: Dict[str, Dict[str, Any]] = {}
_config: Dict[str, Any] = {}
_logs: List[Dict[str, Any]] = []
_stats: Dict[str, Any] = {
    "total_detections": 0,
    "threats_blocked": 0,
    "detectors_active": 0,
    "plugins_active": 0,
    "uptime_seconds": 0,
    "start_time": time.time(),
}

# Initialize detector states from registry
def _init_detector_states():
    """Initialize detector states from the registry."""
    global _detector_states
    try:
        from xclaw_agentguard.detectors.registry import list_detectors
        detectors = list_detectors()
        for name in detectors:
            if name not in _detector_states:
                _detector_states[name] = {
                    "name": name,
                    "enabled": True,
                    "status": "active",
                    "last_check": None,
                    "detections": 0,
                    "errors": 0,
                }
    except Exception as e:
        # Fallback if registry not available
        _detector_states = {
            "output_injection": {"name": "output_injection", "enabled": True, "status": "active", "last_check": None, "detections": 0, "errors": 0},
            "prompt_injection": {"name": "prompt_injection", "enabled": True, "status": "active", "last_check": None, "detections": 0, "errors": 0},
            "command_injection": {"name": "command_injection", "enabled": True, "status": "active", "last_check": None, "detections": 0, "errors": 0},
            "path_traversal": {"name": "path_traversal", "enabled": True, "status": "active", "last_check": None, "detections": 0, "errors": 0},
            "sql_injection": {"name": "sql_injection", "enabled": True, "status": "active", "last_check": None, "detections": 0, "errors": 0},
            "agent_hijacking": {"name": "agent_hijacking", "enabled": True, "status": "active", "last_check": None, "detections": 0, "errors": 0},
            "context_manipulation": {"name": "context_manipulation", "enabled": True, "status": "active", "last_check": None, "detections": 0, "errors": 0},
            "knowledge_poisoning": {"name": "knowledge_poisoning", "enabled": True, "status": "active", "last_check": None, "detections": 0, "errors": 0},
            "exfiltration_guard": {"name": "exfiltration_guard", "enabled": True, "status": "active", "last_check": None, "detections": 0, "errors": 0},
            "system_prompt_leak": {"name": "system_prompt_leak", "enabled": True, "status": "active", "last_check": None, "detections": 0, "errors": 0},
            "backdoor_code": {"name": "backdoor_code", "enabled": True, "status": "active", "last_check": None, "detections": 0, "errors": 0},
            "jailbreak": {"name": "jailbreak", "enabled": True, "status": "active", "last_check": None, "detections": 0, "errors": 0},
        }

# Initialize plugin states
def _init_plugin_states():
    """Initialize plugin states."""
    global _plugin_states
    _plugin_states = {
        "report_formatter": {"name": "report_formatter", "enabled": True, "status": "active", "version": "1.0.0"},
        "custom_rules": {"name": "custom_rules", "enabled": True, "status": "active", "version": "1.0.0"},
        "audit_logger": {"name": "audit_logger", "enabled": True, "status": "active", "version": "1.0.0"},
        "notification": {"name": "notification", "enabled": True, "status": "active", "version": "1.0.0"},
    }

# Initialize config
def _init_config():
    """Initialize configuration."""
    global _config
    _config = {
        "version": "2.3.0",
        "log_level": "INFO",
        "max_detection_time_ms": 1000,
        "auto_block_threshold": "HIGH",
        "alert_on_detection": True,
        "detectors": {
            "default_enabled": True,
            "parallel_execution": True,
        },
        "plugins": {
            "auto_load": True,
            "sandbox_timeout_seconds": 30,
        },
    }

# Sample logs for demo
def _init_logs():
    """Initialize sample logs."""
    global _logs
    now = time.time()
    _logs = [
        {"timestamp": now - 300, "level": "WARNING", "detector": "prompt_injection", "message": "Potential prompt injection detected", "blocked": True},
        {"timestamp": now - 600, "level": "INFO", "detector": "output_injection", "message": "Detector initialized", "blocked": False},
        {"timestamp": now - 900, "level": "WARNING", "detector": "jailbreak", "message": "Jailbreak attempt blocked", "blocked": True},
        {"timestamp": now - 1200, "level": "ERROR", "detector": "path_traversal", "message": "Timeout during file analysis", "blocked": False},
        {"timestamp": now - 1500, "level": "INFO", "detector": "system", "message": "AgentGuard started", "blocked": False},
    ]

@api_bp.route("/status", methods=["GET"])
def get_status():
    """Get system status."""
    uptime = time.time() - _stats["start_time"]
    active_detectors = sum(1 for d in _detector_states.values() if d["enabled"])
    active_plugins = sum(1 for p in _plugin_states.values() if p["enabled"])
    
    return jsonify({
        "status": "healthy" if active_detectors > 0 else "degraded",
        "version": "2.3.0",
        "uptime_seconds": int(uptime),
        "detectors": {
            "total": len(_detector_states),
            "active": active_detectors,
            "disabled": len(_detector_states) - active_detectors,
        },
        "plugins": {
            "total": len(_plugin_states),
            "active": active_plugins,
            "disabled": len(_plugin_states) - active_plugins,
        },
        "timestamp": time.time(),
    })

@api_bp.route("/stats", methods=["GET"])
def get_stats():
    """Get detailed statistics."""
    uptime = time.time() - _stats["start_time"]
    
    # Generate hourly detection data for the last 24 hours
    hours = 24
    hourly_detections = []
    base_time = time.time() - (hours * 3600)
    
    for i in range(hours):
        hour_time = base_time + (i * 3600)
        # Simulate some detection data
        count = max(0, int(5 + (i % 7) - 3)) if i > 12 else 0
        hourly_detections.append({
            "hour": datetime.fromtimestamp(hour_time).strftime("%H:00"),
            "count": count,
        })
    
    # Detector-specific stats
    detector_stats = []
    for name, state in _detector_states.items():
        detector_stats.append({
            "name": name,
            "enabled": state["enabled"],
            "detections": state["detections"],
            "errors": state["errors"],
            "status": state["status"],
        })
    
    return jsonify({
        "total_detections": _stats["total_detections"],
        "threats_blocked": _stats["threats_blocked"],
        "uptime_seconds": int(uptime),
        "hourly_detections": hourly_detections,
        "detector_stats": detector_stats,
        "timestamp": time.time(),
    })

@api_bp.route("/toggle", methods=["POST"])
def toggle_component():
    """Toggle a detector or plugin."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    
    component_type = data.get("type")
    name = data.get("name")
    enabled = data.get("enabled")
    
    if component_type not in ["detector", "plugin"]:
        return jsonify({"error": "Invalid component type"}), 400
    
    if enabled is None:
        return jsonify({"error": "Missing 'enabled' field"}), 400
    
    if component_type == "detector":
        if name not in _detector_states:
            return jsonify({"error": f"Unknown detector: {name}"}), 404
        _detector_states[name]["enabled"] = enabled
        _detector_states[name]["status"] = "active" if enabled else "disabled"
        return jsonify({
            "success": True,
            "type": "detector",
            "name": name,
            "enabled": enabled,
        })
    else:
        if name not in _plugin_states:
            return jsonify({"error": f"Unknown plugin: {name}"}), 404
        _plugin_states[name]["enabled"] = enabled
        _plugin_states[name]["status"] = "active" if enabled else "disabled"
        return jsonify({
            "success": True,
            "type": "plugin",
            "name": name,
            "enabled": enabled,
        })

@api_bp.route("/config", methods=["GET"])
def get_config():
    """Get current configuration."""
    return jsonify(_config)

@api_bp.route("/config", methods=["POST"])
def update_config():
    """Update configuration (with hot-reload simulation)."""
    global _config
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    
    # Merge new config with existing (simple shallow merge)
    for key, value in data.items():
        if key in _config and isinstance(_config[key], dict) and isinstance(value, dict):
            _config[key].update(value)
        else:
            _config[key] = value
    
    # Log the config change
    _logs.insert(0, {
        "timestamp": time.time(),
        "level": "INFO",
        "detector": "system",
        "message": "Configuration updated",
        "blocked": False,
    })
    
    return jsonify({
        "success": True,
        "config": _config,
        "reloaded": True,
    })

@api_bp.route("/detectors", methods=["GET"])
def list_detectors():
    """List all detectors."""
    return jsonify({
        "detectors": list(_detector_states.values()),
    })

@api_bp.route("/plugins", methods=["GET"])
def list_plugins():
    """List all plugins."""
    return jsonify({
        "plugins": list(_plugin_states.values()),
    })

@api_bp.route("/logs", methods=["GET"])
def get_logs():
    """Get recent detection logs."""
    limit = request.args.get("limit", 100, type=int)
    level = request.args.get("level", None)
    
    filtered_logs = _logs
    if level:
        filtered_logs = [log for log in _logs if log.get("level") == level.upper()]
    
    # Sort by timestamp descending
    sorted_logs = sorted(filtered_logs, key=lambda x: x["timestamp"], reverse=True)
    
    return jsonify({
        "logs": sorted_logs[:limit],
        "total": len(filtered_logs),
        "returned": min(limit, len(filtered_logs)),
    })

# Initialize on module load
_init_detector_states()
_init_plugin_states()
_init_config()
_init_logs()
