"""Dashboard Web Server

Flask-based HTTP server for the AgentGuard dashboard.
"""

import os
import sys
from pathlib import Path
from flask import Flask, send_from_directory, jsonify
from flask_cors import CORS

# Get the directory containing this file
DASHBOARD_DIR = Path(__file__).parent.resolve()
STATIC_DIR = DASHBOARD_DIR / "static"

def create_app():
    """Create and configure the Flask application."""
    app = Flask(
        __name__,
        static_folder=str(STATIC_DIR),
        static_url_path="/static",
    )
    
    # Enable CORS for API endpoints
    CORS(app, resources={
        r"/api/*": {
            "origins": "*",
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type"],
        }
    })
    
    # Register API blueprint
    from .api import api_bp
    app.register_blueprint(api_bp)
    
    @app.route("/")
    def index():
        """Serve the main dashboard page."""
        return send_from_directory(STATIC_DIR, "index.html")
    
    @app.route("/health")
    def health():
        """Health check endpoint."""
        return jsonify({"status": "ok"})
    
    @app.errorhandler(404)
    def not_found(e):
        """Handle 404 errors."""
        return jsonify({"error": "Not found"}), 404
    
    @app.errorhandler(500)
    def server_error(e):
        """Handle 500 errors."""
        return jsonify({"error": "Internal server error"}), 500
    
    return app

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 20118

def run_server(host=DEFAULT_HOST, port=DEFAULT_PORT, debug=False):
    """Run the dashboard server.
    
    Args:
        host: Host to bind to (default: 127.0.0.1 - localhost only for security)
        port: Port to listen on (default: 20118)
        debug: Enable Flask debug mode (default: False)
    """
    app = create_app()
    
    print(f"🛡️  XClaw AgentGuard Dashboard")
    print(f"   URL: http://{host}:{port}")
    print(f"   API: http://{host}:{port}/api")
    print(f"   Press Ctrl+C to stop")
    print()
    
    app.run(host=host, port=port, debug=debug)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="XClaw AgentGuard Dashboard")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Host to bind to (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port to listen on (default: {DEFAULT_PORT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()
    run_server(host=args.host, port=args.port, debug=args.debug)
