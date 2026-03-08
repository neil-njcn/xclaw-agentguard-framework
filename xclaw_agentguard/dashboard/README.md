# XClaw AgentGuard Dashboard

A minimal web dashboard for monitoring and controlling the XClaw AgentGuard security system.

## Features

- 📊 **Real-time Status Overview** - System health, uptime, active detectors/plugins
- 🔍 **Detector Control** - Enable/disable all 12 security detectors with toggle switches
- 🔌 **Plugin Management** - Control built-in plugins (report formatter, audit logger, etc.)
- 📈 **Statistics Charts** - 24-hour detection visualization
- ⚙️ **Configuration Editor** - Live JSON configuration with hot-reload
- 📝 **Log Viewer** - Filterable detection logs with real-time updates
- 📱 **Mobile Responsive** - Works on desktop and mobile devices

## Quick Start

```bash
# From the project root
python -m xclaw_agentguard.dashboard.server

# Or use the server directly
python -c "from xclaw_agentguard.dashboard import run_server; run_server()"
```

Then open http://127.0.0.1:20118 in your browser.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | System status overview |
| `/api/stats` | GET | Detailed statistics |
| `/api/detectors` | GET | List all detectors |
| `/api/plugins` | GET | List all plugins |
| `/api/toggle` | POST | Toggle detector/plugin |
| `/api/config` | GET | Get configuration |
| `/api/config` | POST | Update configuration |
| `/api/logs` | GET | Recent detection logs |

### Toggle Component

```bash
curl -X POST http://127.0.0.1:20118/api/toggle \
  -H "Content-Type: application/json" \
  -d '{"type": "detector", "name": "prompt_injection", "enabled": false}'
```

### Update Configuration

```bash
curl -X POST http://127.0.0.1:20118/api/config \
  -H "Content-Type: application/json" \
  -d '{"log_level": "DEBUG"}'
```

## File Structure

```
dashboard/
├── __init__.py      # Package exports
├── server.py        # Flask HTTP server
├── api.py           # REST API endpoints
└── static/
    ├── index.html   # Dashboard UI
    └── style.css    # Minimalist styling
```

## Auto-Refresh

The dashboard polls for updates every 5 seconds:
- Status indicators update automatically
- Logs refresh in real-time
- Toggle changes reflect immediately

## Configuration

Default server options:
- **Host**: `127.0.0.1` (localhost only, for security)
- **Port**: `20118` (configurable via `--port`)
- **Debug**: `false` (enable with `--debug`)

```bash
# Custom host and port (use with caution - 0.0.0.0 exposes to network)
python -m xclaw_agentguard.dashboard.server --host 0.0.0.0 --port 8080

# Enable debug mode
python -m xclaw_agentguard.dashboard.server --debug
```
