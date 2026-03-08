# Example Plugin

A sample plugin demonstrating the XClaw XClaw AgentGuard plugin API.

## Structure

```
example_plugin/
├── __init__.py       # Package entry
├── manifest.json     # Plugin manifest
└── plugin.py         # Main implementation
```

## Usage

```python
from xclaw_agentguard.plugins.example_plugin import ExamplePlugin

plugin = ExamplePlugin()
result = plugin.custom_check("test.txt", "content with EXAMPLE_VIOLATION")
```

## Manifest Format

```json
{
  "id": "example_plugin",
  "name": "Example Plugin",
  "version": "1.0.0",
  "author": "XClaw AgentGuard Team",
  "description": "An example plugin for XClaw AgentGuard",
  "requires_core": "^2.3.0",
  "entry_point": "plugin.py:ExamplePlugin"
}
```
