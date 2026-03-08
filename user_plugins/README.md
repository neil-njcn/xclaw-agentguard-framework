# User Plugins Directory

This directory is for **user-created custom plugins** that extend XClaw AgentGuard's functionality.

## Why Outside the Package?

```
xclaw_agentguard/          ← Framework package (distributed via pip)
├── plugins/               ← Built-in plugins (part of framework)
user_plugins/              ← Your custom plugins (not distributed)
```

| Aspect | Built-in Plugins | User Plugins |
|--------|-----------------|--------------|
| Location | `xclaw_agentguard/plugins/` | `user_plugins/` (this directory) |
| Maintained by | Framework developers | You |
| Distributed with | pip package | Not distributed |
| Survives upgrades | Yes (part of package) | Yes (separate directory) |
| Version control | Framework repo | Your own repo |

## Quick Start

### 1. Create Your Plugin Directory

```bash
mkdir user_plugins/my_plugin
cd user_plugins/my_plugin
```

### 2. Create Plugin File

`plugin.py`:
```python
from xclaw_agentguard.core.extension_system import AntiJackExtension

class MyPlugin(AntiJackExtension):
    def on_load(self):
        print("My plugin loaded!")
    
    def on_detect(self, result):
        # React to detection results
        if result.is_critical():
            self.send_alert(result)
    
    def send_alert(self, result):
        # Your custom alerting logic
        pass
```

### 3. Create Manifest

`manifest.json`:
```json
{
  "id": "my_plugin",
  "name": "My Custom Plugin",
  "version": "1.0.0",
  "author": "Your Name",
  "requires_core": "^2.3.0",
  "entry_point": "plugin.py:MyPlugin"
}
```

### 4. Use Your Plugin

```python
from xclaw_agentguard.user_plugins.my_plugin.plugin import MyPlugin

plugin = MyPlugin()
plugin.on_load()
```

## Directory Structure

```
user_plugins/
├── README.md              # This file
├── __init__.py            # Package marker
├── plugin_manifest_example.json  # Example manifest
└── my_plugin/             # Your plugin directory
    ├── __init__.py
    ├── manifest.json
    ├── plugin.py
    └── README.md          # Optional: your plugin docs
```

## Example Plugin

See `plugin_manifest_example.json` for a complete manifest example.

See `xclaw_agentguard/plugins/example_plugin/` for a working plugin reference.

## Best Practices

1. **Version your plugins**: Use semantic versioning in manifest
2. **Document dependencies**: List all requirements in manifest
3. **Handle errors gracefully**: Don't crash the framework
4. **Test thoroughly**: Plugins run with framework privileges
5. **Keep backups**: This directory is not version-controlled by the framework

## Security Note

User plugins run with the same privileges as the framework. Only install plugins from trusted sources.