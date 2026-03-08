"""
XClaw AgentGuard User Plugins - User Custom Plugin Directory

User plugin directory structure example:
    my_plugin/
    ├── __init__.py
    ├── manifest.json
    ├── plugin.py
    └── README.md (optional)

manifest.json format:
    {
      "id": "my_plugin",
      "name": "My Plugin",
      "version": "1.0.0",
      "author": "Your Name",
      "requires_core": "^2.3.0",
      "entry_point": "plugin.py:MyPluginClass"
    }

Development steps:
1. Create new directory: mkdir my_plugin
2. Write plugin.py extending AntiJackExtension
3. Create manifest.json defining metadata
4. Import and use: from xclaw_agentguard.user_plugins.my_plugin import MyPlugin

Reference example: plugins/example_plugin/
"""
