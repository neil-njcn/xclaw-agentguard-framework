"""
XClaw AgentGuard Example Plugin

A sample plugin demonstrating the XClaw AgentGuard plugin API.
"""

from xclaw_agentguard import AntiJackExtension, ExtensionViolation


class ExamplePlugin(AntiJackExtension):
    """
    示例插件：展示基本结构和API用法
    """
    
    PLUGIN_ID = "example_plugin"
    PLUGIN_VERSION = "1.0.0"
    PLUGIN_NAME = "Example Plugin"
    
    def get_metadata(self):
        return {
            "id": self.PLUGIN_ID,
            "version": self.PLUGIN_VERSION,
            "name": self.PLUGIN_NAME,
            "description": "An example plugin for XClaw AgentGuard",
            "author": "XClaw AgentGuard Team",
        }
    
    def custom_check(self, file_path: str, content: str = None) -> list:
        """自定义检查规则"""
        violations = []
        
        if content and "EXAMPLE_VIOLATION" in content:
            violations.append(ExtensionViolation(
                path=file_path,
                violation_type="example_pattern",
                severity="low",
                message="Found example violation pattern",
            ))
        
        return violations
