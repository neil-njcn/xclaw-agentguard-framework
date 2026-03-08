"""
XClaw AgentGuard Plugin with Version Management - 带版本管理的插件示例

展示如何使用版本管理系统创建具有依赖和兼容性检查的插件。
"""

from xclaw_agentguard import AntiJackExtension, ExtensionViolation
from xclaw_agentguard.core.version_management import (
    PluginVersion, 
    PluginManifest, 
    VersionManager
)


class VersionedExamplePlugin(AntiJackExtension):
    """
    带版本管理的示例插件
    
    特性:
    - 使用 PluginManifest 声明版本和依赖
    - 自动兼容性检查
    - 语义化版本控制
    """
    
    # 插件元数据 (传统方式)
    PLUGIN_ID = "versioned_example"
    PLUGIN_VERSION = "1.2.0"
    PLUGIN_NAME = "Versioned Example Plugin"
    
    # 使用 PluginManifest 定义完整版本信息
    MANIFEST = PluginManifest(
        id="versioned_example",
        name="Versioned Example Plugin",
        version=PluginVersion(1, 2, 0),
        author="Neil",
        description="An example plugin with version management",
        
        # 核心版本要求: 需要 XClaw AgentGuard 2.3.0+
        requires_core="^2.3.0",
        
        # 插件依赖
        dependencies={
            # "some_other_plugin": "^1.0.0",  # 依赖其他插件 >=1.0.0, <2.0.0
        },
        
        # 可选依赖
        optional_dependencies={
            # "optional_plugin": ">=0.5.0",
        },
        
        # 冲突插件
        conflicts=[
            # "conflicting_plugin",
        ],
    )
    
    def __init__(self):
        super().__init__()
        # 获取版本管理器
        self.version_manager = VersionManager(core_version="2.3.0")
    
    def get_metadata(self):
        """返回包含版本信息的元数据"""
        return {
            "id": self.PLUGIN_ID,
            "version": self.PLUGIN_VERSION,
            "name": self.PLUGIN_NAME,
            "manifest": self.MANIFEST.to_dict(),
        }
    
    def check_compatibility(self) -> tuple[bool, list]:
        """
        检查插件兼容性
        
        返回: (是否兼容, 问题列表)
        """
        return self.version_manager.check_compatibility(self.MANIFEST)
    
    def custom_check(self, file_path: str, content: str = None) -> list:
        """
        自定义检查规则
        
        在检查前会自动验证版本兼容性
        """
        # 检查兼容性
        compatible, issues = self.check_compatibility()
        if not compatible:
            # 如果不兼容，返回一个特殊的违规报告
            return [ExtensionViolation(
                path=file_path,
                violation_type="plugin_compatibility_error",
                severity="critical",
                message=f"Plugin compatibility issues: {'; '.join(issues)}",
            )]
        
        violations = []
        
        # 实际的检查逻辑
        if content and "SENSITIVE_DATA" in content:
            violations.append(ExtensionViolation(
                path=file_path,
                violation_type="sensitive_data_exposure",
                severity="high",
                message="Potential sensitive data exposure detected",
                details={
                    "pattern": "SENSITIVE_DATA",
                    "line": content.find("SENSITIVE_DATA"),
                }
            ))
        
        return violations
    
    def get_version_info(self) -> dict:
        """获取版本信息"""
        v = self.MANIFEST.version
        return {
            "version": str(v),
            "major": v.major,
            "minor": v.minor,
            "patch": v.patch,
            "is_prerelease": v.prerelease is not None,
            "next_minor": str(v.bump_minor()),
            "next_patch": str(v.bump_patch()),
        }


# 版本升级示例
class UpgradablePlugin(AntiJackExtension):
    """
    展示版本升级的插件
    """
    
    PLUGIN_ID = "upgradable_plugin"
    PLUGIN_VERSION = "1.0.0"
    PLUGIN_NAME = "Upgradable Plugin"
    
    def __init__(self, current_version: str = "1.0.0"):
        super().__init__()
        self.current_version = PluginVersion.parse(current_version)
        self.version_manager = VersionManager()
        # 注册当前版本
        self.version_manager.register_plugin(PluginManifest(
            id=self.PLUGIN_ID,
            name=self.PLUGIN_NAME,
            version=self.current_version,
            author="Neil",
            description="Plugin that can be upgraded",
        ))
    
    def check_upgrade(self, new_version_str: str) -> dict:
        """检查是否可以升级到指定版本"""
        new_version = PluginVersion.parse(new_version_str)
        can_upgrade, reason = self.version_manager.can_upgrade(
            self.PLUGIN_ID, 
            new_version
        )
        
        return {
            "current_version": str(self.current_version),
            "target_version": str(new_version),
            "can_upgrade": can_upgrade,
            "reason": reason,
            "is_breaking_change": new_version.major > self.current_version.major,
        }


# 使用示例
if __name__ == "__main__":
    print("=" * 50)
    print("XClaw AgentGuard Plugin Version Management Demo")
    print("=" * 50)
    
    # 1. 创建带版本管理的插件
    plugin = VersionedExamplePlugin()
    
    print("\n1. Plugin Metadata:")
    metadata = plugin.get_metadata()
    print(f"   ID: {metadata['id']}")
    print(f"   Name: {metadata['name']}")
    print(f"   Version: {metadata['version']}")
    
    print("\n2. Version Info:")
    version_info = plugin.get_version_info()
    for key, value in version_info.items():
        print(f"   {key}: {value}")
    
    print("\n3. Compatibility Check:")
    compatible, issues = plugin.check_compatibility()
    print(f"   Compatible: {compatible}")
    if issues:
        print(f"   Issues: {issues}")
    
    print("\n4. Custom Check:")
    # 安全的内容
    result1 = plugin.custom_check("test.txt", "normal content")
    print(f"   Safe content: {len(result1)} violations")
    
    # 包含敏感数据的内容
    result2 = plugin.custom_check("test.txt", "This contains SENSITIVE_DATA!")
    print(f"   Sensitive content: {len(result2)} violations")
    if result2:
        print(f"   Violation type: {result2[0].violation_type}")
        print(f"   Severity: {result2[0].severity}")
    
    print("\n5. Upgrade Check:")
    upgradable = UpgradablePlugin(current_version="1.2.0")
    
    # 小版本升级
    check1 = upgradable.check_upgrade("1.3.0")
    print(f"   {check1['current_version']} -> {check1['target_version']}: {check1['can_upgrade']}")
    print(f"   Reason: {check1['reason']}")
    
    # 大版本升级
    check2 = upgradable.check_upgrade("2.0.0")
    print(f"   {check2['current_version']} -> {check2['target_version']}: {check2['can_upgrade']}")
    print(f"   Breaking change: {check2['is_breaking_change']}")
    
    print("\n" + "=" * 50)
    print("Demo completed!")
    print("=" * 50)
