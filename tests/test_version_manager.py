"""
Version Manager 单元测试

测试覆盖:
- PluginVersion 类完整功能
- VersionConstraint 约束匹配
- PluginManifest 清单管理
- VersionManager 版本管理
- 边界情况: 无效版本、依赖冲突
"""

import unittest
from unittest.mock import Mock, patch

from xclaw_agentguard.core.version_management import (
    PluginVersion,
    VersionConstraint,
    PluginManifest,
    VersionManager,
    parse_version,
    check_version_constraint,
)


class TestPluginVersion(unittest.TestCase):
    """测试 PluginVersion 类"""
    
    def test_basic_creation(self):
        """测试基本创建"""
        version = PluginVersion(major=2, minor=3, patch=1)
        self.assertEqual(version.major, 2)
        self.assertEqual(version.minor, 3)
        self.assertEqual(version.patch, 1)
    
    def test_parse_simple_version(self):
        """测试解析简单版本"""
        version = PluginVersion.parse("2.3.1")
        self.assertEqual(version.major, 2)
        self.assertEqual(version.minor, 3)
        self.assertEqual(version.patch, 1)
    
    def test_parse_with_prerelease(self):
        """测试解析预发布版本"""
        version = PluginVersion.parse("2.3.1-beta.1")
        self.assertEqual(version.major, 2)
        self.assertEqual(version.minor, 3)
        self.assertEqual(version.patch, 1)
        self.assertEqual(version.prerelease, "beta.1")
    
    def test_parse_with_build(self):
        """测试解析带构建元数据版本"""
        version = PluginVersion.parse("2.3.1+build.123")
        self.assertEqual(version.major, 2)
        self.assertEqual(version.minor, 3)
        self.assertEqual(version.patch, 1)
        self.assertEqual(version.build, "build.123")
    
    def test_parse_invalid_version(self):
        """测试解析无效版本"""
        with self.assertRaises(ValueError):
            PluginVersion.parse("invalid")
        with self.assertRaises(ValueError):
            PluginVersion.parse("")
    
    def test_version_comparison(self):
        """测试版本比较"""
        v1 = PluginVersion(1, 0, 0)
        v2 = PluginVersion(2, 0, 0)
        v3 = PluginVersion(1, 1, 0)
        v4 = PluginVersion(1, 0, 1)
        
        self.assertTrue(v1 < v2)
        self.assertTrue(v1 < v3)
        self.assertTrue(v1 < v4)
        self.assertTrue(v2 > v1)
        self.assertEqual(str(v1), "1.0.0")
    
    def test_bump_operations(self):
        """测试版本号递增"""
        v = PluginVersion(1, 2, 3)
        
        v_major = v.bump_major()
        self.assertEqual(v_major.major, 2)
        self.assertEqual(v_major.minor, 0)
        self.assertEqual(v_major.patch, 0)
        
        v_minor = v.bump_minor()
        self.assertEqual(v_minor.major, 1)
        self.assertEqual(v_minor.minor, 3)
        self.assertEqual(v_minor.patch, 0)
        
        v_patch = v.bump_patch()
        self.assertEqual(v_patch.major, 1)
        self.assertEqual(v_patch.minor, 2)
        self.assertEqual(v_patch.patch, 4)
    
    def test_is_compatible_with(self):
        """测试版本兼容性检查"""
        v1 = PluginVersion(1, 2, 3)
        v2 = PluginVersion(1, 5, 0)
        v3 = PluginVersion(2, 0, 0)
        
        self.assertTrue(v1.is_compatible_with(v2))  # 相同 MAJOR
        self.assertFalse(v1.is_compatible_with(v3))  # 不同 MAJOR


class TestVersionConstraint(unittest.TestCase):
    """测试 VersionConstraint 类"""
    
    def test_exact_constraint(self):
        """测试精确版本约束"""
        constraint = VersionConstraint("2.3.1")
        version = PluginVersion.parse("2.3.1")
        self.assertTrue(constraint.matches(version))
    
    def test_greater_than_constraint(self):
        """测试大于等于约束"""
        constraint = VersionConstraint(">=2.0.0")
        self.assertTrue(constraint.matches(PluginVersion.parse("2.0.0")))
        self.assertTrue(constraint.matches(PluginVersion.parse("3.0.0")))
    
    def test_caret_constraint(self):
        """测试 ^ 约束（兼容版本）"""
        constraint = VersionConstraint("^1.2.0")
        self.assertTrue(constraint.matches(PluginVersion.parse("1.2.0")))
        self.assertTrue(constraint.matches(PluginVersion.parse("1.5.0")))


class TestPluginManifest(unittest.TestCase):
    """测试 PluginManifest 类"""
    
    def test_basic_creation(self):
        """测试基本创建"""
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test Author"
        )
        
        self.assertEqual(manifest.id, "test_plugin")
        self.assertEqual(manifest.name, "Test Plugin")
        self.assertEqual(str(manifest.version), "1.0.0")
        self.assertEqual(manifest.author, "Test Author")
    
    def test_with_dependencies(self):
        """测试带依赖的创建"""
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test Author",
            requires_core=">=2.0.0",
            dependencies={"other_plugin": ">=1.0.0"}
        )
        
        self.assertEqual(manifest.requires_core, ">=2.0.0")
        self.assertIn("other_plugin", manifest.dependencies)
    
    def test_to_dict(self):
        """测试转换为字典"""
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test Author"
        )
        
        data = manifest.to_dict()
        self.assertEqual(data["id"], "test_plugin")
        self.assertEqual(data["version"], "1.0.0")


class TestVersionManager(unittest.TestCase):
    """测试 VersionManager 类"""
    
    def setUp(self):
        """测试前置 setup"""
        self.manager = VersionManager(core_version="2.3.0")
    
    def test_initialization(self):
        """测试初始化"""
        self.assertIsNotNone(self.manager)
        self.assertEqual(str(self.manager.core_version), "2.3.0")
    
    def test_check_compatibility_compatible(self):
        """测试兼容性检查 - 兼容"""
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test Author",
            requires_core=">=2.0.0"
        )
        
        compatible, issues = self.manager.check_compatibility(manifest)
        self.assertTrue(compatible)
        self.assertEqual(len(issues), 0)
    
    def test_check_compatibility_incompatible_core(self):
        """测试兼容性检查 - 核心版本不兼容"""
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test Author",
            requires_core=">=3.0.0"  # 要求 3.0.0，但实际是 2.3.0
        )
        
        compatible, issues = self.manager.check_compatibility(manifest)
        self.assertFalse(compatible)
        self.assertTrue(any("Core version mismatch" in issue for issue in issues))
    
    def test_check_compatibility_missing_dependency(self):
        """测试兼容性检查 - 缺失依赖"""
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test Author",
            requires_core=">=2.0.0",
            dependencies={"missing_plugin": ">=1.0.0"}
        )
        
        compatible, issues = self.manager.check_compatibility(manifest)
        self.assertFalse(compatible)
        self.assertTrue(any("Missing dependency" in issue for issue in issues))
    
    def test_register_plugin_success(self):
        """测试成功注册插件"""
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test Author",
            requires_core=">=2.0.0"
        )
        
        result = self.manager.register_plugin(manifest)
        self.assertTrue(result)
        
        # 验证已注册
        version = self.manager.get_installed_version("test_plugin")
        self.assertIsNotNone(version)
        self.assertEqual(str(version), "1.0.0")
    
    def test_register_plugin_incompatible(self):
        """测试注册不兼容插件"""
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test Author",
            requires_core=">=5.0.0"  # 不兼容
        )
        
        with self.assertRaises(RuntimeError):
            self.manager.register_plugin(manifest)
    
    def test_get_installed_version_nonexistent(self):
        """测试获取不存在插件版本"""
        version = self.manager.get_installed_version("nonexistent")
        self.assertIsNone(version)
    
    def test_can_upgrade(self):
        """测试升级检查"""
        # 先注册插件
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test Author",
            requires_core=">=2.0.0"
        )
        self.manager.register_plugin(manifest)
        
        # 检查是否可以升级到 1.1.0
        can_upgrade, reason = self.manager.can_upgrade("test_plugin", PluginVersion(1, 1, 0))
        self.assertTrue(can_upgrade)
    
    def test_can_upgrade_major_version(self):
        """测试主版本升级检查"""
        # 先注册插件
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test Author",
            requires_core=">=2.0.0"
        )
        self.manager.register_plugin(manifest)
        
        # 检查是否可以升级到 2.0.0（主版本变化）
        can_upgrade, reason = self.manager.can_upgrade("test_plugin", PluginVersion(2, 0, 0))
        self.assertTrue(can_upgrade)
        self.assertIn("MAJOR", reason)  # 应该警告主版本变化
    
    def test_can_upgrade_not_installed(self):
        """测试未安装插件升级检查"""
        can_upgrade, reason = self.manager.can_upgrade("nonexistent", PluginVersion(1, 1, 0))
        self.assertFalse(can_upgrade)
        self.assertIn("not installed", reason)
    
    def test_can_upgrade_same_version(self):
        """测试相同版本升级检查"""
        # 先注册插件
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test Author",
            requires_core=">=2.0.0"
        )
        self.manager.register_plugin(manifest)
        
        # 尝试升级到相同版本
        can_upgrade, reason = self.manager.can_upgrade("test_plugin", PluginVersion(1, 0, 0))
        self.assertFalse(can_upgrade)


class TestConvenienceFunctions(unittest.TestCase):
    """测试便捷函数"""
    
    def test_parse_version(self):
        """测试 parse_version 函数"""
        version = parse_version("2.3.1")
        self.assertEqual(version.major, 2)
        self.assertEqual(version.minor, 3)
        self.assertEqual(version.patch, 1)
    
    def test_check_version_constraint(self):
        """测试 check_version_constraint 函数"""
        self.assertTrue(check_version_constraint("2.3.1", ">=2.0.0"))
        self.assertTrue(check_version_constraint("2.3.1", "2.3.1"))


class TestEdgeCases(unittest.TestCase):
    """测试边界情况"""
    
    def setUp(self):
        """测试前置 setup"""
        self.manager = VersionManager(core_version="2.3.0")
    
    def test_parse_partial_version(self):
        """测试解析部分版本"""
        # 只提供 major
        v1 = PluginVersion.parse("2")
        self.assertEqual(v1.major, 2)
        self.assertEqual(v1.minor, 0)
        self.assertEqual(v1.patch, 0)
        
        # 提供 major.minor
        v2 = PluginVersion.parse("2.3")
        self.assertEqual(v2.major, 2)
        self.assertEqual(v2.minor, 3)
        self.assertEqual(v2.patch, 0)
    
    def test_version_with_complex_prerelease(self):
        """测试复杂预发布版本"""
        version = PluginVersion.parse("1.0.0-alpha.1.beta.2")
        self.assertEqual(version.prerelease, "alpha.1.beta.2")
    
    def test_empty_dependencies(self):
        """测试空依赖"""
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test Author",
            requires_core=">=2.0.0",
            dependencies={}
        )
        
        compatible, issues = self.manager.check_compatibility(manifest)
        self.assertTrue(compatible)


if __name__ == "__main__":
    unittest.main()