#!/usr/bin/env python3
"""
Anti-Jacked Extension Core - Test Suite
核心版扩展系统测试
"""

import os
import sys
import time
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

# Add paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from .anti_jacked_ext_core import (
    AntiJackExtension,
    ExtensionRegistry,
    ExtensionSandbox,
    ExtensionViolation,
    ExtensionMetadata,
    AntiJackedExtensionMixin
)


# =============================================================================
# Mock Extensions for Testing
# =============================================================================

class SimpleRule(AntiJackExtension):
    """简单的测试规则"""
    
    def __init__(self, ext_id="simple_rule", detect_pattern=None, priority=50):
        super().__init__(
            metadata=ExtensionMetadata(
                id=ext_id,
                name="Simple Rule",
                version="1.0.0",
                author="Test",
                description="Simple test rule"
            )
        )
        self.detect_pattern = detect_pattern or "suspicious"
        self._priority = priority
    
    def get_priority(self) -> int:
        return self._priority
    
    def check(self, file_path: str, file_hash: str) -> Optional[ExtensionViolation]:
        if self.detect_pattern in file_path:
            return ExtensionViolation(
                path=file_path,
                violation_type="pattern_match",
                severity="high",
                message=f"Detected pattern: {self.detect_pattern}"
            )
        return None


class AlwaysDetectRule(AntiJackExtension):
    """总是检测到的规则"""
    
    def __init__(self):
        super().__init__(
            metadata=ExtensionMetadata(
                id="always_detect",
                name="Always Detect",
                version="1.0.0",
                author="Test",
                description="Always detects"
            )
        )
    
    def get_priority(self) -> int:
        return 50
    
    def check(self, file_path: str, file_hash: str) -> Optional[ExtensionViolation]:
        return ExtensionViolation(
            path=file_path,
            violation_type="always_detect",
            severity="critical",
            message="Always triggered"
        )


class NeverDetectRule(AntiJackExtension):
    """从不检测到的规则"""
    
    def __init__(self):
        super().__init__(
            metadata=ExtensionMetadata(
                id="never_detect",
                name="Never Detect",
                version="1.0.0",
                author="Test",
                description="Never detects"
            )
        )
    
    def get_priority(self) -> int:
        return 50
    
    def check(self, file_path: str, file_hash: str) -> Optional[ExtensionViolation]:
        return None


class SlowRule(AntiJackExtension):
    """慢速规则 - 用于测试超时"""
    
    def __init__(self):
        super().__init__(
            metadata=ExtensionMetadata(
                id="slow_rule",
                name="Slow Rule",
                version="1.0.0",
                author="Test",
                description="Takes too long"
            )
        )
    
    def get_priority(self) -> int:
        return 50
    
    def check(self, file_path: str, file_hash: str) -> Optional[ExtensionViolation]:
        time.sleep(10)  # 会超时
        return None


class CrashingRule(AntiJackExtension):
    """崩溃规则 - 用于测试异常处理"""
    
    def __init__(self):
        super().__init__(
            metadata=ExtensionMetadata(
                id="crashing_rule",
                name="Crashing Rule",
                version="1.0.0",
                author="Test",
                description="Always crashes"
            )
        )
    
    def get_priority(self) -> int:
        return 50
    
    def check(self, file_path: str, file_hash: str) -> Optional[ExtensionViolation]:
        raise RuntimeError("Intentional crash for testing")


class FailingInitRule(AntiJackExtension):
    """初始化失败的规则"""
    
    def __init__(self):
        super().__init__(
            metadata=ExtensionMetadata(
                id="failing_init",
                name="Failing Init",
                version="1.0.0",
                author="Test",
                description="Fails during init"
            )
        )
    
    def get_priority(self) -> int:
        return 50
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        return False  # 故意失败
    
    def check(self, file_path: str, file_hash: str) -> Optional[ExtensionViolation]:
        return None


# =============================================================================
# Test Cases
# =============================================================================

class TestExtensionBase(unittest.TestCase):
    """测试扩展基类"""
    
    def test_extension_creation(self):
        """测试扩展创建"""
        ext = SimpleRule("test_id")
        
        self.assertEqual(ext.metadata.id, "test_id")
        self.assertEqual(ext.metadata.name, "Simple Rule")
        self.assertTrue(ext._active)
    
    def test_extension_priority(self):
        """测试优先级系统"""
        ext = SimpleRule(priority=75)
        self.assertEqual(ext.get_priority(), 75)
    
    def test_extension_stats(self):
        """测试统计信息"""
        ext = SimpleRule()
        
        stats = ext.get_stats()
        self.assertEqual(stats['id'], "simple_rule")
        self.assertEqual(stats['check_count'], 0)
        self.assertEqual(stats['violation_count'], 0)
        
        # 模拟检查
        ext._record_check()
        ext._record_check()
        ext._record_violation()
        
        stats = ext.get_stats()
        self.assertEqual(stats['check_count'], 2)
        self.assertEqual(stats['violation_count'], 1)
    
    def test_extension_initialize(self):
        """测试初始化"""
        ext = SimpleRule()
        result = ext.initialize({'key': 'value'})
        
        self.assertTrue(result)
        self.assertEqual(ext.config['key'], 'value')
    
    def test_extension_shutdown(self):
        """测试关闭"""
        ext = SimpleRule()
        ext.shutdown()
        
        self.assertFalse(ext._active)


class TestExtensionViolation(unittest.TestCase):
    """测试违规数据类"""
    
    def test_violation_creation(self):
        """测试违规创建"""
        v = ExtensionViolation(
            path="/test/file.txt",
            violation_type="test_type",
            severity="high",
            message="Test message",
            details={'key': 'value'}
        )
        
        self.assertEqual(v.path, "/test/file.txt")
        self.assertEqual(v.severity, "high")
        self.assertEqual(v.details['key'], "value")
    
    def test_violation_to_dict(self):
        """测试违规序列化"""
        v = ExtensionViolation(
            path="/test/file.txt",
            violation_type="test",
            severity="critical",
            message="Test"
        )
        
        d = v.to_dict()
        self.assertEqual(d['path'], "/test/file.txt")
        self.assertEqual(d['severity'], "critical")


class TestExtensionSandbox(unittest.TestCase):
    """测试扩展沙箱"""
    
    def setUp(self):
        self.sandbox = ExtensionSandbox(timeout=1.0)
    
    def tearDown(self):
        self.sandbox.shutdown()
    
    def test_successful_execution(self):
        """测试正常执行"""
        ext = SimpleRule(detect_pattern="suspicious")
        ext.initialize({})
        
        success, violation, error = self.sandbox.execute(
            ext, "/test/suspicious_file.txt", "abc123"
        )
        
        self.assertTrue(success)
        self.assertIsNotNone(violation)
        self.assertIsNone(error)
        self.assertEqual(violation.violation_type, "pattern_match")
    
    def test_no_detection(self):
        """测试无检测"""
        ext = SimpleRule(detect_pattern="suspicious")
        ext.initialize({})
        
        success, violation, error = self.sandbox.execute(
            ext, "/test/clean_file.txt", "abc123"
        )
        
        self.assertTrue(success)
        self.assertIsNone(violation)
        self.assertIsNone(error)
    
    def test_timeout_protection(self):
        """测试超时保护"""
        ext = SlowRule()
        ext.initialize({})
        
        success, violation, error = self.sandbox.execute(
            ext, "/test/file.txt", "abc123"
        )
        
        self.assertFalse(success)
        self.assertIsNone(violation)
        self.assertIsNotNone(error)
        self.assertIn("timed out", error)
    
    def test_exception_handling(self):
        """测试异常隔离"""
        ext = CrashingRule()
        ext.initialize({})
        
        success, violation, error = self.sandbox.execute(
            ext, "/test/file.txt", "abc123"
        )
        
        self.assertFalse(success)
        self.assertIsNone(violation)
        self.assertIsNotNone(error)
        self.assertIn("crashed", error)
    
    def test_inactive_extension(self):
        """测试非活跃扩展"""
        ext = SimpleRule()
        ext.initialize({})
        ext.shutdown()  # 关闭扩展
        
        success, violation, error = self.sandbox.execute(
            ext, "/test/file.txt", "abc123"
        )
        
        self.assertFalse(success)
        self.assertIn("not active", error)


class TestExtensionRegistry(unittest.TestCase):
    """测试扩展注册表"""
    
    def setUp(self):
        self.registry = ExtensionRegistry()
    
    def tearDown(self):
        self.registry.shutdown()
    
    def test_register_extension(self):
        """测试基本注册"""
        ext = SimpleRule("test_rule")
        
        result = self.registry.register_extension(ext)
        
        self.assertTrue(result)
        self.assertIn("test_rule", self.registry._extensions)
    
    def test_register_duplicate(self):
        """测试重复注册预防"""
        ext1 = SimpleRule("same_id")
        ext2 = SimpleRule("same_id")
        
        self.assertTrue(self.registry.register_extension(ext1))
        self.assertFalse(self.registry.register_extension(ext2))  # 应该失败
    
    def test_register_failing_init(self):
        """测试初始化失败处理"""
        ext = FailingInitRule()
        
        result = self.registry.register_extension(ext)
        
        self.assertFalse(result)
    
    def test_unregister_extension(self):
        """测试注销"""
        ext = SimpleRule("to_remove")
        self.registry.register_extension(ext)
        
        result = self.registry.unregister_extension("to_remove")
        
        self.assertTrue(result)
        self.assertNotIn("to_remove", self.registry._extensions)
    
    def test_unregister_nonexistent(self):
        """测试注销不存在的扩展"""
        result = self.registry.unregister_extension("nonexistent")
        self.assertFalse(result)
    
    def test_priority_sorting(self):
        """测试优先级排序"""
        low = SimpleRule("low_priority", priority=10)
        high = SimpleRule("high_priority", priority=90)
        medium = SimpleRule("medium_priority", priority=50)
        
        self.registry.register_extension(low)
        self.registry.register_extension(high)
        self.registry.register_extension(medium)
        
        # 检查顺序 (高优先级在前)
        self.assertEqual(self.registry._extension_order[0], "high_priority")
        self.assertEqual(self.registry._extension_order[1], "medium_priority")
        self.assertEqual(self.registry._extension_order[2], "low_priority")
    
    def test_check_file_single_violation(self):
        """测试单文件检查 - 单个违规"""
        ext = AlwaysDetectRule()
        self.registry.register_extension(ext)
        
        violations = self.registry.check_file("/test/file.txt", "hash123")
        
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].violation_type, "always_detect")
    
    def test_check_file_multiple_extensions(self):
        """测试多扩展检查"""
        ext1 = AlwaysDetectRule()
        ext2 = SimpleRule("pattern_rule", detect_pattern="test")
        
        self.registry.register_extension(ext1)
        self.registry.register_extension(ext2)
        
        violations = self.registry.check_file("/test/file.txt", "hash123")
        
        self.assertEqual(len(violations), 2)  # 两个扩展都检测到
    
    def test_check_file_with_timeout(self):
        """测试检查时的超时处理"""
        ext = SlowRule()
        self.registry.register_extension(ext)
        
        violations = self.registry.check_file("/test/file.txt", "hash123")
        
        # 超时不应该影响结果,只是没有违规
        self.assertEqual(len(violations), 0)
        
        # 但扩展应该记录了错误
        self.assertEqual(ext._error_count, 1)
    
    def test_list_extensions(self):
        """测试列出扩展"""
        ext1 = SimpleRule("rule1")
        ext2 = SimpleRule("rule2")
        
        self.registry.register_extension(ext1)
        self.registry.register_extension(ext2)
        
        extensions = self.registry.list_extensions()
        
        self.assertEqual(len(extensions), 2)
        ids = [e['metadata']['id'] for e in extensions]
        self.assertIn("rule1", ids)
        self.assertIn("rule2", ids)
    
    def test_get_stats(self):
        """测试统计信息"""
        ext = SimpleRule("stats_test")
        self.registry.register_extension(ext)
        
        stats = self.registry.get_stats()
        
        self.assertEqual(stats['registered_count'], 1)
        self.assertIn("stats_test", stats['extensions'])


class TestAntiJackedExtensionMixin(unittest.TestCase):
    """测试混入类"""
    
    def setUp(self):
        # 创建带扩展支持的模拟AntiJacked类
        class MockAntiJackedWithExtensions(AntiJackedExtensionMixin):
            def __init__(self):
                self._init_extensions()
                self.baseline = Mock()
                self.baseline.files = {}
        
        self.aj = MockAntiJackedWithExtensions()
    
    def tearDown(self):
        self.aj.shutdown_extensions()
    
    def test_register_extension(self):
        """测试通过混入类注册扩展"""
        ext = SimpleRule("mixin_test")
        
        result = self.aj.register_extension(ext)
        
        self.assertTrue(result)
    
    def test_check_with_extensions_single_file(self):
        """测试检查特定文件"""
        ext = AlwaysDetectRule()
        self.aj.register_extension(ext)
        
        violations = self.aj.check_with_extensions("/test/file.txt")
        
        self.assertEqual(len(violations), 1)
    
    def test_check_with_extensions_all_baseline(self):
        """测试检查所有基线文件"""
        ext = SimpleRule("pattern_test", detect_pattern="suspicious")
        self.aj.register_extension(ext)
        
        # 模拟基线文件
        mock_entry = Mock()
        mock_entry.sha256 = "abc123"
        self.aj.baseline.files = {
            "/safe/file.txt": mock_entry,
            "/suspicious/malware.exe": mock_entry
        }
        
        violations = self.aj.check_with_extensions()  # 无参数 = 检查所有
        
        self.assertEqual(len(violations), 1)  # 只有一个文件匹配
        self.assertIn("suspicious", violations[0].path)
    
    def test_get_extension_stats(self):
        """测试获取扩展统计"""
        ext = SimpleRule("stats_ext")
        self.aj.register_extension(ext)
        
        stats = self.aj.get_extension_stats()
        
        self.assertEqual(stats['registered_count'], 1)


class TestIntegration(unittest.TestCase):
    """集成测试"""
    
    def test_full_workflow(self):
        """测试完整工作流程"""
        registry = ExtensionRegistry()
        
        try:
            # 1. 注册多个扩展
            rule1 = SimpleRule("rule1", detect_pattern="malware", priority=80)
            rule2 = SimpleRule("rule2", detect_pattern="virus", priority=60)
            rule3 = NeverDetectRule()
            
            self.assertTrue(registry.register_extension(rule1))
            self.assertTrue(registry.register_extension(rule2))
            self.assertTrue(registry.register_extension(rule3))
            
            # 2. 检查文件
            violations = registry.check_file(
                "/path/malware_virus.exe", 
                "hash123"
            )
            
            # 两个规则都应该检测到
            self.assertEqual(len(violations), 2)
            
            # 3. 验证优先级排序
            self.assertEqual(violations[0].extension_id, "rule1")  # 高优先级
            self.assertEqual(violations[1].extension_id, "rule2")
            
            # 4. 检查统计
            self.assertEqual(rule1._violation_count, 1)
            self.assertEqual(rule2._violation_count, 1)
            self.assertEqual(rule3._check_count, 1)
            
            # 5. 列出扩展
            extensions = registry.list_extensions()
            self.assertEqual(len(extensions), 3)
            
            # 6. 注销扩展
            self.assertTrue(registry.unregister_extension("rule1"))
            self.assertEqual(len(registry._extensions), 2)
            
        finally:
            registry.shutdown()
    
    def test_error_isolation(self):
        """测试错误隔离 - 一个扩展失败不应影响其他"""
        registry = ExtensionRegistry()
        
        try:
            # 注册一个会崩溃的扩展和一个正常的扩展
            crashing = CrashingRule()
            normal = AlwaysDetectRule()
            
            registry.register_extension(crashing)
            registry.register_extension(normal)
            
            # 检查应该仍然工作
            violations = registry.check_file("/test/file.txt", "hash123")
            
            # 正常扩展应该返回结果
            self.assertEqual(len(violations), 1)
            self.assertEqual(violations[0].extension_id, "always_detect")
            
            # 崩溃扩展应该记录了错误
            self.assertEqual(crashing._error_count, 1)
            
        finally:
            registry.shutdown()


# =============================================================================
# Main
# =============================================================================

def run_integration_demo():
    """运行集成演示"""
    print("\n" + "="*60)
    print("Anti-Jacked Extension Core - Integration Demo")
    print("="*60 + "\n")
    
    registry = ExtensionRegistry()
    
    try:
        # 创建自定义规则示例
        class MalwarePatternRule(AntiJackExtension):
            def __init__(self):
                super().__init__(ExtensionMetadata(
                    id="malware_pattern",
                    name="Malware Pattern Detector",
                    version="1.0.0",
                    author="Security Team",
                    description="Detects known malware patterns"
                ))
            
            def get_priority(self) -> int:
                return 90  # 高优先级
            
            def check(self, file_path: str, file_hash: str) -> Optional[ExtensionViolation]:
                malware_patterns = ['.exe', '.dll', 'trojan', 'backdoor']
                for pattern in malware_patterns:
                    if pattern in file_path.lower():
                        return ExtensionViolation(
                            path=file_path,
                            violation_type="malware_pattern",
                            severity="critical",
                            message=f"Detected malware pattern: {pattern}"
                        )
                return None
        
        class SuspiciousHashRule(AntiJackExtension):
            def __init__(self):
                super().__init__(ExtensionMetadata(
                    id="suspicious_hash",
                    name="Suspicious Hash Detector",
                    version="1.0.0",
                    author="Security Team",
                    description="Detects known suspicious file hashes"
                ))
                self.known_bad_hashes = {
                    "badhash123",
                    "malware456"
                }
            
            def get_priority(self) -> int:
                return 70
            
            def check(self, file_path: str, file_hash: str) -> Optional[ExtensionViolation]:
                if file_hash in self.known_bad_hashes:
                    return ExtensionViolation(
                        path=file_path,
                        violation_type="known_bad_hash",
                        severity="critical",
                        message="File hash matches known malware"
                    )
                return None
        
        # 注册扩展
        print("1. Registering extensions...")
        registry.register_extension(MalwarePatternRule())
        registry.register_extension(SuspiciousHashRule())
        print(f"   ✓ Registered {len(registry._extensions)} extensions\n")
        
        # 测试文件
        test_files = [
            ("/usr/bin/ls", "abc123"),
            ("/tmp/malware.exe", "def456"),
            ("/home/user/document.txt", "badhash123"),
            ("/var/log/trojan.log", "xyz789")
        ]
        
        print("2. Checking files...")
        for file_path, file_hash in test_files:
            violations = registry.check_file(file_path, file_hash)
            status = "✗ VIOLATIONS" if violations else "✓ Clean"
            print(f"   {status}: {file_path}")
            for v in violations:
                print(f"      - [{v.severity.upper()}] {v.message}")
        
        print("\n3. Extension statistics:")
        for ext_id in registry._extension_order:
            ext = registry._extensions[ext_id]
            stats = ext.get_stats()
            print(f"   - {ext_id}: {stats['check_count']} checks, "
                  f"{stats['violation_count']} violations, "
                  f"{stats['error_count']} errors")
        
        print("\n" + "="*60)
        print("Demo completed successfully!")
        print("="*60 + "\n")
        
    finally:
        registry.shutdown()


if __name__ == '__main__':
    # 运行单元测试
    print("Running unit tests...\n")
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # 添加所有测试类
    suite.addTests(loader.loadTestsFromTestCase(TestExtensionBase))
    suite.addTests(loader.loadTestsFromTestCase(TestExtensionViolation))
    suite.addTests(loader.loadTestsFromTestCase(TestExtensionSandbox))
    suite.addTests(loader.loadTestsFromTestCase(TestExtensionRegistry))
    suite.addTests(loader.loadTestsFromTestCase(TestAntiJackedExtensionMixin))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # 运行集成演示
    if result.wasSuccessful():
        run_integration_demo()
        print("\n🎉 ALL TESTS PASSED")
        sys.exit(0)
    else:
        print("\n❌ SOME TESTS FAILED")
        sys.exit(1)
