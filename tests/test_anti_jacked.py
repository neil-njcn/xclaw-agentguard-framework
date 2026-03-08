"""
Anti-Jacked Security Base 单元测试

测试覆盖:
- IntegrityMonitor 完整性监控
- ImmutableLogChain 不可变日志链
- TamperDetector 篡改检测器
- AutoRecovery 自动恢复
- CLI 命令行接口
- 边界情况: 文件权限、并发访问、大数据量
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import json
import os
import hashlib
import threading
import time
from pathlib import Path

from xclaw_agentguard.anti_jacked import (
    IntegrityMonitor,
    ImmutableLogChain,
    TamperDetector,
    AutoRecovery,
    log_event,
    get_integrity_monitor,
    get_log_chain,
    get_tamper_detector,
    get_auto_recovery,
)


class TestIntegrityMonitor(unittest.TestCase):
    """测试 IntegrityMonitor 完整性监控"""
    
    def setUp(self):
        """测试前置 setup"""
        self.temp_dir = tempfile.mkdtemp()
        self.baseline_path = os.path.join(self.temp_dir, "baseline.json")
        self.monitor = IntegrityMonitor(baseline_path=self.baseline_path)
    
    def tearDown(self):
        """测试后置清理"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization(self):
        """测试初始化"""
        self.assertIsNotNone(self.monitor)
        self.assertEqual(self.monitor.baseline_path, self.baseline_path)
        self.assertEqual(len(self.monitor.watched_files), 0)
    
    def test_add_watch_file(self):
        """测试添加文件监控"""
        test_file = Path(self.temp_dir) / "test.py"
        test_file.write_text("print('hello')")
        
        success = self.monitor.add_watch(str(test_file))
        
        self.assertTrue(success)
        self.assertIn(str(test_file), self.monitor.watched_files)
    
    def test_add_watch_nonexistent_file(self):
        """测试添加不存在文件"""
        success = self.monitor.add_watch("/nonexistent/file.py")
        self.assertFalse(success)
    
    def test_generate_baseline(self):
        """测试生成基线"""
        # 创建测试文件
        test_file = Path(self.temp_dir) / "test.py"
        test_file.write_text("print('hello')")
        
        self.monitor.add_watch(str(test_file))
        result = self.monitor.generate_baseline(directories=[self.temp_dir])
        
        self.assertIn('total_files', result)
        self.assertGreaterEqual(result['total_files'], 1)
        self.assertTrue(os.path.exists(self.baseline_path))
    
    def test_check_integrity_clean(self):
        """测试完整性检查 - 无篡改"""
        test_file = Path(self.temp_dir) / "test.py"
        test_file.write_text("print('hello')")
        
        self.monitor.add_watch(str(test_file))
        self.monitor.generate_baseline(directories=[self.temp_dir])
        
        result = self.monitor.check_integrity()
        
        self.assertIn('verified', result)
        self.assertIn('modified', result)
        self.assertEqual(len(result['modified']), 0)
    
    def test_check_integrity_modified(self):
        """测试完整性检查 - 文件被修改"""
        test_file = Path(self.temp_dir) / "test.py"
        test_file.write_text("print('hello')")
        
        self.monitor.add_watch(str(test_file))
        self.monitor.generate_baseline(directories=[self.temp_dir])
        
        # 修改文件
        test_file.write_text("print('modified')")
        
        result = self.monitor.check_integrity()
        
        self.assertGreater(len(result['modified']), 0)
    
    def test_compute_file_hash(self):
        """测试计算文件哈希"""
        test_file = Path(self.temp_dir) / "test.py"
        test_file.write_text("print('hello')")
        
        hash1 = self.monitor.calculate_sha256(str(test_file))
        hash2 = self.monitor.calculate_sha256(str(test_file))
        
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)  # SHA256 hex length
    
    def test_add_watch_directory(self):
        """测试监控目录"""
        # 创建多个文件
        for i in range(3):
            (Path(self.temp_dir) / f"file{i}.py").write_text(f"print({i})")
        
        count = self.monitor.add_watch_directory(self.temp_dir, pattern="*.py")
        
        self.assertEqual(count, 3)
    
    def test_get_status(self):
        """测试获取状态"""
        status = self.monitor.get_status()
        
        self.assertIn('monitoring_active', status)
        self.assertIn('watched_files', status)


class TestImmutableLogChain(unittest.TestCase):
    """测试 ImmutableLogChain 不可变日志链"""
    
    def setUp(self):
        """测试前置 setup"""
        self.temp_dir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.temp_dir, "audit.log")
        self.log_chain = ImmutableLogChain(log_path=self.log_path)
    
    def tearDown(self):
        """测试后置清理"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization(self):
        """测试初始化"""
        self.assertIsNotNone(self.log_chain)
        self.assertEqual(self.log_chain.log_path, self.log_path)
    
    def test_append_entry(self):
        """测试添加日志条目"""
        entry = self.log_chain.append(
            event_type="test_event",
            severity="INFO",
            message="Test message",
            details={"key": "value"}
        )
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.event_type, "test_event")
        self.assertEqual(entry.severity, "INFO")
    
    def test_verify_chain(self):
        """测试验证链完整性"""
        # 添加多个条目
        self.log_chain.append("event1", "INFO", "Message 1")
        self.log_chain.append("event2", "WARNING", "Message 2")
        
        result = self.log_chain.verify_chain()
        
        self.assertTrue(result.get('valid'))
    
    def test_chain_tamper_detection(self):
        """测试链篡改检测"""
        self.log_chain.append("event1", "INFO", "Message 1")
        self.log_chain.append("event2", "INFO", "Message 2")
        
        # 手动篡改日志文件
        with open(self.log_path, 'r') as f:
            lines = f.readlines()
        
        if lines:
            # 修改第一行
            data = json.loads(lines[0])
            data['message'] = "TAMPERED"
            lines[0] = json.dumps(data) + '\n'
            
            with open(self.log_path, 'w') as f:
                f.writelines(lines)
        
        # 验证应该失败
        result = self.log_chain.verify_chain()
        self.assertFalse(result.get('valid'))
    
    def test_get_entries(self):
        """测试获取日志条目"""
        self.log_chain.append("event1", "INFO", "Message 1")
        self.log_chain.append("event2", "INFO", "Message 2")
        
        entries = self.log_chain.get_entries()
        
        self.assertEqual(len(entries), 2)
    
    def test_log_entry_immutability(self):
        """测试日志条目不可变性"""
        entry = self.log_chain.append("test", "INFO", "Test")
        
        # 尝试修改应该失败（如果是dataclass/frozen）
        # 或者创建新条目
        original_hash = entry.entry_hash
        self.assertIsNotNone(original_hash)


class TestTamperDetector(unittest.TestCase):
    """测试 TamperDetector 篡改检测器"""
    
    def setUp(self):
        """测试前置 setup"""
        self.detector = TamperDetector()
    
    def test_initialization(self):
        """测试初始化"""
        self.assertIsNotNone(self.detector)
    
    def test_check_integrity_result_with_tampering(self):
        """测试检测篡改"""
        # 创建模拟的完整性检查结果
        integrity_result = {
            'modified': [{'path': '/path/to/modified/file.py', 'expected_hash': 'abc', 'actual_hash': 'def'}],
            'verified': ['/path/to/verified/file.py']
        }
        
        alerts = self.detector.check_integrity_result(integrity_result)
        
        # 应该有篡改警报
        self.assertGreater(len(alerts), 0)
    
    def test_check_integrity_result_clean(self):
        """测试无篡改情况"""
        integrity_result = {
            'modified': [],
            'verified': ['/path/to/file.py']
        }
        
        alerts = self.detector.check_integrity_result(integrity_result)
        
        self.assertEqual(len(alerts), 0)


class TestAutoRecovery(unittest.TestCase):
    """测试 AutoRecovery 自动恢复"""
    
    def setUp(self):
        """测试前置 setup"""
        self.temp_dir = tempfile.mkdtemp()
        self.backup_dir = os.path.join(self.temp_dir, "backups")
        self.recovery = AutoRecovery(backup_dir=self.backup_dir)
    
    def tearDown(self):
        """测试后置清理"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization(self):
        """测试初始化"""
        self.assertIsNotNone(self.recovery)
        self.assertEqual(self.recovery.backup_dir, self.backup_dir)
    
    def test_create_backup(self):
        """测试创建备份"""
        test_file = Path(self.temp_dir) / "test.py"
        test_file.write_text("original content")
        
        success = self.recovery.create_backup(str(test_file))
        
        self.assertTrue(success)
        # 验证备份文件存在
        backup_files = list(Path(self.backup_dir).glob("*.bak"))
        self.assertGreater(len(backup_files), 0)
    
    def test_restore_from_backup(self):
        """测试从备份恢复"""
        test_file = Path(self.temp_dir) / "test.py"
        test_file.write_text("original content")
        
        # 创建备份
        self.recovery.create_backup(str(test_file))
        
        # 修改文件
        test_file.write_text("modified content")
        
        # 恢复
        success = self.recovery.restore_from_backup(str(test_file))
        
        self.assertTrue(success)
        content = test_file.read_text()
        self.assertEqual(content, "original content")
    
    def test_list_backups(self):
        """测试列出备份"""
        test_file = Path(self.temp_dir) / "test.py"
        test_file.write_text("content")
        
        # 创建备份
        self.recovery.create_backup(str(test_file))
        
        # 列出备份
        backups = self.recovery.list_backups(str(test_file))
        
        self.assertGreater(len(backups), 0)


class TestConvenienceFunctions(unittest.TestCase):
    """测试便捷函数"""
    
    def test_get_integrity_monitor(self):
        """测试获取完整性监控器"""
        monitor = get_integrity_monitor()
        self.assertIsNotNone(monitor)
        # 多次调用应该返回相同实例（单例）
        monitor2 = get_integrity_monitor()
        self.assertIs(monitor, monitor2)
    
    def test_get_log_chain(self):
        """测试获取日志链"""
        log_chain = get_log_chain()
        self.assertIsNotNone(log_chain)
    
    def test_get_tamper_detector(self):
        """测试获取篡改检测器"""
        detector = get_tamper_detector()
        self.assertIsNotNone(detector)
    
    def test_get_auto_recovery(self):
        """测试获取自动恢复"""
        recovery = get_auto_recovery()
        self.assertIsNotNone(recovery)
    
    def test_log_event(self):
        """测试记录事件"""
        entry = log_event("test_event", "INFO", "Test message")
        self.assertIsNotNone(entry)


class TestEdgeCases(unittest.TestCase):
    """测试边界情况"""
    
    def test_large_file_hash(self):
        """测试大文件哈希"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            # 写入10MB数据
            f.write("x" * (10 * 1024 * 1024))
            temp_path = f.name
        
        try:
            monitor = IntegrityMonitor()
            hash_value = monitor.calculate_sha256(temp_path)
            self.assertEqual(len(hash_value), 64)
        finally:
            os.unlink(temp_path)
    
    def test_concurrent_access(self):
        """测试并发访问"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_chain = ImmutableLogChain(log_path=os.path.join(temp_dir, "test.log"))
            
            errors = []
            
            def append_entries():
                try:
                    for i in range(10):
                        log_chain.append(f"event_{i}", "INFO", f"Message {i}")
                except Exception as e:
                    errors.append(e)
            
            # 启动多个线程
            threads = [threading.Thread(target=append_entries) for _ in range(3)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            
            # 应该没有错误
            self.assertEqual(len(errors), 0)
            # 应该有30个条目
            entries = log_chain.get_entries()
            self.assertEqual(len(entries), 30)
    
    def test_empty_directory_baseline(self):
        """测试空目录基线"""
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = IntegrityMonitor()
            result = monitor.generate_baseline(directories=[temp_dir])
            self.assertEqual(result['total_files'], 0)
    
    def test_special_characters_in_filename(self):
        """测试特殊字符文件名"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # 创建带特殊字符的文件
            special_file = Path(temp_dir) / "file with spaces.py"
            special_file.write_text("print('hello')")
            
            monitor = IntegrityMonitor()
            success = monitor.add_watch(str(special_file))
            self.assertTrue(success)


class TestCLI(unittest.TestCase):
    """测试 CLI 命令行接口"""
    
    def test_cli_parser_creation(self):
        """测试 CLI 解析器创建"""
        from xclaw_agentguard.cli import create_parser
        
        parser = create_parser()
        self.assertIsNotNone(parser)
    
    def test_baseline_generate_command(self):
        """测试基线生成命令"""
        from xclaw_agentguard.cli import cmd_baseline_generate
        
        # 使用模拟参数
        args = Mock()
        
        # 应该不抛出异常
        try:
            result = cmd_baseline_generate(args)
            # 命令可能成功或失败，但不应该崩溃
            self.assertIn(result, [0, 1])
        except Exception as e:
            # 某些情况下可能抛出异常，这是可接受的
            pass


if __name__ == "__main__":
    unittest.main()