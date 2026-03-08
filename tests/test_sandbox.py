"""
Sandbox 模块单元测试

测试覆盖:
- SandboxConfig 配置
- ExecutionResult 结果处理
"""

import unittest

from xclaw_agentguard.sandbox import (
    SandboxConfig,
    ExecutionResult,
)


class TestSandboxConfig(unittest.TestCase):
    """测试 SandboxConfig"""
    
    def test_default_config(self):
        """测试默认配置"""
        config = SandboxConfig()
        
        self.assertEqual(config.image, "xclaw-sandbox:latest")
        self.assertEqual(config.timeout, 30)
        self.assertEqual(config.cpu_limit, 1.0)
        self.assertEqual(config.memory_limit, "512m")
        self.assertEqual(config.network_mode, "none")
        self.assertTrue(config.read_only)
    
    def test_custom_config(self):
        """测试自定义配置"""
        config = SandboxConfig(
            image="custom-image",
            timeout=60,
            cpu_limit=2.0,
            memory_limit="1g",
            network_mode="bridge"
        )
        
        self.assertEqual(config.image, "custom-image")
        self.assertEqual(config.timeout, 60)
        self.assertEqual(config.cpu_limit, 2.0)
        self.assertEqual(config.memory_limit, "1g")
        self.assertEqual(config.network_mode, "bridge")


class TestExecutionResult(unittest.TestCase):
    """测试 ExecutionResult"""
    
    def test_success_result(self):
        """测试成功结果"""
        result = ExecutionResult(
            command="echo hello",
            exit_code=0,
            stdout="hello",
            stderr="",
            duration_ms=100.0
        )
        
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, "hello")
        self.assertFalse(result.timed_out)
    
    def test_failure_result(self):
        """测试失败结果"""
        result = ExecutionResult(
            command="exit 1",
            exit_code=1,
            stdout="",
            stderr="error",
            duration_ms=50.0
        )
        
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.stderr, "error")
    
    def test_timeout_result(self):
        """测试超时结果"""
        result = ExecutionResult(
            command="sleep 100",
            exit_code=-1,
            stdout="",
            stderr="",
            duration_ms=30000.0,
            timed_out=True
        )
        
        self.assertTrue(result.timed_out)
    
    def test_to_dict(self):
        """测试转换为字典"""
        result = ExecutionResult(
            command="echo test",
            exit_code=0,
            stdout="test",
            stderr="",
            duration_ms=100.0
        )
        
        data = result.to_dict()
        self.assertEqual(data["command"], "echo test")
        self.assertEqual(data["exit_code"], 0)
        self.assertEqual(data["stdout"], "test")


if __name__ == "__main__":
    unittest.main()