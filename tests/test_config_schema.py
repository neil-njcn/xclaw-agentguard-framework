"""
ConfigSchema 单元测试

测试覆盖:
- 基本配置创建
- 字段验证
- 默认值处理
- 类型检查
- 范围验证
"""

import unittest
from typing import List, Optional

from xclaw_agentguard.core.config_schema import (
    ConfigSchema,
    ConfigValidator,
    DetectorConfig
)


class TestConfigSchema(unittest.TestCase):
    """测试 ConfigSchema 类"""
    
    def test_basic_creation(self):
        """测试基本创建"""
        schema = ConfigSchema(
            name="threshold",
            type=float,
            description="Detection threshold",
            default=0.5
        )
        
        self.assertEqual(schema.name, "threshold")
        self.assertEqual(schema.type, float)
        self.assertEqual(schema.default, 0.5)
    
    def test_with_valid_range(self):
        """测试范围验证"""
        schema = ConfigSchema(
            name="threshold",
            type=float,
            description="Detection threshold",
            default=0.5,
            valid_range=(0.0, 1.0)
        )
        
        self.assertEqual(schema.valid_range, (0.0, 1.0))
    
    def test_with_valid_values(self):
        """测试有效值列表"""
        schema = ConfigSchema(
            name="mode",
            type=str,
            description="Detection mode",
            default="normal",
            valid_values=["strict", "normal", "permissive"]
        )
        
        self.assertIn("strict", schema.valid_values)
    
    def test_required_field(self):
        """测试必填字段"""
        schema = ConfigSchema(
            name="api_key",
            type=str,
            description="API key",
            default="",
            required=True
        )
        
        self.assertTrue(schema.required)
    
    def test_to_dict(self):
        """测试转换为字典"""
        schema = ConfigSchema(
            name="threshold",
            type=float,
            description="Detection threshold",
            default=0.5
        )
        
        data = schema.to_dict()
        self.assertEqual(data["name"], "threshold")
        self.assertEqual(data["type"], "float")
        self.assertEqual(data["default"], 0.5)


class TestConfigValidator(unittest.TestCase):
    """测试 ConfigValidator 类"""
    
    def test_validate_valid_config(self):
        """测试验证有效配置"""
        schema = DetectorConfig(
            detector_id="test",
            version="1.0.0",
            schema=[
                ConfigSchema(
                    name="threshold",
                    type=float,
                    description="Detection threshold",
                    default=0.5
                )
            ]
        )
        
        is_valid, errors = ConfigValidator.validate({"threshold": 0.7}, schema)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)
    
    def test_validate_type_error(self):
        """测试类型错误"""
        schema = DetectorConfig(
            detector_id="test",
            version="1.0.0",
            schema=[
                ConfigSchema(
                    name="count",
                    type=int,
                    description="Count value",
                    default=0
                )
            ]
        )
        
        is_valid, errors = ConfigValidator.validate({"count": "not_a_number"}, schema)
        self.assertFalse(is_valid)
    
    def test_validate_missing_required(self):
        """测试缺少必填字段"""
        schema = DetectorConfig(
            detector_id="test",
            version="1.0.0",
            schema=[
                ConfigSchema(
                    name="name",
                    type=str,
                    description="Name field",
                    default="",
                    required=True
                )
            ]
        )
        
        is_valid, errors = ConfigValidator.validate({}, schema)
        self.assertFalse(is_valid)
        self.assertTrue(any("required" in e.lower() for e in errors))
    
    def test_validate_range_error(self):
        """测试范围错误"""
        schema = DetectorConfig(
            detector_id="test",
            version="1.0.0",
            schema=[
                ConfigSchema(
                    name="threshold",
                    type=float,
                    description="Detection threshold",
                    default=0.5,
                    valid_range=(0.0, 1.0)
                )
            ]
        )
        
        is_valid, errors = ConfigValidator.validate({"threshold": 1.5}, schema)
        self.assertFalse(is_valid)
    
    def test_validate_valid_values_error(self):
        """测试有效值错误"""
        schema = DetectorConfig(
            detector_id="test",
            version="1.0.0",
            schema=[
                ConfigSchema(
                    name="mode",
                    type=str,
                    description="Detection mode",
                    default="normal",
                    valid_values=["strict", "normal", "permissive"]
                )
            ]
        )
        
        is_valid, errors = ConfigValidator.validate({"mode": "invalid"}, schema)
        self.assertFalse(is_valid)
    
    def test_apply_defaults(self):
        """测试应用默认值"""
        detector_config = DetectorConfig(
            detector_id="test",
            version="1.0.0",
            schema=[
                ConfigSchema(
                    name="threshold",
                    type=float,
                    description="Detection threshold",
                    default=0.5
                ),
                ConfigSchema(
                    name="enabled",
                    type=bool,
                    description="Enable detection",
                    default=True
                )
            ]
        )
        
        config = {}
        result = ConfigValidator.apply_defaults(config, detector_config)
        
        self.assertEqual(result["threshold"], 0.5)
        self.assertEqual(result["enabled"], True)


class TestDetectorConfig(unittest.TestCase):
    """测试 DetectorConfig 类"""
    
    def test_basic_creation(self):
        """测试基本创建"""
        schemas = [
            ConfigSchema(
                name="threshold",
                type=float,
                description="Detection threshold",
                default=0.5
            )
        ]
        
        config = DetectorConfig(
            detector_id="prompt_injection",
            version="1.0.0",
            schema=schemas
        )
        
        self.assertEqual(config.detector_id, "prompt_injection")
        self.assertEqual(config.version, "1.0.0")
    
    def test_to_dict(self):
        """测试转换为字典"""
        schemas = [
            ConfigSchema(
                name="threshold",
                type=float,
                description="Detection threshold",
                default=0.5
            )
        ]
        
        config = DetectorConfig(
            detector_id="prompt_injection",
            version="1.0.0",
            schema=schemas
        )
        
        data = config.to_dict()
        self.assertEqual(data["detector_id"], "prompt_injection")
        self.assertIn("schema", data)
    
    def test_get_config_names(self):
        """测试获取配置名称列表"""
        schemas = [
            ConfigSchema(
                name="threshold",
                type=float,
                description="Detection threshold",
                default=0.5
            ),
            ConfigSchema(
                name="enabled",
                type=bool,
                description="Enable detection",
                default=True
            )
        ]
        
        config = DetectorConfig(
            detector_id="prompt_injection",
            version="1.0.0",
            schema=schemas
        )
        
        names = config.get_config_names()
        self.assertIn("threshold", names)
        self.assertIn("enabled", names)
    
    def test_get_config(self):
        """测试获取单个配置"""
        schemas = [
            ConfigSchema(
                name="threshold",
                type=float,
                description="Detection threshold",
                default=0.5
            )
        ]
        
        config = DetectorConfig(
            detector_id="prompt_injection",
            version="1.0.0",
            schema=schemas
        )
        
        schema = config.get_config("threshold")
        self.assertIsNotNone(schema)
        self.assertEqual(schema.name, "threshold")
        
        # 不存在的配置
        schema = config.get_config("nonexistent")
        self.assertIsNone(schema)


if __name__ == "__main__":
    unittest.main()