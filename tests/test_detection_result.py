"""
DetectionResult 单元测试

测试覆盖:
- 基本构造和验证
- 不可变性保证
- 序列化/反序列化
- Builder模式
- 工厂方法
- 聚合函数
- 边界条件
"""

import json
import unittest
from datetime import datetime
from typing import List

from xclaw_agentguard import (
    DetectionResult,
    ThreatLevel,
    AttackType,
    DetectionResultBuilder,
)


class TestThreatLevel(unittest.TestCase):
    """测试 ThreatLevel 枚举"""
    
    def test_enum_values(self):
        """测试枚举值"""
        self.assertEqual(ThreatLevel.CRITICAL.value, "critical")
        self.assertEqual(ThreatLevel.HIGH.value, "high")
        self.assertEqual(ThreatLevel.MEDIUM.value, "medium")
        self.assertEqual(ThreatLevel.LOW.value, "low")
        self.assertEqual(ThreatLevel.NONE.value, "none")
    
    def test_to_int(self):
        """测试数值转换"""
        self.assertEqual(ThreatLevel.CRITICAL.to_int(), 4)
        self.assertEqual(ThreatLevel.HIGH.to_int(), 3)
        self.assertEqual(ThreatLevel.MEDIUM.to_int(), 2)
        self.assertEqual(ThreatLevel.LOW.to_int(), 1)
        self.assertEqual(ThreatLevel.NONE.to_int(), 0)
    
    def test_comparison(self):
        """测试比较操作"""
        self.assertTrue(ThreatLevel.CRITICAL > ThreatLevel.HIGH)
        self.assertTrue(ThreatLevel.HIGH > ThreatLevel.MEDIUM)
        self.assertTrue(ThreatLevel.MEDIUM > ThreatLevel.LOW)
        self.assertTrue(ThreatLevel.LOW > ThreatLevel.NONE)


class TestAttackType(unittest.TestCase):
    """测试 AttackType 枚举"""
    
    def test_display_name(self):
        """测试显示名称"""
        self.assertEqual(AttackType.PROMPT_INJECTION.display_name, "Prompt Injection")
        self.assertEqual(AttackType.JAILBREAK.display_name, "Jailbreak")
    
    def test_default_severity(self):
        """测试默认严重级别"""
        self.assertEqual(AttackType.PROMPT_INJECTION.severity, ThreatLevel.HIGH)
        self.assertEqual(AttackType.DATA_EXTRACTION.severity, ThreatLevel.CRITICAL)


class TestDetectionResult(unittest.TestCase):
    """测试 DetectionResult 类"""
    
    def setUp(self):
        """测试前置 setup"""
        from xclaw_agentguard.core.detection_result import ResultMetadata
        self.metadata = ResultMetadata(
            detector_id="test_detector",
            detector_version="1.0.0",
            processing_time_ms=42.0
        )
    
    def test_clean_result_construction(self):
        """测试清洁结果构造"""
        result = DetectionResult.clean(metadata=self.metadata)
        
        self.assertFalse(result.detected)
        self.assertEqual(result.threat_level, ThreatLevel.NONE)
        self.assertEqual(len(result.attack_types), 0)  # 可能是 tuple 或 list
        self.assertEqual(result.confidence, 1.0)
    
    def test_threat_result_construction(self):
        """测试威胁结果构造"""
        result = DetectionResult.threat(
            attack_type=AttackType.PROMPT_INJECTION,
            metadata=self.metadata
        )
        
        self.assertTrue(result.detected)
        self.assertEqual(result.threat_level, ThreatLevel.HIGH)
        self.assertIn(AttackType.PROMPT_INJECTION, result.attack_types)
    
    def test_consistency_validation(self):
        """测试一致性验证"""
        # detected=False 但 threat_level 不是 NONE，应该报错
        with self.assertRaises(ValueError):
            DetectionResult(
                detected=False,
                threat_level=ThreatLevel.HIGH,
                attack_types=[],
                confidence=0.9,
                evidence=None,
                metadata=self.metadata,
                timestamp=datetime.now()
            )
    
    def test_immutability(self):
        """测试不可变性"""
        result = DetectionResult.clean(metadata=self.metadata)
        
        # 尝试修改应该失败
        with self.assertRaises(AttributeError):
            result.detected = True
    
    def test_to_dict(self):
        """测试序列化为字典"""
        result = DetectionResult.clean(metadata=self.metadata)
        data = result.to_dict()
        
        self.assertIn("detected", data)
        self.assertIn("threat_level", data)
        self.assertFalse(data["detected"])
    
    def test_from_dict(self):
        """测试从字典反序列化"""
        result = DetectionResult.clean(metadata=self.metadata)
        data = result.to_dict()
        
        restored = DetectionResult.from_dict(data)
        self.assertEqual(restored.detected, result.detected)
        self.assertEqual(restored.threat_level, result.threat_level)
    
    def test_to_json(self):
        """测试序列化为 JSON"""
        result = DetectionResult.clean(metadata=self.metadata)
        json_str = result.to_json()
        
        self.assertIsInstance(json_str, str)
        data = json.loads(json_str)
        self.assertIn("detected", data)
    
    def test_from_json(self):
        """测试从 JSON 反序列化"""
        result = DetectionResult.clean(metadata=self.metadata)
        json_str = result.to_json()
        
        restored = DetectionResult.from_json(json_str)
        self.assertEqual(restored.detected, result.detected)
    
    def test_is_critical(self):
        """测试 is_critical 方法"""
        critical = DetectionResult.critical(
            attack_types=[AttackType.DATA_EXTRACTION],
            metadata=self.metadata
        )
        self.assertTrue(critical.is_critical())
        
        clean = DetectionResult.clean(metadata=self.metadata)
        self.assertFalse(clean.is_critical())
    
    def test_is_high_or_above(self):
        """测试 is_high_or_above 方法"""
        high = DetectionResult.threat(
            attack_type=AttackType.PROMPT_INJECTION,
            metadata=self.metadata
        )
        self.assertTrue(high.is_high_or_above())
        
        clean = DetectionResult.clean(metadata=self.metadata)
        self.assertFalse(clean.is_high_or_above())
    
    def test_has_attack_type(self):
        """测试 has_attack_type 方法"""
        result = DetectionResult.threat(
            attack_type=AttackType.PROMPT_INJECTION,
            metadata=self.metadata
        )
        self.assertTrue(result.has_attack_type(AttackType.PROMPT_INJECTION))
        self.assertFalse(result.has_attack_type(AttackType.JAILBREAK))
    
    def test_get_primary_attack(self):
        """测试 get_primary_attack 方法"""
        result = DetectionResult.threat(
            attack_type=AttackType.PROMPT_INJECTION,
            metadata=self.metadata
        )
        self.assertEqual(result.get_primary_attack(), AttackType.PROMPT_INJECTION)
        
        clean = DetectionResult.clean(metadata=self.metadata)
        self.assertIsNone(clean.get_primary_attack())
    
    def test_str_representation(self):
        """测试字符串表示"""
        result = DetectionResult.clean(metadata=self.metadata)
        str_repr = str(result)
        
        self.assertIn("CLEAN", str_repr)


class TestDetectionResultBuilder(unittest.TestCase):
    """测试 DetectionResultBuilder"""
    
    def test_builder_pattern(self):
        """测试 Builder 模式"""
        from xclaw_agentguard.core.detection_result import ResultMetadata
        
        result = DetectionResult.builder() \
            .detected(True) \
            .threat_level(ThreatLevel.HIGH) \
            .attack_type(AttackType.PROMPT_INJECTION) \
            .confidence(0.95) \
            .metadata("test", "1.0.0", 42.0) \
            .build()
        
        self.assertTrue(result.detected)
        self.assertEqual(result.threat_level, ThreatLevel.HIGH)
        self.assertEqual(result.confidence, 0.95)
    
    def test_builder_clean(self):
        """测试 build_clean 快捷方法"""
        result = DetectionResult.builder().build_clean("test", "1.0.0")
        
        self.assertFalse(result.detected)
        self.assertEqual(result.threat_level, ThreatLevel.NONE)
    
    def test_builder_threat(self):
        """测试 build_threat 快捷方法"""
        result = DetectionResult.builder().build_threat(
            AttackType.PROMPT_INJECTION,
            "test",
            "1.0.0"
        )
        
        self.assertTrue(result.detected)
        self.assertEqual(result.threat_level, ThreatLevel.HIGH)


class TestMergeResults(unittest.TestCase):
    """测试结果合并"""
    
    def setUp(self):
        from xclaw_agentguard.core.detection_result import ResultMetadata
        self.metadata = ResultMetadata(
            detector_id="test",
            detector_version="1.0.0",
            processing_time_ms=1.0
        )
    
    def test_merge_clean_results(self):
        """测试合并清洁结果"""
        from xclaw_agentguard.core.detection_result import merge_results
        
        results = [
            DetectionResult.clean(metadata=self.metadata),
            DetectionResult.clean(metadata=self.metadata),
        ]
        
        merged = merge_results(results)
        self.assertFalse(merged.detected)
    
    def test_merge_threat_results(self):
        """测试合并威胁结果"""
        from xclaw_agentguard.core.detection_result import merge_results
        
        results = [
            DetectionResult.threat(AttackType.PROMPT_INJECTION, self.metadata),
            DetectionResult.threat(AttackType.JAILBREAK, self.metadata),
        ]
        
        merged = merge_results(results)
        self.assertTrue(merged.detected)
        self.assertEqual(merged.threat_level, ThreatLevel.HIGH)
    
    def test_merge_mixed_results(self):
        """测试合并混合结果"""
        from xclaw_agentguard.core.detection_result import merge_results
        
        results = [
            DetectionResult.clean(metadata=self.metadata),
            DetectionResult.threat(AttackType.PROMPT_INJECTION, self.metadata),
        ]
        
        merged = merge_results(results)
        self.assertTrue(merged.detected)
    
    def test_empty_list_error(self):
        """测试空列表错误"""
        from xclaw_agentguard.core.detection_result import merge_results
        
        with self.assertRaises(ValueError):
            merge_results([])


class TestEdgeCases(unittest.TestCase):
    """测试边界条件"""
    
    def setUp(self):
        from xclaw_agentguard.core.detection_result import ResultMetadata
        self.metadata = ResultMetadata(
            detector_id="test",
            detector_version="1.0.0",
            processing_time_ms=1.0
        )
    
    def test_zero_confidence(self):
        """测试零置信度"""
        result = DetectionResult.clean(metadata=self.metadata, confidence=0.0)
        self.assertEqual(result.confidence, 0.0)
    
    def test_max_confidence(self):
        """测试最大置信度"""
        result = DetectionResult.clean(metadata=self.metadata, confidence=1.0)
        self.assertEqual(result.confidence, 1.0)
    
    def test_invalid_confidence(self):
        """测试无效置信度"""
        with self.assertRaises(ValueError):
            DetectionResult.clean(metadata=self.metadata, confidence=1.5)
        
        with self.assertRaises(ValueError):
            DetectionResult.clean(metadata=self.metadata, confidence=-0.1)


if __name__ == "__main__":
    unittest.main()