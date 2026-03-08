"""越狱攻击检测器模块 - 检测试图绕过AI安全限制的攻击"""
from .detector import JailbreakDetector
from . import patterns

__all__ = ["JailbreakDetector", "patterns"]
