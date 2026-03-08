"""数据外泄检测器模块 (ExfiltrationGuard)"""
from .detector import ExfiltrationGuard
from . import patterns

__all__ = ["ExfiltrationGuard", "patterns"]
