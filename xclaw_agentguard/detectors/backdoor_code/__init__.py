"""后门代码检测器模块

检测代码中的后门攻击，包括:
- 远程Shell/命令执行
- 反向Shell连接
- 动态代码执行
- 代码混淆
- 逻辑炸弹
"""
from .detector import BackdoorCodeDetector
from . import patterns

__all__ = ["BackdoorCodeDetector", "patterns"]
