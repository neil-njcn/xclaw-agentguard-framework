"""代理劫持检测器模块

检测Agent/LLM代理被劫持的攻击，包括：
- 权限提升尝试
- 目标/指令重定向
- 角色替换攻击
- 编码混淆技巧
"""
from .detector import AgentHijackingDetector
from . import patterns

__all__ = ["AgentHijackingDetector", "patterns"]
