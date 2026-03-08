#!/usr/bin/env python3
"""
Anti-Jacked Extension API - Core Version (疫苗接口核心版)
XClaw AgentGuard v2.3.0 - Phase 3 Core Extension Module

提供基础的扩展接口:
1. AntiJackExtension基类
2. register_extension()方法  
3. 扩展沙箱(基础超时保护)

简化设计:
- 单一扩展点: 自定义检查规则
- 沙箱仅提供超时保护
- 不包含完整审计系统

Author: XClaw AgentGuard Security Team
Version: 1.0.0-core
"""

import os
import sys
import json
import time
import signal
import threading
import traceback
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from pathlib import Path
import logging

logger = logging.getLogger('anti-jacked-ext-core')


# =============================================================================
# Core Data Classes
# =============================================================================

@dataclass
class ExtensionViolation:
    """
    扩展规则检测到的违规报告
    
    Attributes:
        path: 被检查的文件路径
        violation_type: 违规类型标识
        severity: 严重级别 (critical, high, medium, low)
        message: 人类可读的描述
        details: 额外详情字典
        timestamp: 检测时间戳
        extension_id: 检测此违规的扩展ID
    """
    path: str
    violation_type: str
    severity: str  # "critical", "high", "medium", "low"
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    extension_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'path': self.path,
            'violation_type': self.violation_type,
            'severity': self.severity,
            'message': self.message,
            'details': self.details,
            'timestamp': self.timestamp,
            'extension_id': self.extension_id
        }


@dataclass  
class ExtensionMetadata:
    """扩展元数据"""
    id: str                          # 唯一标识符
    name: str                        # 显示名称
    version: str                     # 版本号
    author: str                      # 作者
    description: str                 # 描述
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description
        }


# =============================================================================
# Core Extension Base Class
# =============================================================================

class AntiJackExtension(ABC):
    """
    Anti-Jacked扩展基类 (疫苗API)
    
    所有自定义检查规则必须继承此类。
    扩展在沙箱环境中运行,受超时保护。
    
    Example:
        class MyCustomRule(AntiJackExtension):
            def __init__(self):
                super().__init__(
                    metadata=ExtensionMetadata(
                        id="my_rule",
                        name="My Rule",
                        version="1.0.0",
                        author="Security Team",
                        description="检测可疑模式"
                    )
                )
            
            def get_priority(self) -> int:
                return 50
            
            def check(self, file_path: str, file_hash: str) -> Optional[ExtensionViolation]:
                if "suspicious" in file_path:
                    return ExtensionViolation(
                        path=file_path,
                        violation_type="suspicious_pattern",
                        severity="high",
                        message="检测到可疑文件模式"
                    )
                return None
    """
    
    def __init__(self, metadata: ExtensionMetadata):
        self.metadata = metadata
        self.config: Dict[str, Any] = {}
        self._created_at = time.time()
        self._check_count = 0
        self._violation_count = 0
        self._error_count = 0
        self._last_error: Optional[str] = None
        self._active = True
    
    @abstractmethod
    def get_priority(self) -> int:
        """
        获取扩展优先级 (0-100, 越高越早执行)
        
        Returns:
            0-100之间的优先级值
        """
        pass
    
    @abstractmethod
    def check(self, file_path: str, file_hash: str) -> Optional[ExtensionViolation]:
        """
        检查文件是否违反自定义规则
        
        这是唯一的扩展点。自定义规则通过实现此方法来
        检测特定的安全威胁。
        
        Args:
            file_path: 文件路径
            file_hash: 文件SHA256哈希
            
        Returns:
            ExtensionViolation如果规则触发,否则None
        """
        pass
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """
        使用配置初始化扩展
        
        Args:
            config: 配置字典
            
        Returns:
            True如果初始化成功
        """
        self.config = config
        self._active = True
        return True
    
    def shutdown(self) -> None:
        """关闭扩展,清理资源"""
        self._active = False
    
    def get_stats(self) -> Dict[str, Any]:
        """获取扩展统计信息"""
        return {
            'id': self.metadata.id,
            'active': self._active,
            'created_at': self._created_at,
            'check_count': self._check_count,
            'violation_count': self._violation_count,
            'error_count': self._error_count,
            'last_error': self._last_error,
            'priority': self.get_priority()
        }
    
    def _record_check(self) -> None:
        """记录检查执行 (内部使用)"""
        self._check_count += 1
    
    def _record_violation(self) -> None:
        """记录违规检测 (内部使用)"""
        self._violation_count += 1
    
    def _record_error(self, error: str) -> None:
        """记录错误 (内部使用)"""
        self._error_count += 1
        self._last_error = error


# =============================================================================
# Extension Sandbox (Simplified)
# =============================================================================

class ExtensionSandbox:
    """
    扩展沙箱 - 基础超时保护
    
    提供:
    - 超时保护 (最大执行时间)
    - 异常隔离
    """
    
    DEFAULT_TIMEOUT = 5.0  # 5秒超时
    
    def __init__(self, timeout: float = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self._executor = ThreadPoolExecutor(max_workers=4)
    
    def execute(self, extension: AntiJackExtension, 
                file_path: str, 
                file_hash: str) -> Tuple[bool, Optional[ExtensionViolation], Optional[str]]:
        """
        在沙箱中执行扩展检查
        
        Args:
            extension: 扩展实例
            file_path: 文件路径
            file_hash: 文件哈希
            
        Returns:
            Tuple of (success: bool, violation: Optional[ExtensionViolation], error: Optional[str])
        """
        if not extension._active:
            return False, None, "Extension is not active"
        
        # 在线程池中执行,带超时
        future = self._executor.submit(
            self._run_check_safely, extension, file_path, file_hash
        )
        
        try:
            return future.result(timeout=self.timeout)
        except FutureTimeoutError:
            error = f"Extension {extension.metadata.id} timed out after {self.timeout}s"
            extension._record_error(error)
            return False, None, error
        except Exception as e:
            error = f"Extension {extension.metadata.id} crashed: {str(e)}"
            extension._record_error(error)
            return False, None, error
    
    def _run_check_safely(self, extension: AntiJackExtension,
                          file_path: str, file_hash: str) -> Tuple[bool, Optional[ExtensionViolation], Optional[str]]:
        """安全地运行扩展检查,捕获所有异常"""
        try:
            result = extension.check(file_path, file_hash)
            extension._record_check()
            if result is not None:
                result.extension_id = extension.metadata.id
                extension._record_violation()
            return True, result, None
        except Exception as e:
            return False, None, str(e)
    
    def shutdown(self) -> None:
        """关闭沙箱"""
        self._executor.shutdown(wait=True)


# =============================================================================
# Extension Registry (Simplified)
# =============================================================================

class ExtensionRegistry:
    """
    扩展注册表 - 管理扩展生命周期
    
    简化版本仅支持:
    - 注册/注销扩展
    - 执行所有扩展检查
    - 按优先级排序
    """
    
    def __init__(self):
        self._extensions: Dict[str, AntiJackExtension] = {}
        self._extension_order: List[str] = []  # 按优先级排序的ID列表
        self._sandbox = ExtensionSandbox()
        self._lock = threading.RLock()
    
    def register_extension(self, extension: AntiJackExtension, 
                          config: Optional[Dict[str, Any]] = None) -> bool:
        """
        注册扩展
        
        Args:
            extension: 扩展实例
            config: 可选配置字典
            
        Returns:
            True如果注册成功
            
        Example:
            registry = ExtensionRegistry()
            registry.register_extension(MyCustomRule())
        """
        with self._lock:
            ext_id = extension.metadata.id
            
            if ext_id in self._extensions:
                logger.warning(f"Extension {ext_id} already registered, skipping")
                return False
            
            # 初始化扩展
            config = config or {}
            if not extension.initialize(config):
                logger.error(f"Extension {ext_id} initialization failed")
                return False
            
            # 注册
            self._extensions[ext_id] = extension
            self._sort_extensions()
            
            logger.info(f"Registered extension: {ext_id} (priority: {extension.get_priority()})")
            return True
    
    def unregister_extension(self, extension_id: str) -> bool:
        """
        注销扩展
        
        Args:
            extension_id: 要注销的扩展ID
            
        Returns:
            True如果注销成功
        """
        with self._lock:
            if extension_id not in self._extensions:
                return False
            
            extension = self._extensions[extension_id]
            extension.shutdown()
            
            del self._extensions[extension_id]
            self._extension_order.remove(extension_id)
            
            logger.info(f"Unregistered extension: {extension_id}")
            return True
    
    def check_file(self, file_path: str, file_hash: str) -> List[ExtensionViolation]:
        """
        使用所有已注册扩展检查文件
        
        Args:
            file_path: 文件路径
            file_hash: 文件SHA256哈希
            
        Returns:
            检测到的违规列表
        """
        violations = []
        
        with self._lock:
            extensions = [self._extensions[ext_id] for ext_id in self._extension_order]
        
        for extension in extensions:
            success, violation, error = self._sandbox.execute(
                extension, file_path, file_hash
            )
            
            if success and violation is not None:
                violations.append(violation)
            elif error:
                logger.warning(f"Extension {extension.metadata.id} error: {error}")
        
        return violations
    
    def get_extension(self, extension_id: str) -> Optional[AntiJackExtension]:
        """通过ID获取扩展"""
        return self._extensions.get(extension_id)
    
    def list_extensions(self) -> List[Dict[str, Any]]:
        """列出所有已注册扩展"""
        with self._lock:
            return [
                {
                    'metadata': ext.metadata.to_dict(),
                    'stats': ext.get_stats()
                }
                for ext_id in self._extension_order
                for ext in [self._extensions[ext_id]]
            ]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取注册表统计信息"""
        with self._lock:
            return {
                'registered_count': len(self._extensions),
                'extensions': [ext_id for ext_id in self._extension_order]
            }
    
    def _sort_extensions(self) -> None:
        """按优先级排序扩展 (高优先级在前)"""
        self._extension_order = sorted(
            self._extensions.keys(),
            key=lambda eid: self._extensions[eid].get_priority(),
            reverse=True
        )
    
    def shutdown(self) -> None:
        """关闭所有扩展和沙箱"""
        with self._lock:
            for extension in self._extensions.values():
                extension.shutdown()
            self._sandbox.shutdown()
            logger.info("Extension registry shutdown complete")


# =============================================================================
# Integration Helper
# =============================================================================

class AntiJackedExtensionMixin:
    """
    AntiJacked扩展混入类
    
    为现有AntiJacked类添加扩展支持。
    核心功能不受影响,扩展作为额外检查层。
    
    Usage:
        class AntiJackedWithExtensions(AntiJacked, AntiJackedExtensionMixin):
            def __init__(self):
                super().__init__()
                self._init_extensions()
            
            def verify_integrity(self):
                # 1. 运行核心检查
                core_valid, core_violations = super().verify_integrity()
                
                # 2. 运行扩展检查
                ext_violations = self.check_with_extensions()
                
                return core_valid and len(ext_violations) == 0, core_violations + ext_violations
    """
    
    def _init_extensions(self) -> None:
        """初始化扩展系统"""
        self._extension_registry = ExtensionRegistry()
    
    def register_extension(self, extension: AntiJackExtension, 
                          config: Optional[Dict[str, Any]] = None) -> bool:
        """
        注册扩展
        
        Example:
            anti_jacked.register_extension(MyCustomRule())
        """
        return self._extension_registry.register_extension(extension, config)
    
    def check_with_extensions(self, file_path: Optional[str] = None) -> List[ExtensionViolation]:
        """
        使用扩展检查文件
        
        Args:
            file_path: 特定文件路径,为None则检查所有基线文件
            
        Returns:
            扩展检测到的违规列表
        """
        violations = []
        
        if file_path:
            # 检查特定文件
            from anti_jacked import SecureHasher
            file_hash = SecureHasher.sha256_file(file_path)
            violations.extend(self._extension_registry.check_file(file_path, file_hash))
        elif hasattr(self, 'baseline') and self.baseline.files:
            # 检查所有基线文件
            for path, entry in self.baseline.files.items():
                violations.extend(self._extension_registry.check_file(path, entry.sha256))
        
        return violations
    
    def get_extension_stats(self) -> Dict[str, Any]:
        """获取扩展统计信息"""
        return self._extension_registry.get_stats()
    
    def shutdown_extensions(self) -> None:
        """关闭扩展系统"""
        self._extension_registry.shutdown()


# =============================================================================
# Convenience Exports
# =============================================================================

__all__ = [
    # Core classes
    'AntiJackExtension',
    'ExtensionRegistry',
    'ExtensionSandbox',
    'AntiJackedExtensionMixin',
    
    # Data classes
    'ExtensionViolation',
    'ExtensionMetadata',
]
