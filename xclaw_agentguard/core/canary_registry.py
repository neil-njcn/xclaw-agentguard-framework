"""
Canary注册中心 - 集成Canary发布机制到检测器注册中心
提供统一的API接口进行灰度发布管理
"""
from typing import Dict, Any, Optional, List, Callable, Union
import logging

from .base_detector import BaseDetector
from .detection_result import DetectionResult
from .canary_controller import (
    CanaryController,
    CanaryConfig,
    CanaryState,
    CanaryStage,
    MetricThresholds,
    RolloutStrategy,
    PromotionDecision
)

logger = logging.getLogger(__name__)


class CanaryRegistry:
    """
    Canary注册中心
    
    功能:
    1. 管理检测器注册和生命周期
    2. 集成Canary发布流程
    3. 提供统一的检测器调用接口
    4. 支持A/B测试对比
    """
    
    def __init__(
        self,
        canary_controller: Optional[CanaryController] = None,
        enable_auto_monitoring: bool = True
    ):
        """
        初始化Canary注册中心
        
        Args:
            canary_controller: Canary控制器实例(默认创建新的)
            enable_auto_monitoring: 是否启用自动监控
        """
        self._detectors: Dict[str, BaseDetector] = {}
        self._baseline_detectors: Dict[str, BaseDetector] = {}
        self._canary = canary_controller or CanaryController()
        self._enable_auto_monitoring = enable_auto_monitoring
        
        if enable_auto_monitoring:
            self._canary.start_monitoring()
    
    def register(
        self,
        detector_id: str,
        detector: BaseDetector,
        is_canary: bool = False
    ) -> bool:
        """
        注册检测器
        
        Args:
            detector_id: 检测器ID
            detector: 检测器实例
            is_canary: 是否为Canary版本(如果是，需要配合baseline_detector使用)
        
        Returns:
            bool: 是否注册成功
        """
        if is_canary:
            # Canary版本暂时不注册到主检测器列表
            logger.info(f"Canary detector {detector_id} staged (not active yet)")
            return True
        
        self._detectors[detector_id] = detector
        logger.info(f"Detector {detector_id} registered")
        return True
    
    def register_baseline(
        self,
        detector_id: str,
        detector: BaseDetector
    ) -> bool:
        """
        注册基线检测器(用于Canary对比)
        
        Args:
            detector_id: 检测器ID
            detector: 基线检测器实例
        
        Returns:
            bool: 是否注册成功
        """
        self._baseline_detectors[detector_id] = detector
        logger.info(f"Baseline detector {detector_id} registered")
        return True
    
    def register_canary_pair(
        self,
        detector_id: str,
        new_detector: BaseDetector,
        baseline_detector: BaseDetector,
        config: CanaryConfig
    ) -> bool:
        """
        注册Canary检测器对(新检测器 + 基线检测器)
        
        Args:
            detector_id: 检测器ID
            new_detector: 新检测器实例
            baseline_detector: 基线检测器实例
            config: Canary配置
        
        Returns:
            bool: 是否注册成功
        """
        # 注册两个检测器
        self._detectors[detector_id] = new_detector
        self._baseline_detectors[detector_id] = baseline_detector
        
        # 注册到Canary控制器
        self._canary.register_detector(detector_id, config)
        
        logger.info(
            f"Canary pair registered for {detector_id} with "
            f"initial rollout {config.rollout_percentage}%"
        )
        return True
    
    def enable_with_canary(
        self,
        detector_id: str,
        config: Optional[Union[CanaryConfig, Dict[str, Any]]] = None,
        initial_percentage: Optional[float] = None
    ) -> bool:
        """
        启用Canary发布
        
        这是主要的Canary启动入口，支持两种方式:
        1. 已注册检测器，直接传入配置
        2. 传入字典配置，自动转换为CanaryConfig
        
        Args:
            detector_id: 检测器ID
            config: Canary配置(对象或字典)
            initial_percentage: 初始流量百分比(覆盖配置中的值)
        
        Returns:
            bool: 是否成功启用
        
        Example:
            ```python
            registry.enable_with_canary(
                "sql_injection_v2",
                config={
                    "detector_id": "sql_injection_v2",
                    "rollout_percentage": 5,
                    "target_metrics": {
                        "false_positive_rate": 0.01,
                        "latency_p99": 100
                    },
                    "auto_promote": True,
                    "rollback_threshold": 0.05
                }
            )
            ```
        """
        # 转换配置
        if config is None:
            config = CanaryConfig(detector_id=detector_id)
        elif isinstance(config, dict):
            config = CanaryConfig(**config)
        
        # 确保detector_id一致
        config.detector_id = detector_id
        
        # 检查检测器是否已注册
        if detector_id not in self._detectors:
            logger.error(f"Detector {detector_id} not registered")
            return False
        
        # 如果没有基线检测器，使用自身作为基线(对比模式)
        if detector_id not in self._baseline_detectors:
            logger.warning(
                f"No baseline detector for {detector_id}, "
                f"using self-comparison mode"
            )
        
        # 注册到Canary控制器(如果尚未注册)
        state = self._canary.get_state(detector_id)
        if state is None:
            self._canary.register_detector(detector_id, config)
        
        # 启用Canary
        return self._canary.enable_canary(detector_id, initial_percentage)
    
    def detect(
        self,
        detector_id: str,
        input_data: Any,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ground_truth: Optional[bool] = None
    ) -> DetectionResult:
        """
        执行检测(自动路由到Canary或基线检测器)
        
        这是主要的检测入口，自动处理:
        1. 判断是否使用新检测器(Canary路由)
        2. 执行检测
        3. 记录指标
        4. 对比基线结果(如果可用)
        
        Args:
            detector_id: 检测器ID
            input_data: 输入数据
            user_id: 用户ID(用于一致性路由)
            session_id: 会话ID(用于一致性路由)
            ground_truth: 真实结果(用于指标计算)
        
        Returns:
            DetectionResult: 检测结果
        """
        import time
        
        # 检查Canary状态
        use_new_detector = self._canary.should_use_new_detector(
            detector_id, user_id, session_id
        )
        
        start_time = time.time()
        error = None
        
        try:
            if use_new_detector:
                # 使用新检测器
                if detector_id not in self._detectors:
                    raise ValueError(f"Detector {detector_id} not found")
                
                detector = self._detectors[detector_id]
                result = detector.detect_safe(input_data)
            else:
                # 使用基线检测器
                if detector_id in self._baseline_detectors:
                    detector = self._baseline_detectors[detector_id]
                    result = detector.detect_safe(input_data)
                elif detector_id in self._detectors:
                    # 如果没有基线，使用主检测器
                    detector = self._detectors[detector_id]
                    result = detector.detect_safe(input_data)
                else:
                    raise ValueError(f"Detector {detector_id} not found")
            
            detected = result.detected if result.detected is not None else False
            
        except Exception as e:
            error = str(e)
            result = None
            detected = False
            logger.error(f"Detection error for {detector_id}: {e}")
        
        latency_ms = (time.time() - start_time) * 1000
        
        # 记录指标(仅当Canary启用时)
        state = self._canary.get_state(detector_id)
        if state and state.current_stage != CanaryStage.DISABLED:
            self._canary.record_request(
                detector_id=detector_id,
                used_new_detector=use_new_detector,
                latency_ms=latency_ms,
                detected=detected,
                ground_truth=ground_truth,
                error=error
            )
            
            # 如果同时有基线检测，进行对比记录
            if use_new_detector and detector_id in self._baseline_detectors:
                try:
                    baseline_detector = self._baseline_detectors[detector_id]
                    baseline_result = baseline_detector.detect_safe(input_data)
                    # 这里可以记录对比数据用于分析
                except Exception as e:
                    logger.debug(f"Baseline comparison error: {e}")
        
        return result if result is not None else DetectionResult.with_error(
            error=type('DetectionError', (), {
                'message': error or 'Unknown error',
                'category': 'ERROR'
            })()
        )
    
    def update_rollout(self, detector_id: str, percentage: float) -> bool:
        """
        更新流量百分比
        
        Args:
            detector_id: 检测器ID
            percentage: 新的流量百分比 (0-100)
        
        Returns:
            bool: 是否成功更新
        
        Example:
            ```python
            # 手动调整到20%流量
            registry.update_rollout("sql_injection_v2", 20)
            
            # 全量发布
            registry.update_rollout("sql_injection_v2", 100)
            
            # 暂停Canary
            registry.update_rollout("sql_injection_v2", 0)
            ```
        """
        return self._canary.update_rollout_percentage(detector_id, percentage)
    
    def rollback(self, detector_id: str, reason: str = "manual") -> bool:
        """
        回滚检测器
        
        Args:
            detector_id: 检测器ID
            reason: 回滚原因
        
        Returns:
            bool: 是否成功回滚
        
        Example:
            ```python
            # 手动回滚
            registry.rollback("sql_injection_v2", reason="high_false_positive")
            ```
        """
        return self._canary.rollback(detector_id, reason)
    
    def promote(self, detector_id: str) -> bool:
        """
        手动晋升到下一阶段
        
        Args:
            detector_id: 检测器ID
        
        Returns:
            bool: 是否成功晋升
        
        Example:
            ```python
            # 手动晋升到下一阶段
            registry.promote("sql_injection_v2")
            ```
        """
        return self._canary.promote(detector_id)
    
    def get_canary_status(self, detector_id: str) -> Optional[Dict[str, Any]]:
        """
        获取Canary状态
        
        Args:
            detector_id: 检测器ID
        
        Returns:
            Dict: Canary状态详情
        """
        state = self._canary.get_state(detector_id)
        if state is None:
            return None
        
        return state.to_dict()
    
    def get_all_canary_status(self) -> Dict[str, Dict[str, Any]]:
        """
        获取所有Canary检测器状态
        
        Returns:
            Dict: 所有Canary状态
        """
        states = self._canary.get_all_states()
        return {
            detector_id: state.to_dict()
            for detector_id, state in states.items()
        }
    
    def evaluate(self, detector_id: str) -> PromotionDecision:
        """
        评估检测器晋升条件
        
        Args:
            detector_id: 检测器ID
        
        Returns:
            PromotionDecision: 晋升决策结果
        """
        return self._canary.evaluate_promotion(detector_id)
    
    def list_active_canaries(self) -> List[str]:
        """
        列出活跃的Canary检测器
        
        Returns:
            List[str]: 活跃的检测器ID列表
        """
        active = []
        for detector_id, state in self._canary.get_all_states().items():
            if state.current_stage not in (
                CanaryStage.DISABLED,
                CanaryStage.ROLLED_BACK
            ):
                active.append(detector_id)
        return active
    
    def unregister(self, detector_id: str) -> bool:
        """
        注销检测器
        
        Args:
            detector_id: 检测器ID
        
        Returns:
            bool: 是否成功注销
        """
        # 如果正在Canary中，先回滚
        state = self._canary.get_state(detector_id)
        if state and state.current_stage not in (
            CanaryStage.DISABLED,
            CanaryStage.ROLLED_BACK
        ):
            self._canary.rollback(detector_id, reason="unregistered")
        
        # 从注册表中移除
        self._detectors.pop(detector_id, None)
        self._baseline_detectors.pop(detector_id, None)
        
        logger.info(f"Detector {detector_id} unregistered")
        return True
    
    def register_callback(self, event: str, callback: Callable):
        """
        注册事件回调
        
        Args:
            event: 事件类型 (on_promote, on_rollback, on_metric_alert)
            callback: 回调函数
        """
        self._canary.register_callback(event, callback)
    
    def get_detector(self, detector_id: str) -> Optional[BaseDetector]:
        """
        获取检测器实例
        
        Args:
            detector_id: 检测器ID
        
        Returns:
            BaseDetector: 检测器实例
        """
        return self._detectors.get(detector_id)
    
    def get_baseline_detector(self, detector_id: str) -> Optional[BaseDetector]:
        """
        获取基线检测器实例
        
        Args:
            detector_id: 检测器ID
        
        Returns:
            BaseDetector: 基线检测器实例
        """
        return self._baseline_detectors.get(detector_id)
    
    def shutdown(self):
        """关闭注册中心，停止监控"""
        self._canary.stop_monitoring()
        logger.info("Canary registry shut down")


# 便捷函数 - 创建标准Canary配置
def create_canary_config(
    detector_id: str,
    rollout_percentage: float = 5.0,
    false_positive_rate: float = 0.01,
    latency_p99: float = 100.0,
    auto_promote: bool = True,
    rollback_threshold: float = 0.05,
    observation_minutes: int = 10,
    strategy: str = "percentage"
) -> CanaryConfig:
    """
    创建标准Canary配置
    
    Args:
        detector_id: 检测器ID
        rollout_percentage: 初始流量百分比
        false_positive_rate: 目标误报率
        latency_p99: 目标P99延迟
        auto_promote: 是否自动晋升
        rollback_threshold: 自动回滚阈值
        observation_minutes: 观察时间(分钟)
        strategy: 流量分配策略
    
    Returns:
        CanaryConfig: Canary配置对象
    
    Example:
        ```python
        config = create_canary_config(
            detector_id="sql_injection_v2",
            rollout_percentage=5,
            false_positive_rate=0.01,
            latency_p99=100
        )
        registry.enable_with_canary("sql_injection_v2", config)
        ```
    """
    return CanaryConfig(
        detector_id=detector_id,
        rollout_percentage=rollout_percentage,
        target_metrics=MetricThresholds(
            false_positive_rate=false_positive_rate,
            latency_p99=latency_p99
        ),
        auto_promote=auto_promote,
        rollback_threshold=rollback_threshold,
        observation_minutes=observation_minutes,
        strategy=RolloutStrategy(strategy)
    )


# 全局注册中心实例
_canary_registry: Optional[CanaryRegistry] = None


def get_canary_registry() -> CanaryRegistry:
    """获取全局Canary注册中心实例"""
    global _canary_registry
    if _canary_registry is None:
        _canary_registry = CanaryRegistry()
    return _canary_registry


def reset_canary_registry():
    """重置全局注册中心(主要用于测试)"""
    global _canary_registry
    if _canary_registry:
        _canary_registry.shutdown()
    _canary_registry = None