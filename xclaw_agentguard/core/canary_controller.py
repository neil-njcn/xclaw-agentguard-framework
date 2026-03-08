"""
Canary发布机制 - 灰度发布控制器
实现渐进式发布，支持百分比灰度、自动监控和自动回滚
"""
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Callable, Set
from collections import defaultdict
import time
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CanaryStage(Enum):
    """Canary发布阶段"""
    DISABLED = "disabled"           # 未启用
    CANARY_5 = "canary_5"           # 5% 流量
    CANARY_20 = "canary_20"         # 20% 流量
    CANARY_50 = "canary_50"         # 50% 流量
    GA = "ga"                       # 100% 流量 (General Availability)
    ROLLING_BACK = "rolling_back"   # 回滚中
    ROLLED_BACK = "rolled_back"     # 已回滚


class RolloutStrategy(Enum):
    """流量分配策略"""
    PERCENTAGE = "percentage"       # 纯百分比随机
    USER_ID = "user_id"             # 基于用户ID哈希
    SESSION = "session"             # 基于会话ID
    TIME_SLICE = "time_slice"       # 基于时间切片
    COMBINED = "combined"           # 组合策略


class PromotionDecision(Enum):
    """晋升决策结果"""
    PROMOTE = "promote"             # 晋升到下一阶段
    HOLD = "hold"                   # 保持当前阶段
    ROLLBACK = "rollback"           # 回滚


@dataclass
class MetricThresholds:
    """指标阈值配置"""
    false_positive_rate: float = 0.01      # 误报率阈值
    latency_p99: float = 100.0             # P99延迟阈值(ms)
    latency_p95: float = 50.0              # P95延迟阈值(ms)
    error_rate: float = 0.001              # 错误率阈值
    min_sample_size: int = 100             # 最小样本数
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "false_positive_rate": self.false_positive_rate,
            "latency_p99": self.latency_p99,
            "latency_p95": self.latency_p95,
            "error_rate": self.error_rate,
            "min_sample_size": self.min_sample_size
        }


@dataclass
class CanaryConfig:
    """Canary发布配置"""
    detector_id: str
    rollout_percentage: float = 5.0        # 初始流量百分比
    target_metrics: MetricThresholds = field(default_factory=MetricThresholds)
    auto_promote: bool = True              # 是否自动晋升
    auto_rollback: bool = True             # 是否自动回滚
    rollback_threshold: float = 0.05       # 自动回滚阈值(误报率)
    observation_minutes: int = 10          # 每阶段观察时间(分钟)
    promotion_criteria: Dict[str, Any] = field(default_factory=dict)
    strategy: RolloutStrategy = RolloutStrategy.PERCENTAGE
    user_whitelist: Set[str] = field(default_factory=set)  # 白名单用户
    user_blacklist: Set[str] = field(default_factory=set)  # 黑名单用户
    
    def __post_init__(self):
        if isinstance(self.target_metrics, dict):
            self.target_metrics = MetricThresholds(**self.target_metrics)
        if isinstance(self.strategy, str):
            self.strategy = RolloutStrategy(self.strategy)
        if isinstance(self.user_whitelist, list):
            self.user_whitelist = set(self.user_whitelist)
        if isinstance(self.user_blacklist, list):
            self.user_blacklist = set(self.user_blacklist)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector_id": self.detector_id,
            "rollout_percentage": self.rollout_percentage,
            "target_metrics": self.target_metrics.to_dict(),
            "auto_promote": self.auto_promote,
            "auto_rollback": self.auto_rollback,
            "rollback_threshold": self.rollback_threshold,
            "observation_minutes": self.observation_minutes,
            "promotion_criteria": self.promotion_criteria,
            "strategy": self.strategy.value,
            "user_whitelist": list(self.user_whitelist),
            "user_blacklist": list(self.user_blacklist)
        }


@dataclass
class DetectorMetrics:
    """检测器性能指标"""
    total_requests: int = 0
    new_detector_requests: int = 0          # 新检测器处理的请求数
    baseline_requests: int = 0              # 基线检测器处理的请求数
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    errors: int = 0
    latencies: List[float] = field(default_factory=list)
    stage_start_time: float = field(default_factory=time.time)
    
    def add_latency(self, latency_ms: float):
        """添加延迟记录"""
        self.latencies.append(latency_ms)
        # 保持列表大小合理
        if len(self.latencies) > 10000:
            self.latencies = self.latencies[-5000:]
    
    @property
    def error_rate(self) -> float:
        """计算错误率"""
        if self.total_requests == 0:
            return 0.0
        return self.errors / self.total_requests
    
    @property
    def false_positive_rate(self) -> float:
        """计算误报率"""
        total_negative = self.true_negatives + self.false_positives
        if total_negative == 0:
            return 0.0
        return self.false_positives / total_negative
    
    @property
    def p99_latency(self) -> float:
        """计算P99延迟"""
        if not self.latencies:
            return 0.0
        sorted_latencies = sorted(self.latencies)
        idx = int(len(sorted_latencies) * 0.99)
        return sorted_latencies[min(idx, len(sorted_latencies) - 1)]
    
    @property
    def p95_latency(self) -> float:
        """计算P95延迟"""
        if not self.latencies:
            return 0.0
        sorted_latencies = sorted(self.latencies)
        idx = int(len(sorted_latencies) * 0.95)
        return sorted_latencies[min(idx, len(sorted_latencies) - 1)]
    
    @property
    def avg_latency(self) -> float:
        """计算平均延迟"""
        if not self.latencies:
            return 0.0
        return sum(self.latencies) / len(self.latencies)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "new_detector_requests": self.new_detector_requests,
            "baseline_requests": self.baseline_requests,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "errors": self.errors,
            "error_rate": self.error_rate,
            "false_positive_rate": self.false_positive_rate,
            "p99_latency": self.p99_latency,
            "p95_latency": self.p95_latency,
            "avg_latency": self.avg_latency,
            "stage_duration_minutes": (time.time() - self.stage_start_time) / 60
        }
    
    def reset(self):
        """重置指标(阶段切换时使用)"""
        self.total_requests = 0
        self.new_detector_requests = 0
        self.baseline_requests = 0
        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0
        self.errors = 0
        self.latencies = []
        self.stage_start_time = time.time()


@dataclass
class CanaryState:
    """Canary发布状态"""
    detector_id: str
    config: CanaryConfig
    current_stage: CanaryStage = CanaryStage.DISABLED
    current_percentage: float = 0.0
    metrics: DetectorMetrics = field(default_factory=DetectorMetrics)
    history: List[Dict[str, Any]] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    promotion_count: int = 0
    rollback_count: int = 0
    
    def record_event(self, event_type: str, details: Dict[str, Any]):
        """记录事件"""
        self.history.append({
            "timestamp": time.time(),
            "event_type": event_type,
            "stage": self.current_stage.value,
            "percentage": self.current_percentage,
            "details": details
        })
        # 保持历史记录大小合理
        if len(self.history) > 1000:
            self.history = self.history[-500:]
        self.updated_at = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector_id": self.detector_id,
            "current_stage": self.current_stage.value,
            "current_percentage": self.current_percentage,
            "config": self.config.to_dict(),
            "metrics": self.metrics.to_dict(),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "promotion_count": self.promotion_count,
            "rollback_count": self.rollback_count,
            "history_count": len(self.history)
        }


class TrafficRouter:
    """流量路由器 - 决定请求使用新检测器还是基线检测器"""
    
    def __init__(self, strategy: RolloutStrategy = RolloutStrategy.PERCENTAGE):
        self.strategy = strategy
    
    def should_use_new_detector(
        self,
        rollout_percentage: float,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        whitelist: Set[str] = None,
        blacklist: Set[str] = None
    ) -> bool:
        """
        决定是否使用新检测器
        
        优先级:
        1. 白名单用户 -> 总是使用新检测器
        2. 黑名单用户 -> 从不使用新检测器
        3. 根据策略分配
        """
        whitelist = whitelist or set()
        blacklist = blacklist or set()
        
        # 白名单优先
        if user_id and user_id in whitelist:
            return True
        
        # 黑名单次之
        if user_id and user_id in blacklist:
            return False
        
        # 根据策略分配
        if self.strategy == RolloutStrategy.PERCENTAGE:
            return self._percentage_rollout(rollout_percentage)
        
        elif self.strategy == RolloutStrategy.USER_ID and user_id:
            return self._hash_based_rollout(user_id, rollout_percentage)
        
        elif self.strategy == RolloutStrategy.SESSION and session_id:
            return self._hash_based_rollout(session_id, rollout_percentage)
        
        elif self.strategy == RolloutStrategy.TIME_SLICE:
            return self._time_slice_rollout(rollout_percentage)
        
        elif self.strategy == RolloutStrategy.COMBINED:
            # 组合策略：优先使用user_id，其次session_id，最后随机
            if user_id:
                return self._hash_based_rollout(user_id, rollout_percentage)
            elif session_id:
                return self._hash_based_rollout(session_id, rollout_percentage)
            else:
                return self._percentage_rollout(rollout_percentage)
        
        # 默认使用百分比策略
        return self._percentage_rollout(rollout_percentage)
    
    def _percentage_rollout(self, percentage: float) -> bool:
        """纯百分比随机分配"""
        import random
        return random.random() * 100 < percentage
    
    def _hash_based_rollout(self, identifier: str, percentage: float) -> bool:
        """基于哈希的一致性分配(确保同一用户总是路由到相同检测器)"""
        hash_value = int(hashlib.md5(identifier.encode()).hexdigest(), 16)
        bucket = hash_value % 100
        return bucket < percentage
    
    def _time_slice_rollout(self, percentage: float) -> bool:
        """基于时间切片的分配(确保流量均匀分布)"""
        current_minute = int(time.time() / 60)
        slice_size = max(1, int(100 / percentage)) if percentage > 0 else 100
        return (current_minute % slice_size) == 0


class CanaryController:
    """
    Canary发布控制器
    
    功能:
    1. 管理检测器的灰度发布流程
    2. 实时监控检测器性能指标
    3. 自动评估晋升/回滚条件
    4. 支持多种流量分配策略
    """
    
    # 阶段晋升路径
    STAGE_PROGRESSION = [
        (CanaryStage.DISABLED, 0.0),
        (CanaryStage.CANARY_5, 5.0),
        (CanaryStage.CANARY_20, 20.0),
        (CanaryStage.CANARY_50, 50.0),
        (CanaryStage.GA, 100.0)
    ]
    
    def __init__(
        self,
        check_interval_seconds: float = 60.0,
        metrics_window_size: int = 1000
    ):
        self._states: Dict[str, CanaryState] = {}
        self._routers: Dict[str, TrafficRouter] = {}
        self._lock = threading.RLock()
        self._check_interval = check_interval_seconds
        self._metrics_window = metrics_window_size
        self._callbacks: Dict[str, List[Callable]] = {
            "on_promote": [],
            "on_rollback": [],
            "on_metric_alert": []
        }
        
        # 启动监控线程
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
    
    def register_detector(
        self,
        detector_id: str,
        config: CanaryConfig
    ) -> CanaryState:
        """注册检测器到Canary发布系统"""
        with self._lock:
            state = CanaryState(
                detector_id=detector_id,
                config=config
            )
            self._states[detector_id] = state
            self._routers[detector_id] = TrafficRouter(config.strategy)
            
            logger.info(f"Detector {detector_id} registered for canary rollout")
            state.record_event("registered", {"config": config.to_dict()})
            return state
    
    def enable_canary(
        self,
        detector_id: str,
        initial_percentage: Optional[float] = None
    ) -> bool:
        """
        启用Canary发布
        
        Args:
            detector_id: 检测器ID
            initial_percentage: 初始流量百分比(默认使用配置中的值)
        
        Returns:
            bool: 是否成功启用
        """
        with self._lock:
            if detector_id not in self._states:
                logger.error(f"Detector {detector_id} not registered")
                return False
            
            state = self._states[detector_id]
            percentage = initial_percentage or state.config.rollout_percentage
            
            # 找到对应阶段
            target_stage = CanaryStage.CANARY_5
            for stage, pct in self.STAGE_PROGRESSION:
                if pct == percentage:
                    target_stage = stage
                    break
            
            state.current_stage = target_stage
            state.current_percentage = percentage
            state.metrics.reset()
            state.record_event("canary_enabled", {"initial_percentage": percentage})
            
            logger.info(
                f"Canary enabled for {detector_id}: "
                f"stage={target_stage.value}, percentage={percentage}%"
            )
            return True
    
    def should_use_new_detector(
        self,
        detector_id: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> bool:
        """
        判断是否使用新检测器处理请求
        
        Returns:
            bool: True表示使用新检测器，False表示使用基线检测器
        """
        with self._lock:
            if detector_id not in self._states:
                return False
            
            state = self._states[detector_id]
            
            # 如果不在Canary阶段，不使用新检测器
            if state.current_stage in (
                CanaryStage.DISABLED,
                CanaryStage.ROLLED_BACK
            ):
                return False
            
            # 如果已GA，总是使用新检测器
            if state.current_stage == CanaryStage.GA:
                return True
            
            # 使用路由器决定
            router = self._routers[detector_id]
            return router.should_use_new_detector(
                state.current_percentage,
                user_id=user_id,
                session_id=session_id,
                whitelist=state.config.user_whitelist,
                blacklist=state.config.user_blacklist
            )
    
    def record_request(
        self,
        detector_id: str,
        used_new_detector: bool,
        latency_ms: float,
        detected: bool,
        ground_truth: Optional[bool] = None,
        error: Optional[str] = None
    ):
        """
        记录请求结果
        
        Args:
            detector_id: 检测器ID
            used_new_detector: 是否使用了新检测器
            latency_ms: 延迟(毫秒)
            detected: 是否检测到威胁
            ground_truth: 真实结果(用于计算误报率)
            error: 错误信息
        """
        with self._lock:
            if detector_id not in self._states:
                return
            
            state = self._states[detector_id]
            metrics = state.metrics
            
            metrics.total_requests += 1
            
            if used_new_detector:
                metrics.new_detector_requests += 1
                metrics.add_latency(latency_ms)
                
                if error:
                    metrics.errors += 1
                
                # 记录混淆矩阵(如果有真实标签)
                if ground_truth is not None:
                    if detected and ground_truth:
                        metrics.true_positives += 1
                    elif detected and not ground_truth:
                        metrics.false_positives += 1
                    elif not detected and not ground_truth:
                        metrics.true_negatives += 1
                    else:  # not detected and ground_truth
                        metrics.false_negatives += 1
            else:
                metrics.baseline_requests += 1
    
    def evaluate_promotion(self, detector_id: str) -> PromotionDecision:
        """
        评估是否满足晋升条件
        
        Returns:
            PromotionDecision: 晋升决策结果
        """
        with self._lock:
            if detector_id not in self._states:
                return PromotionDecision.HOLD
            
            state = self._states[detector_id]
            config = state.config
            metrics = state.metrics
            
            # 检查最小样本数
            if metrics.new_detector_requests < config.target_metrics.min_sample_size:
                logger.debug(
                    f"{detector_id}: Insufficient samples "
                    f"({metrics.new_detector_requests}/{config.target_metrics.min_sample_size})"
                )
                return PromotionDecision.HOLD
            
            # 检查观察时间
            stage_duration = (time.time() - metrics.stage_start_time) / 60
            if stage_duration < config.observation_minutes:
                logger.debug(
                    f"{detector_id}: Observation period not complete "
                    f"({stage_duration:.1f}/{config.observation_minutes} min)"
                )
                return PromotionDecision.HOLD
            
            # 检查是否需要回滚
            if config.auto_rollback:
                if metrics.false_positive_rate > config.rollback_threshold:
                    logger.warning(
                        f"{detector_id}: False positive rate exceeded threshold "
                        f"({metrics.false_positive_rate:.4f} > {config.rollback_threshold})"
                    )
                    return PromotionDecision.ROLLBACK
                
                if metrics.error_rate > config.target_metrics.error_rate * 5:
                    logger.warning(
                        f"{detector_id}: Error rate too high "
                        f"({metrics.error_rate:.4f})"
                    )
                    return PromotionDecision.ROLLBACK
            
            # 检查是否满足晋升条件
            checks_passed = 0
            checks_total = 0
            
            # 误报率检查
            checks_total += 1
            if metrics.false_positive_rate <= config.target_metrics.false_positive_rate:
                checks_passed += 1
            
            # P99延迟检查
            checks_total += 1
            if metrics.p99_latency <= config.target_metrics.latency_p99:
                checks_passed += 1
            
            # P95延迟检查
            checks_total += 1
            if metrics.p95_latency <= config.target_metrics.latency_p95:
                checks_passed += 1
            
            # 错误率检查
            checks_total += 1
            if metrics.error_rate <= config.target_metrics.error_rate:
                checks_passed += 1
            
            # 如果通过所有检查，可以晋升
            if checks_passed == checks_total:
                logger.info(
                    f"{detector_id}: All checks passed, ready for promotion "
                    f"(FPR={metrics.false_positive_rate:.4f}, "
                    f"P99={metrics.p99_latency:.2f}ms)"
                )
                return PromotionDecision.PROMOTE
            
            logger.debug(
                f"{detector_id}: Checks passed {checks_passed}/{checks_total}"
            )
            return PromotionDecision.HOLD
    
    def promote(self, detector_id: str) -> bool:
        """
        晋升到下一阶段
        
        Returns:
            bool: 是否成功晋升
        """
        with self._lock:
            if detector_id not in self._states:
                return False
            
            state = self._states[detector_id]
            current_stage = state.current_stage
            
            # 找到下一阶段
            next_stage = None
            next_percentage = 0.0
            for i, (stage, pct) in enumerate(self.STAGE_PROGRESSION):
                if stage == current_stage and i + 1 < len(self.STAGE_PROGRESSION):
                    next_stage, next_percentage = self.STAGE_PROGRESSION[i + 1]
                    break
            
            if next_stage is None:
                logger.info(f"{detector_id}: Already at final stage ({current_stage.value})")
                return False
            
            # 执行晋升
            old_stage = state.current_stage
            state.current_stage = next_stage
            state.current_percentage = next_percentage
            state.promotion_count += 1
            
            # 重置阶段指标
            old_metrics = state.metrics.to_dict()
            state.metrics.reset()
            
            state.record_event("promoted", {
                "from_stage": old_stage.value,
                "to_stage": next_stage.value,
                "from_percentage": old_metrics.get("current_percentage", 0),
                "to_percentage": next_percentage,
                "previous_metrics": old_metrics
            })
            
            # 触发回调
            self._trigger_callbacks("on_promote", {
                "detector_id": detector_id,
                "from_stage": old_stage.value,
                "to_stage": next_stage.value,
                "percentage": next_percentage
            })
            
            logger.info(
                f"{detector_id}: Promoted from {old_stage.value} to {next_stage.value} "
                f"({next_percentage}%)"
            )
            return True
    
    def rollback(self, detector_id: str, reason: str = "manual") -> bool:
        """
        回滚检测器
        
        Args:
            detector_id: 检测器ID
            reason: 回滚原因
        
        Returns:
            bool: 是否成功回滚
        """
        with self._lock:
            if detector_id not in self._states:
                return False
            
            state = self._states[detector_id]
            old_stage = state.current_stage
            
            # 执行回滚
            state.current_stage = CanaryStage.ROLLED_BACK
            state.current_percentage = 0.0
            state.rollback_count += 1
            
            state.record_event("rollback", {
                "from_stage": old_stage.value,
                "reason": reason,
                "final_metrics": state.metrics.to_dict()
            })
            
            # 触发回调
            self._trigger_callbacks("on_rollback", {
                "detector_id": detector_id,
                "from_stage": old_stage.value,
                "reason": reason
            })
            
            logger.warning(
                f"{detector_id}: Rolled back from {old_stage.value}. Reason: {reason}"
            )
            return True
    
    def update_rollout_percentage(self, detector_id: str, percentage: float) -> bool:
        """
        手动更新流量百分比
        
        Args:
            detector_id: 检测器ID
            percentage: 新的流量百分比 (0-100)
        
        Returns:
            bool: 是否成功更新
        """
        with self._lock:
            if detector_id not in self._states:
                return False
            
            state = self._states[detector_id]
            old_percentage = state.current_percentage
            state.current_percentage = max(0.0, min(100.0, percentage))
            
            # 更新阶段
            if percentage >= 100:
                state.current_stage = CanaryStage.GA
            elif percentage >= 50:
                state.current_stage = CanaryStage.CANARY_50
            elif percentage >= 20:
                state.current_stage = CanaryStage.CANARY_20
            elif percentage > 0:
                state.current_stage = CanaryStage.CANARY_5
            else:
                state.current_stage = CanaryStage.DISABLED
            
            state.record_event("percentage_updated", {
                "from": old_percentage,
                "to": state.current_percentage,
                "stage": state.current_stage.value
            })
            
            logger.info(
                f"{detector_id}: Rollout percentage updated from "
                f"{old_percentage}% to {state.current_percentage}%"
            )
            return True
    
    def get_state(self, detector_id: str) -> Optional[CanaryState]:
        """获取检测器状态"""
        with self._lock:
            return self._states.get(detector_id)
    
    def get_all_states(self) -> Dict[str, CanaryState]:
        """获取所有检测器状态"""
        with self._lock:
            return self._states.copy()
    
    def register_callback(self, event: str, callback: Callable):
        """注册事件回调"""
        if event in self._callbacks:
            self._callbacks[event].append(callback)
    
    def _trigger_callbacks(self, event: str, data: Dict[str, Any]):
        """触发事件回调"""
        for callback in self._callbacks.get(event, []):
            try:
                callback(data)
            except Exception as e:
                logger.error(f"Callback error: {e}")
    
    def start_monitoring(self):
        """启动自动监控线程"""
        if self._monitoring:
            return
        
        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.info("Canary monitoring started")
    
    def stop_monitoring(self):
        """停止自动监控线程"""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)
        logger.info("Canary monitoring stopped")
    
    def _monitor_loop(self):
        """监控循环"""
        while self._monitoring:
            try:
                self._check_all_detectors()
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
            
            # 等待下一个检查周期
            time.sleep(self._check_interval)
    
    def _check_all_detectors(self):
        """检查所有检测器状态"""
        with self._lock:
            states = list(self._states.items())
        
        for detector_id, state in states:
            # 只检查启用了auto_promote的检测器
            if not state.config.auto_promote:
                continue
            
            # 跳过已结束的阶段
            if state.current_stage in (
                CanaryStage.DISABLED,
                CanaryStage.GA,
                CanaryStage.ROLLED_BACK
            ):
                continue
            
            # 评估晋升条件
            decision = self.evaluate_promotion(detector_id)
            
            if decision == PromotionDecision.PROMOTE:
                self.promote(detector_id)
            elif decision == PromotionDecision.ROLLBACK and state.config.auto_rollback:
                self.rollback(detector_id, reason="auto_rollback_threshold_exceeded")


# 单例模式 - 全局Canary控制器
_canary_controller: Optional[CanaryController] = None


def get_canary_controller() -> CanaryController:
    """获取全局Canary控制器实例"""
    global _canary_controller
    if _canary_controller is None:
        _canary_controller = CanaryController()
    return _canary_controller


def reset_canary_controller():
    """重置全局Canary控制器(主要用于测试)"""
    global _canary_controller
    if _canary_controller:
        _canary_controller.stop_monitoring()
    _canary_controller = None