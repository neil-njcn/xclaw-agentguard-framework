"""
统一配置系统 - ConfigSchema
声明式配置系统，每个检测器定义自己的配置模式
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Type, Union, get_origin, get_args
import json


@dataclass
class ConfigSchema:
    """配置模式定义
    
    声明式定义检测器需要的配置项，包括类型、默认值、验证规则等
    
    Attributes:
        name: 配置项名称
        type: 配置项类型 (str, int, float, bool, List, Dict等)
        description: 配置项说明文档
        default: 默认值
        valid_range: 数值范围 (用于int/float类型)
        valid_values: 枚举值列表 (用于限制可选值)
        required: 是否必需 (默认为False，即使用默认值)
    """
    name: str
    type: Type
    description: str
    default: Any
    valid_range: Optional[Tuple[Any, Any]] = None
    valid_values: Optional[List[Any]] = None
    required: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "name": self.name,
            "type": self._get_type_name(self.type),
            "description": self.description,
            "default": self.default,
            "valid_range": self.valid_range,
            "valid_values": self.valid_values,
            "required": self.required
        }
    
    @staticmethod
    def _get_type_name(t: Type) -> str:
        """获取类型的友好名称"""
        origin = get_origin(t)
        if origin is not None:
            args = get_args(t)
            if args:
                args_str = ", ".join(ConfigSchema._get_type_name(arg) for arg in args)
                return f"{origin.__name__}[{args_str}]"
            return origin.__name__
        return t.__name__ if hasattr(t, '__name__') else str(t)


@dataclass
class DetectorConfig:
    """检测器完整配置定义
    
    定义检测器的所有配置项及其元数据
    
    Attributes:
        detector_id: 检测器唯一标识
        version: 配置版本号
        schema: 配置模式列表
    """
    detector_id: str
    version: str
    schema: List[ConfigSchema]
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "detector_id": self.detector_id,
            "version": self.version,
            "schema": [s.to_dict() for s in self.schema]
        }
    
    def to_json(self, indent: int = 2) -> str:
        """转换为JSON字符串"""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
    
    def get_config_names(self) -> List[str]:
        """获取所有配置项名称"""
        return [s.name for s in self.schema]
    
    def get_config(self, name: str) -> Optional[ConfigSchema]:
        """根据名称获取配置模式"""
        for s in self.schema:
            if s.name == name:
                return s
        return None


class ConfigValidator:
    """配置验证器
    
    验证用户提供的配置是否符合检测器定义的schema
    支持类型检查、范围检查、枚举值检查等
    """
    
    @staticmethod
    def validate(config: Dict[str, Any], schema: DetectorConfig) -> Tuple[bool, List[str]]:
        """验证配置是否符合模式
        
        Args:
            config: 用户提供的配置字典
            schema: 检测器配置定义
            
        Returns:
            (是否验证通过, 错误信息列表)
        """
        errors = []
        
        for field_schema in schema.schema:
            value = config.get(field_schema.name, field_schema.default)
            
            # 检查必需字段
            if field_schema.required and field_schema.name not in config:
                errors.append(f"{field_schema.name}: required field is missing")
                continue
            
            # 类型检查
            if not ConfigValidator._check_type(value, field_schema.type):
                type_name = ConfigSchema._get_type_name(field_schema.type)
                actual_type = type(value).__name__
                errors.append(f"{field_schema.name}: expected type '{type_name}', got '{actual_type}'")
                continue
            
            # 范围检查 (仅适用于数值类型)
            if field_schema.valid_range is not None and isinstance(value, (int, float)):
                min_val, max_val = field_schema.valid_range
                if not (min_val <= value <= max_val):
                    errors.append(
                        f"{field_schema.name}: value {value} out of range [{min_val}, {max_val}]"
                    )
            
            # 枚举值检查
            if field_schema.valid_values is not None:
                # 对于列表类型，检查每个元素
                origin = get_origin(field_schema.type)
                if origin is list or (isinstance(field_schema.type, type) and issubclass(field_schema.type, list)):
                    if isinstance(value, list):
                        invalid_items = [v for v in value if v not in field_schema.valid_values]
                        if invalid_items:
                            errors.append(
                                f"{field_schema.name}: invalid values {invalid_items}, "
                                f"must be one of {field_schema.valid_values}"
                            )
                else:
                    if value not in field_schema.valid_values:
                        errors.append(
                            f"{field_schema.name}: value '{value}' not in allowed values "
                            f"{field_schema.valid_values}"
                        )
        
        return len(errors) == 0, errors
    
    @staticmethod
    def _check_type(value: Any, expected_type: Type) -> bool:
        """检查值是否符合预期类型
        
        支持基本类型和泛型类型(List, Dict等)的检查
        """
        # 处理None值
        if value is None:
            return not isinstance(expected_type, type) or expected_type is type(None)
        
        # 获取泛型原始类型
        origin = get_origin(expected_type)
        
        if origin is not None:
            # 处理泛型类型
            args = get_args(expected_type)
            
            # 检查基本容器类型
            if origin is list:
                if not isinstance(value, list):
                    return False
                # 检查列表元素类型
                if args:
                    elem_type = args[0]
                    return all(ConfigValidator._check_type(item, elem_type) for item in value)
                return True
            
            if origin is dict:
                if not isinstance(value, dict):
                    return False
                if args and len(args) >= 2:
                    key_type, val_type = args[0], args[1]
                    return all(
                        ConfigValidator._check_type(k, key_type) and 
                        ConfigValidator._check_type(v, val_type)
                        for k, v in value.items()
                    )
                return True
            
            # Union类型 (如 Optional[int] = Union[int, None])
            if origin is Union:
                return any(ConfigValidator._check_type(value, arg) for arg in args)
            
            # 其他泛型类型使用isinstance检查
            try:
                return isinstance(value, origin)
            except TypeError:
                return True  # 某些泛型类型无法直接检查
        
        # 基本类型检查
        try:
            # Python中bool是int的子类，但通常我们不希望bool被接受为int
            # 同时允许int被接受为float（因为int是float的子类型概念）
            if expected_type is float and isinstance(value, int) and not isinstance(value, bool):
                return True
            return isinstance(value, expected_type)
        except TypeError:
            # 处理某些特殊类型
            return True
    
    @staticmethod
    def apply_defaults(config: Dict[str, Any], schema: DetectorConfig) -> Dict[str, Any]:
        """应用默认值到配置
        
        返回新的配置字典，未提供的配置项使用默认值
        """
        result = {}
        for field_schema in schema.schema:
            result[field_schema.name] = config.get(field_schema.name, field_schema.default)
        return result
    
    @staticmethod
    def validate_and_apply(config: Dict[str, Any], schema: DetectorConfig) -> Dict[str, Any]:
        """验证配置并应用默认值
        
        Args:
            config: 用户配置
            schema: 配置模式
            
        Returns:
            应用默认值后的完整配置
            
        Raises:
            ValueError: 验证失败时抛出，包含错误信息
        """
        is_valid, errors = ConfigValidator.validate(config, schema)
        if not is_valid:
            raise ValueError(f"Config validation failed: {'; '.join(errors)}")
        return ConfigValidator.apply_defaults(config, schema)


class ConfigDocumentationGenerator:
    """配置文档生成器
    
    根据配置模式自动生成文档
    """
    
    @staticmethod
    def generate_markdown(schema: DetectorConfig) -> str:
        """生成Markdown格式的配置文档"""
        lines = [
            f"# {schema.detector_id} 配置文档",
            "",
            f"- **版本**: {schema.version}",
            f"- **配置项数量**: {len(schema.schema)}",
            "",
            "## 配置项列表",
            "",
        ]
        
        for field in schema.schema:
            lines.extend(ConfigDocumentationGenerator._generate_field_doc(field))
        
        return "\n".join(lines)
    
    @staticmethod
    def _generate_field_doc(field: ConfigSchema) -> List[str]:
        """生成单个配置项的文档"""
        lines = [
            f"### `{field.name}`",
            "",
            f"**描述**: {field.description}",
            "",
            f"**类型**: `{ConfigSchema._get_type_name(field.type)}`",
            "",
            f"**默认值**: `{repr(field.default)}`",
            "",
        ]
        
        if field.required:
            lines.append("**必需**: ✅ 是")
            lines.append("")
        
        if field.valid_range is not None:
            lines.append(f"**有效范围**: [{field.valid_range[0]}, {field.valid_range[1]}]")
            lines.append("")
        
        if field.valid_values is not None:
            values_str = ", ".join(f"`{v}`" for v in field.valid_values)
            lines.append(f"**允许值**: {values_str}")
            lines.append("")
        
        return lines
    
    @staticmethod
    def generate_example_config(schema: DetectorConfig) -> str:
        """生成示例配置"""
        example = {}
        for field in schema.schema:
            example[field.name] = field.default
        return json.dumps(example, indent=2, ensure_ascii=False)


# 预定义的通用配置模式
class CommonConfigs:
    """通用配置项模板"""
    
    @staticmethod
    def threshold(default: float = 0.5, valid_range: Tuple[float, float] = (0.0, 1.0)) -> ConfigSchema:
        """检测阈值配置"""
        return ConfigSchema(
            name="threshold",
            type=float,
            description="检测阈值，决定敏感内容的判定严格程度",
            default=default,
            valid_range=valid_range
        )
    
    @staticmethod
    def enabled(default: bool = True) -> ConfigSchema:
        """是否启用检测器"""
        return ConfigSchema(
            name="enabled",
            type=bool,
            description="是否启用该检测器",
            default=default
        )
    
    @staticmethod
    def log_level(default: str = "INFO") -> ConfigSchema:
        """日志级别配置"""
        return ConfigSchema(
            name="log_level",
            type=str,
            description="日志输出级别",
            default=default,
            valid_values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        )
    
    @staticmethod
    def max_length(default: int = 10000, valid_range: Tuple[int, int] = (1, 100000)) -> ConfigSchema:
        """最大输入长度配置"""
        return ConfigSchema(
            name="max_length",
            type=int,
            description="最大输入长度限制",
            default=default,
            valid_range=valid_range
        )
    
    @staticmethod
    def timeout(default: float = 30.0, valid_range: Tuple[float, float] = (0.1, 300.0)) -> ConfigSchema:
        """超时时间配置（秒）"""
        return ConfigSchema(
            name="timeout",
            type=float,
            description="检测超时时间（秒）",
            default=default,
            valid_range=valid_range
        )


# 便捷函数
def create_config(
    name: str,
    type: Type,
    description: str,
    default: Any,
    **kwargs
) -> ConfigSchema:
    """快速创建配置模式"""
    return ConfigSchema(
        name=name,
        type=type,
        description=description,
        default=default,
        **kwargs
    )


def create_detector_config(
    detector_id: str,
    version: str,
    *schemas: ConfigSchema
) -> DetectorConfig:
    """快速创建检测器配置"""
    return DetectorConfig(
        detector_id=detector_id,
        version=version,
        schema=list(schemas)
    )
