"""
XClaw AgentGuard Plugin Version Management - 插件版本管理系统

提供优雅的插件版本控制和兼容性管理。
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple
from packaging import version as pkg_version
from packaging.specifiers import SpecifierSet
import re


@dataclass(frozen=True)
class PluginVersion:
    """
    插件版本号 (遵循 SemVer 规范)
    
    格式: MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
    示例: 1.2.3, 2.0.0-alpha, 1.0.0+build.123
    """
    major: int
    minor: int = 0
    patch: int = 0
    prerelease: Optional[str] = None
    build: Optional[str] = None
    
    def __str__(self) -> str:
        v = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            v += f"-{self.prerelease}"
        if self.build:
            v += f"+{self.build}"
        return v
    
    def __lt__(self, other: 'PluginVersion') -> bool:
        return self._to_tuple() < other._to_tuple()
    
    def __le__(self, other: 'PluginVersion') -> bool:
        return self._to_tuple() <= other._to_tuple()
    
    def __gt__(self, other: 'PluginVersion') -> bool:
        return self._to_tuple() > other._to_tuple()
    
    def __ge__(self, other: 'PluginVersion') -> bool:
        return self._to_tuple() >= other._to_tuple()
    
    def _to_tuple(self) -> Tuple:
        """转换为可比较的元组"""
        return (self.major, self.minor, self.patch, self.prerelease or "", self.build or "")
    
    @classmethod
    def parse(cls, version_str: str) -> 'PluginVersion':
        """从字符串解析版本号"""
        # 匹配 SemVer 格式
        pattern = r'^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([a-zA-Z0-9.]+))?(?:\+([a-zA-Z0-9.]+))?$'
        match = re.match(pattern, version_str)
        if not match:
            raise ValueError(f"Invalid version format: {version_str}")
        
        major = int(match.group(1))
        minor = int(match.group(2)) if match.group(2) else 0
        patch = int(match.group(3)) if match.group(3) else 0
        prerelease = match.group(4)
        build = match.group(5)
        
        return cls(major, minor, patch, prerelease, build)
    
    def is_compatible_with(self, other: 'PluginVersion') -> bool:
        """
        检查版本兼容性 (相同 MAJOR 版本)
        遵循 SemVer: MAJOR 版本不兼容，MINOR/PATCH 兼容
        """
        return self.major == other.major
    
    def bump_major(self) -> 'PluginVersion':
        """主版本号+1"""
        return PluginVersion(self.major + 1, 0, 0)
    
    def bump_minor(self) -> 'PluginVersion':
        """次版本号+1"""
        return PluginVersion(self.major, self.minor + 1, 0)
    
    def bump_patch(self) -> 'PluginVersion':
        """补丁版本号+1"""
        return PluginVersion(self.major, self.minor, self.patch + 1)


@dataclass
class VersionConstraint:
    """
    版本约束条件
    
    支持语义化版本约束:
    - >=1.0.0 (最低版本)
    - ^1.2.0 (兼容1.x.x, 即>=1.2.0,<2.0.0)
    - ~1.2.0 (兼容1.2.x, 即>=1.2.0,<1.3.0)
    - 1.2.0 (精确匹配)
    """
    specifier: str
    
    def __post_init__(self):
        """转换为 packaging 的 SpecifierSet"""
        self._specifier = SpecifierSet(self._normalize())
    
    def _normalize(self) -> str:
        """规范化约束格式"""
        spec = self.specifier.strip()
        
        # ^1.2.0 -> >=1.2.0,<2.0.0
        if spec.startswith('^'):
            v = PluginVersion.parse(spec[1:])
            return f">={v},<{v.major+1}.0.0"
        
        # ~1.2.0 -> >=1.2.0,<1.3.0
        if spec.startswith('~'):
            v = PluginVersion.parse(spec[1:])
            return f">={v},<{v.major}.{v.minor+1}.0"
        
        # 纯版本号 -> 精确匹配
        if not any(op in spec for op in ['>=', '<=', '>', '<', '==', '!=', '~=', '*']):
            return f"=={spec}"
        
        return spec
    
    def matches(self, version: PluginVersion) -> bool:
        """检查版本是否符合约束"""
        return pkg_version.parse(str(version)) in self._specifier
    
    def __str__(self) -> str:
        return self.specifier


@dataclass
class PluginManifest:
    """
    插件清单 - 包含完整的版本和依赖信息
    
    示例:
        manifest = PluginManifest(
            id="my_plugin",
            name="My Plugin",
            version=PluginVersion(1, 2, 0),
            author="Plugin Author",
            description="A sample plugin",
            requires_core="^2.3.0",  # 需要 XClaw AgentGuard 核心 2.3.0+
            dependencies={
                "other_plugin": ">=1.0.0,<2.0.0",
            }
        )
    """
    id: str
    name: str
    version: PluginVersion
    author: str
    description: str = ""
    
    # 核心版本要求
    requires_core: str = "^2.0.0"  # 默认兼容 XClaw AgentGuard 2.x
    
    # 插件依赖: {plugin_id: version_constraint}
    dependencies: Dict[str, str] = field(default_factory=dict)
    
    # 可选依赖
    optional_dependencies: Dict[str, str] = field(default_factory=dict)
    
    # 冲突插件
    conflicts: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """转换为字典格式 (用于序列化)"""
        return {
            "id": self.id,
            "name": self.name,
            "version": str(self.version),
            "author": self.author,
            "description": self.description,
            "requires_core": self.requires_core,
            "dependencies": self.dependencies,
            "optional_dependencies": self.optional_dependencies,
            "conflicts": self.conflicts,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'PluginManifest':
        """从字典创建"""
        return cls(
            id=data["id"],
            name=data["name"],
            version=PluginVersion.parse(data["version"]),
            author=data["author"],
            description=data.get("description", ""),
            requires_core=data.get("requires_core", "^2.0.0"),
            dependencies=data.get("dependencies", {}),
            optional_dependencies=data.get("optional_dependencies", {}),
            conflicts=data.get("conflicts", []),
        )


class VersionManager:
    """
    插件版本管理器
    
    管理插件版本、依赖解析和兼容性检查。
    """
    
    def __init__(self, core_version: str = "2.3.0"):
        self.core_version = PluginVersion.parse(core_version)
        self._installed_plugins: Dict[str, PluginVersion] = {}
    
    def check_compatibility(
        self, 
        manifest: PluginManifest
    ) -> Tuple[bool, List[str]]:
        """
        检查插件兼容性
        
        返回: (是否兼容, 不兼容原因列表)
        """
        issues = []
        
        # 1. 检查核心版本兼容性
        core_constraint = VersionConstraint(manifest.requires_core)
        if not core_constraint.matches(self.core_version):
            issues.append(
                f"Core version mismatch: plugin requires {manifest.requires_core}, "
                f"but core is {self.core_version}"
            )
        
        # 2. 检查依赖是否存在
        for dep_id, dep_constraint in manifest.dependencies.items():
            if dep_id not in self._installed_plugins:
                issues.append(f"Missing dependency: {dep_id} {dep_constraint}")
            else:
                installed_version = self._installed_plugins[dep_id]
                constraint = VersionConstraint(dep_constraint)
                if not constraint.matches(installed_version):
                    issues.append(
                        f"Dependency version mismatch: {dep_id} {dep_constraint} required, "
                        f"but {installed_version} installed"
                    )
        
        # 3. 检查冲突
        for conflict_id in manifest.conflicts:
            if conflict_id in self._installed_plugins:
                issues.append(f"Conflict with: {conflict_id}")
        
        return len(issues) == 0, issues
    
    def register_plugin(self, manifest: PluginManifest) -> bool:
        """注册插件 (检查兼容性后)"""
        compatible, issues = self.check_compatibility(manifest)
        if not compatible:
            raise RuntimeError(f"Plugin {manifest.id} incompatible: {', '.join(issues)}")
        
        self._installed_plugins[manifest.id] = manifest.version
        return True
    
    def get_installed_version(self, plugin_id: str) -> Optional[PluginVersion]:
        """获取已安装插件的版本"""
        return self._installed_plugins.get(plugin_id)
    
    def can_upgrade(
        self, 
        plugin_id: str, 
        new_version: PluginVersion
    ) -> Tuple[bool, str]:
        """
        检查是否可以升级
        
        返回: (是否可以, 原因)
        """
        current = self._installed_plugins.get(plugin_id)
        if not current:
            return False, "Plugin not installed"
        
        if new_version <= current:
            return False, f"New version {new_version} is not newer than current {current}"
        
        # 检查 MAJOR 版本变化 (可能有破坏性变更)
        if new_version.major > current.major:
            return True, f"MAJOR version upgrade: {current} -> {new_version} (check for breaking changes)"
        
        return True, f"Compatible upgrade: {current} -> {new_version}"


# 便捷函数
def parse_version(version_str: str) -> PluginVersion:
    """解析版本字符串"""
    return PluginVersion.parse(version_str)


def check_version_constraint(version: str, constraint: str) -> bool:
    """检查版本是否符合约束"""
    v = PluginVersion.parse(version)
    c = VersionConstraint(constraint)
    return c.matches(v)


# 使用示例
if __name__ == "__main__":
    # 创建版本
    v1 = PluginVersion(1, 2, 3)
    v2 = PluginVersion.parse("1.2.4")
    
    print(f"v1: {v1}")
    print(f"v2 > v1: {v2 > v1}")
    
    # 版本约束
    constraint = VersionConstraint("^1.0.0")
    print(f"1.2.3 matches ^1.0.0: {constraint.matches(v1)}")
    
    # 插件清单
    manifest = PluginManifest(
        id="my_plugin",
        name="My Plugin",
        version=PluginVersion(1, 0, 0),
        author="Plugin Author",
        description="A sample plugin",
        requires_core="^2.3.0",
        dependencies={"other_plugin": ">=1.0.0"},
    )
    
    print(f"\nManifest: {manifest.to_dict()}")
    
    # 版本管理器
    manager = VersionManager(core_version="2.3.0")
    compatible, issues = manager.check_compatibility(manifest)
    print(f"\nCompatible: {compatible}")
    if issues:
        print(f"Issues: {issues}")
