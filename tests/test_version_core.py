"""
Comprehensive tests for xclaw_agentguard version core functionality.

Tests cover:
- PluginVersion class (parsing, comparison, validation)
- VersionConstraint class (parsing, matching)
- parse_version function
- check_version_constraint function
- Edge cases: invalid versions, pre-release, build metadata
"""

import pytest
from xclaw_agentguard.core.version_management import (
    PluginVersion,
    VersionConstraint,
    PluginManifest,
    VersionManager,
    parse_version,
    check_version_constraint,
)


class TestPluginVersion:
    """Test PluginVersion class - parsing, comparison, validation"""

    def test_basic_version_creation(self):
        """Test creating version with basic components"""
        v = PluginVersion(1, 2, 3)
        assert v.major == 1
        assert v.minor == 2
        assert v.patch == 3
        assert v.prerelease is None
        assert v.build is None

    def test_version_defaults(self):
        """Test version defaults to 0 for minor and patch"""
        v = PluginVersion(1)
        assert v.major == 1
        assert v.minor == 0
        assert v.patch == 0

    def test_version_with_prerelease(self):
        """Test version with pre-release identifier"""
        v = PluginVersion(1, 2, 3, prerelease="alpha")
        assert v.prerelease == "alpha"
        assert str(v) == "1.2.3-alpha"

    def test_version_with_build(self):
        """Test version with build metadata"""
        v = PluginVersion(1, 2, 3, build="build.123")
        assert v.build == "build.123"
        assert str(v) == "1.2.3+build.123"

    def test_version_with_prerelease_and_build(self):
        """Test version with both pre-release and build metadata"""
        v = PluginVersion(1, 2, 3, prerelease="beta", build="exp.sha.5114f85")
        assert str(v) == "1.2.3-beta+exp.sha.5114f85"

    def test_version_string_representation(self):
        """Test string conversion of versions"""
        assert str(PluginVersion(1, 2, 3)) == "1.2.3"
        assert str(PluginVersion(0, 0, 1)) == "0.0.1"
        assert str(PluginVersion(10, 20, 30)) == "10.20.30"

    def test_parse_simple_version(self):
        """Test parsing simple version strings"""
        v = PluginVersion.parse("1.2.3")
        assert v.major == 1
        assert v.minor == 2
        assert v.patch == 3

    def test_parse_partial_version(self):
        """Test parsing partial version strings"""
        v = PluginVersion.parse("1")
        assert v.major == 1
        assert v.minor == 0
        assert v.patch == 0

        v = PluginVersion.parse("1.2")
        assert v.major == 1
        assert v.minor == 2
        assert v.patch == 0

    def test_parse_with_prerelease(self):
        """Test parsing versions with pre-release"""
        v = PluginVersion.parse("1.0.0-alpha")
        assert v.prerelease == "alpha"

        v = PluginVersion.parse("1.0.0-alpha.1")
        assert v.prerelease == "alpha.1"

        v = PluginVersion.parse("1.0.0-0.3.7")
        assert v.prerelease == "0.3.7"

        v = PluginVersion.parse("1.0.0-x.7.z.92")
        assert v.prerelease == "x.7.z.92"

    def test_parse_with_build_metadata(self):
        """Test parsing versions with build metadata"""
        v = PluginVersion.parse("1.0.0+build.1")
        assert v.build == "build.1"

        v = PluginVersion.parse("1.0.0+20130313144700")
        assert v.build == "20130313144700"

        v = PluginVersion.parse("1.0.0+exp.sha.5114f85")
        assert v.build == "exp.sha.5114f85"

    def test_parse_with_prerelease_and_build(self):
        """Test parsing versions with both pre-release and build"""
        v = PluginVersion.parse("1.0.0-alpha+001")
        assert v.prerelease == "alpha"
        assert v.build == "001"

        v = PluginVersion.parse("1.0.0-beta.11+exp.sha.5114f85")
        assert v.prerelease == "beta.11"
        assert v.build == "exp.sha.5114f85"

    def test_parse_invalid_versions(self):
        """Test parsing invalid version strings raises ValueError"""
        invalid_versions = [
            "",
            "abc",
            "1.2.3.4",
            "1.2.a",
            "v1.2.3",  # 'v' prefix not supported
            "1.2.3-",
            "1.2.3+",
        ]
        for invalid in invalid_versions:
            with pytest.raises(ValueError, match=f"Invalid version format: {invalid}"):
                PluginVersion.parse(invalid)

    def test_version_equality(self):
        """Test version equality comparison"""
        v1 = PluginVersion(1, 2, 3)
        v2 = PluginVersion(1, 2, 3)
        assert v1 == v2

    def test_version_inequality(self):
        """Test version inequality"""
        v1 = PluginVersion(1, 2, 3)
        v2 = PluginVersion(1, 2, 4)
        assert v1 != v2

    def test_version_less_than(self):
        """Test less than comparison"""
        assert PluginVersion(1, 0, 0) < PluginVersion(2, 0, 0)
        assert PluginVersion(1, 1, 0) < PluginVersion(1, 2, 0)
        assert PluginVersion(1, 1, 1) < PluginVersion(1, 1, 2)

    def test_version_less_than_equal(self):
        """Test less than or equal comparison"""
        assert PluginVersion(1, 0, 0) <= PluginVersion(1, 0, 0)
        assert PluginVersion(1, 0, 0) <= PluginVersion(2, 0, 0)

    def test_version_greater_than(self):
        """Test greater than comparison"""
        assert PluginVersion(2, 0, 0) > PluginVersion(1, 0, 0)
        assert PluginVersion(1, 2, 0) > PluginVersion(1, 1, 0)
        assert PluginVersion(1, 1, 2) > PluginVersion(1, 1, 1)

    def test_version_greater_than_equal(self):
        """Test greater than or equal comparison"""
        assert PluginVersion(1, 0, 0) >= PluginVersion(1, 0, 0)
        assert PluginVersion(2, 0, 0) >= PluginVersion(1, 0, 0)

    def test_version_comparison_with_prerelease(self):
        """Test version comparison with pre-release"""
        # Pre-release versions are compared by string
        v1 = PluginVersion(1, 0, 0, prerelease="alpha")
        v2 = PluginVersion(1, 0, 0, prerelease="beta")
        assert v1 < v2

    def test_version_comparison_with_build(self):
        """Test version comparison with build metadata"""
        # Build metadata is compared by string
        v1 = PluginVersion(1, 0, 0, build="001")
        v2 = PluginVersion(1, 0, 0, build="002")
        assert v1 < v2

    def test_is_compatible_with(self):
        """Test version compatibility check"""
        v1 = PluginVersion(1, 2, 3)
        v2 = PluginVersion(1, 5, 0)
        v3 = PluginVersion(2, 0, 0)

        assert v1.is_compatible_with(v2) is True
        assert v1.is_compatible_with(v3) is False

    def test_bump_major(self):
        """Test bumping major version"""
        v = PluginVersion(1, 2, 3)
        new_v = v.bump_major()
        assert new_v.major == 2
        assert new_v.minor == 0
        assert new_v.patch == 0

    def test_bump_minor(self):
        """Test bumping minor version"""
        v = PluginVersion(1, 2, 3)
        new_v = v.bump_minor()
        assert new_v.major == 1
        assert new_v.minor == 3
        assert new_v.patch == 0

    def test_bump_patch(self):
        """Test bumping patch version"""
        v = PluginVersion(1, 2, 3)
        new_v = v.bump_patch()
        assert new_v.major == 1
        assert new_v.minor == 2
        assert new_v.patch == 4

    def test_version_is_frozen(self):
        """Test that PluginVersion is immutable (frozen dataclass)"""
        v = PluginVersion(1, 2, 3)
        with pytest.raises(AttributeError):
            v.major = 2


class TestVersionConstraint:
    """Test VersionConstraint class - parsing, matching"""

    def test_exact_version_constraint(self):
        """Test exact version matching"""
        c = VersionConstraint("1.2.3")
        assert c.matches(PluginVersion(1, 2, 3)) is True
        assert c.matches(PluginVersion(1, 2, 4)) is False

    def test_greater_than_equal_constraint(self):
        """Test >= constraint"""
        c = VersionConstraint(">=1.2.0")
        assert c.matches(PluginVersion(1, 2, 0)) is True
        assert c.matches(PluginVersion(1, 3, 0)) is True
        assert c.matches(PluginVersion(1, 1, 9)) is False

    def test_less_than_equal_constraint(self):
        """Test <= constraint"""
        c = VersionConstraint("<=1.2.0")
        assert c.matches(PluginVersion(1, 2, 0)) is True
        assert c.matches(PluginVersion(1, 1, 0)) is True
        assert c.matches(PluginVersion(1, 3, 0)) is False

    def test_greater_than_constraint(self):
        """Test > constraint"""
        c = VersionConstraint(">1.2.0")
        assert c.matches(PluginVersion(1, 2, 1)) is True
        assert c.matches(PluginVersion(1, 3, 0)) is True
        assert c.matches(PluginVersion(1, 2, 0)) is False

    def test_less_than_constraint(self):
        """Test < constraint"""
        c = VersionConstraint("<1.2.0")
        assert c.matches(PluginVersion(1, 1, 9)) is True
        assert c.matches(PluginVersion(1, 1, 0)) is True
        assert c.matches(PluginVersion(1, 2, 0)) is False

    def test_caret_constraint(self):
        """Test ^ constraint (compatible with major version)"""
        c = VersionConstraint("^1.2.0")
        assert c.matches(PluginVersion(1, 2, 0)) is True
        assert c.matches(PluginVersion(1, 3, 0)) is True
        assert c.matches(PluginVersion(1, 9, 9)) is True
        assert c.matches(PluginVersion(2, 0, 0)) is False
        assert c.matches(PluginVersion(0, 9, 0)) is False

    def test_caret_constraint_zero_major(self):
        """Test ^ constraint with 0.x.x versions"""
        # ^0.2.0 normalizes to >=0.2.0,<1.0.0 (allows minor updates in 0.x)
        c = VersionConstraint("^0.2.0")
        assert c.matches(PluginVersion(0, 2, 0)) is True
        assert c.matches(PluginVersion(0, 2, 5)) is True
        assert c.matches(PluginVersion(0, 3, 0)) is True  # Allowed: <1.0.0
        assert c.matches(PluginVersion(1, 0, 0)) is False

    def test_tilde_constraint(self):
        """Test ~ constraint (compatible with minor version)"""
        c = VersionConstraint("~1.2.0")
        assert c.matches(PluginVersion(1, 2, 0)) is True
        assert c.matches(PluginVersion(1, 2, 5)) is True
        assert c.matches(PluginVersion(1, 3, 0)) is False
        assert c.matches(PluginVersion(1, 1, 0)) is False

    def test_range_constraint(self):
        """Test version range constraints"""
        c = VersionConstraint(">=1.0.0,<2.0.0")
        assert c.matches(PluginVersion(1, 0, 0)) is True
        assert c.matches(PluginVersion(1, 5, 0)) is True
        assert c.matches(PluginVersion(1, 9, 9)) is True
        assert c.matches(PluginVersion(2, 0, 0)) is False
        assert c.matches(PluginVersion(0, 9, 0)) is False

    def test_constraint_string_representation(self):
        """Test string conversion preserves original specifier"""
        c = VersionConstraint("^1.2.0")
        assert str(c) == "^1.2.0"

    def test_constraint_with_whitespace(self):
        """Test constraint parsing with whitespace"""
        c = VersionConstraint(" >= 1.2.0 ")
        assert c.matches(PluginVersion(1, 2, 0)) is True


class TestParseVersionFunction:
    """Test parse_version convenience function"""

    def test_parse_version_returns_plugin_version(self):
        """Test parse_version returns PluginVersion instance"""
        v = parse_version("1.2.3")
        assert isinstance(v, PluginVersion)
        assert v.major == 1
        assert v.minor == 2
        assert v.patch == 3

    def test_parse_version_with_prerelease(self):
        """Test parse_version with pre-release"""
        v = parse_version("2.0.0-beta")
        assert v.major == 2
        assert v.prerelease == "beta"

    def test_parse_version_invalid(self):
        """Test parse_version raises ValueError for invalid input"""
        with pytest.raises(ValueError):
            parse_version("invalid")


class TestCheckVersionConstraintFunction:
    """Test check_version_constraint convenience function"""

    def test_check_exact_match(self):
        """Test exact version constraint check"""
        assert check_version_constraint("1.2.3", "1.2.3") is True
        assert check_version_constraint("1.2.3", "1.2.4") is False

    def test_check_greater_than_equal(self):
        """Test >= constraint check"""
        assert check_version_constraint("1.2.0", ">=1.0.0") is True
        assert check_version_constraint("0.9.0", ">=1.0.0") is False

    def test_check_caret_constraint(self):
        """Test ^ constraint check"""
        assert check_version_constraint("1.5.0", "^1.0.0") is True
        assert check_version_constraint("2.0.0", "^1.0.0") is False

    def test_check_tilde_constraint(self):
        """Test ~ constraint check"""
        assert check_version_constraint("1.2.5", "~1.2.0") is True
        assert check_version_constraint("1.3.0", "~1.2.0") is False


class TestVersionManager:
    """Test VersionManager class"""

    def test_version_manager_creation(self):
        """Test VersionManager initialization"""
        vm = VersionManager("2.3.0")
        assert vm.core_version.major == 2
        assert vm.core_version.minor == 3
        assert vm.core_version.patch == 0

    def test_check_compatibility_core_version(self):
        """Test core version compatibility check"""
        vm = VersionManager("2.3.0")
        
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test",
            requires_core="^2.0.0",
        )
        
        compatible, issues = vm.check_compatibility(manifest)
        assert compatible is True
        assert len(issues) == 0

    def test_check_compatibility_incompatible_core(self):
        """Test incompatible core version detection"""
        vm = VersionManager("3.0.0")
        
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test",
            requires_core="^2.0.0",
        )
        
        compatible, issues = vm.check_compatibility(manifest)
        assert compatible is False
        assert len(issues) == 1
        assert "Core version mismatch" in issues[0]

    def test_check_compatibility_missing_dependency(self):
        """Test missing dependency detection"""
        vm = VersionManager("2.3.0")
        
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test",
            requires_core="^2.0.0",
            dependencies={"other_plugin": ">=1.0.0"},
        )
        
        compatible, issues = vm.check_compatibility(manifest)
        assert compatible is False
        assert any("Missing dependency" in issue for issue in issues)

    def test_check_compatibility_version_mismatch(self):
        """Test dependency version mismatch detection"""
        vm = VersionManager("2.3.0")
        
        # Register a plugin first
        dep_manifest = PluginManifest(
            id="other_plugin",
            name="Other Plugin",
            version=PluginVersion(2, 0, 0),
            author="Test",
            requires_core="^2.0.0",
        )
        vm.register_plugin(dep_manifest)
        
        # Now check a plugin that requires older version
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test",
            requires_core="^2.0.0",
            dependencies={"other_plugin": ">=1.0.0,<2.0.0"},
        )
        
        compatible, issues = vm.check_compatibility(manifest)
        assert compatible is False
        assert any("Dependency version mismatch" in issue for issue in issues)

    def test_check_compatibility_conflict(self):
        """Test conflict detection"""
        vm = VersionManager("2.3.0")
        
        # Register a plugin
        conflict_manifest = PluginManifest(
            id="conflicting_plugin",
            name="Conflicting Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test",
            requires_core="^2.0.0",
        )
        vm.register_plugin(conflict_manifest)
        
        # Now check a plugin that conflicts with it
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test",
            requires_core="^2.0.0",
            conflicts=["conflicting_plugin"],
        )
        
        compatible, issues = vm.check_compatibility(manifest)
        assert compatible is False
        assert any("Conflict with" in issue for issue in issues)

    def test_register_plugin_success(self):
        """Test successful plugin registration"""
        vm = VersionManager("2.3.0")
        
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test",
            requires_core="^2.0.0",
        )
        
        result = vm.register_plugin(manifest)
        assert result is True
        assert vm.get_installed_version("test_plugin") == PluginVersion(1, 0, 0)

    def test_register_plugin_failure(self):
        """Test plugin registration failure"""
        vm = VersionManager("3.0.0")
        
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test",
            requires_core="^2.0.0",
        )
        
        with pytest.raises(RuntimeError):
            vm.register_plugin(manifest)

    def test_can_upgrade(self):
        """Test upgrade check"""
        vm = VersionManager("2.3.0")
        
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test",
            requires_core="^2.0.0",
        )
        vm.register_plugin(manifest)
        
        # Test valid upgrade
        can_upgrade, reason = vm.can_upgrade("test_plugin", PluginVersion(1, 1, 0))
        assert can_upgrade is True
        assert "Compatible upgrade" in reason
        
        # Test major version upgrade
        can_upgrade, reason = vm.can_upgrade("test_plugin", PluginVersion(2, 0, 0))
        assert can_upgrade is True
        assert "MAJOR version upgrade" in reason
        
        # Test downgrade attempt
        can_upgrade, reason = vm.can_upgrade("test_plugin", PluginVersion(0, 9, 0))
        assert can_upgrade is False
        assert "not newer" in reason
        
        # Test same version
        can_upgrade, reason = vm.can_upgrade("test_plugin", PluginVersion(1, 0, 0))
        assert can_upgrade is False

    def test_can_upgrade_not_installed(self):
        """Test upgrade check for non-installed plugin"""
        vm = VersionManager("2.3.0")
        
        can_upgrade, reason = vm.can_upgrade("not_installed", PluginVersion(1, 0, 0))
        assert can_upgrade is False
        assert "not installed" in reason


class TestPluginManifest:
    """Test PluginManifest class"""

    def test_manifest_creation(self):
        """Test manifest creation"""
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 2, 3),
            author="Test Author",
            description="A test plugin",
            requires_core="^2.0.0",
            dependencies={"dep1": ">=1.0.0"},
            optional_dependencies={"opt1": ">=0.5.0"},
            conflicts=["conflict1"],
        )
        
        assert manifest.id == "test_plugin"
        assert manifest.name == "Test Plugin"
        assert manifest.version.major == 1
        assert manifest.author == "Test Author"
        assert manifest.description == "A test plugin"
        assert manifest.requires_core == "^2.0.0"
        assert manifest.dependencies == {"dep1": ">=1.0.0"}
        assert manifest.optional_dependencies == {"opt1": ">=0.5.0"}
        assert manifest.conflicts == ["conflict1"]

    def test_manifest_defaults(self):
        """Test manifest default values"""
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 0, 0),
            author="Test",
        )
        
        assert manifest.description == ""
        assert manifest.requires_core == "^2.0.0"
        assert manifest.dependencies == {}
        assert manifest.optional_dependencies == {}
        assert manifest.conflicts == []

    def test_manifest_to_dict(self):
        """Test manifest serialization to dict"""
        manifest = PluginManifest(
            id="test_plugin",
            name="Test Plugin",
            version=PluginVersion(1, 2, 3),
            author="Test Author",
            description="A test plugin",
        )
        
        data = manifest.to_dict()
        assert data["id"] == "test_plugin"
        assert data["name"] == "Test Plugin"
        assert data["version"] == "1.2.3"
        assert data["author"] == "Test Author"
        assert data["description"] == "A test plugin"

    def test_manifest_from_dict(self):
        """Test manifest deserialization from dict"""
        data = {
            "id": "test_plugin",
            "name": "Test Plugin",
            "version": "1.2.3",
            "author": "Test Author",
            "description": "A test plugin",
            "requires_core": "^2.0.0",
            "dependencies": {"dep1": ">=1.0.0"},
            "optional_dependencies": {},
            "conflicts": [],
        }
        
        manifest = PluginManifest.from_dict(data)
        assert manifest.id == "test_plugin"
        assert manifest.version.major == 1
        assert manifest.version.minor == 2
        assert manifest.version.patch == 3


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_zero_version(self):
        """Test zero version handling"""
        v = PluginVersion(0, 0, 0)
        assert str(v) == "0.0.0"
        assert v.major == 0
        assert v.minor == 0
        assert v.patch == 0

    def test_large_version_numbers(self):
        """Test large version numbers"""
        v = PluginVersion(999, 999, 999)
        assert str(v) == "999.999.999"

    def test_prerelease_with_dots(self):
        """Test pre-release with multiple dot-separated identifiers"""
        v = PluginVersion.parse("1.0.0-alpha.1.2.3")
        assert v.prerelease == "alpha.1.2.3"

    def test_build_with_dots(self):
        """Test build metadata with multiple dot-separated identifiers"""
        v = PluginVersion.parse("1.0.0+build.1.2.3.sha.abc")
        assert v.build == "build.1.2.3.sha.abc"

    def test_prerelease_numeric(self):
        """Test numeric pre-release identifiers"""
        v = PluginVersion.parse("1.0.0-0.3.7")
        assert v.prerelease == "0.3.7"

    def test_constraint_edge_cases(self):
        """Test constraint edge cases"""
        # Empty constraint should match nothing or raise error
        # This tests the behavior of the packaging library
        c = VersionConstraint("0.0.1")
        assert c.matches(PluginVersion(0, 0, 1)) is True

    def test_version_comparison_chain(self):
        """Test version comparison in a chain"""
        v1 = PluginVersion(1, 0, 0)
        v2 = PluginVersion(1, 0, 1)
        v3 = PluginVersion(1, 1, 0)
        v4 = PluginVersion(2, 0, 0)
        
        assert v1 < v2 < v3 < v4
        assert v4 > v3 > v2 > v1

    def test_multiple_constraints(self):
        """Test version matching multiple constraint types"""
        # Test that a version can match complex constraints
        c = VersionConstraint(">=1.0.0,<2.0.0,!=1.5.0")
        assert c.matches(PluginVersion(1, 0, 0)) is True
        assert c.matches(PluginVersion(1, 5, 0)) is False
        assert c.matches(PluginVersion(2, 0, 0)) is False

    def test_frozen_dataclass_equality(self):
        """Test that frozen dataclass instances are properly hashable"""
        v1 = PluginVersion(1, 2, 3)
        v2 = PluginVersion(1, 2, 3)
        
        # Should be usable as dict keys
        d = {v1: "value"}
        assert d[v2] == "value"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
