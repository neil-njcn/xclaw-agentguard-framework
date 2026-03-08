# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.1] - 2026-03-07

### Added - Anti-Jacked Security Base (CRITICAL SECURITY FOUNDATION)
This release adds the **Anti-Jacked Security Base** - a comprehensive file integrity monitoring and tamper detection system that was missing from v2.3.0.

#### New Components (xclaw_agentguard/anti_jacked/):

1. **baseline_generator.py** - Baseline generator with SHA256 hashing
   - Scan critical files and generate cryptographic baselines
   - Store baselines in signed JSON format
   - Support for incremental updates and diff comparison
   - Progress callbacks for long operations

2. **immutable_log.py** - Immutable audit log chain
   - Tamper-evident append-only log
   - Cryptographic chaining (each entry hashes previous)
   - Automatic integrity verification
   - Export capabilities (JSON/JSONL)

3. **tamper_detector.py** - Tamper detection and alerting
   - Compare current state against trusted baseline
   - Detect modified, added, removed files
   - Multi-channel alerts (console, log, file, webhook)
   - Severity classification (info, warning, critical, emergency)

4. **auto_recovery.py** - Auto-recovery mechanism
   - Restore files from verified backups
   - Quarantine unauthorized files
   - Recovery verification
   - Dry-run mode for safe testing

5. **integrity_monitor.py** - Main coordination component
   - Scheduled and real-time monitoring modes
   - Automatic baseline management
   - Event callbacks for integration
   - Statistics and health reporting

6. **cli.py** - Command-line interface
   - `xclaw-agentguard baseline-generate` - Create integrity baseline
   - `xclaw-agentguard integrity-check` - Check for tampering
   - `xclaw-agentguard security-status` - Show security status

#### Integration:
- Exported from main xclaw_agentguard package
- Integrated with existing plugin system
- Automatic startup hook support
- CLI entry point: `xclaw-agentguard`

#### Critical Files Monitored:
- xclaw_agentguard/config/*.py
- xclaw_agentguard/core/*.py
- xclaw_agentguard/anti_jacked/*.py
- xclaw_agentguard/detectors/*/detector.py
- All JSON configuration files

### Security
- **This is a CRITICAL security release** - adds foundation-level protection
- All security events logged to tamper-evident audit chain
- Automatic detection of unauthorized modifications
- Self-healing capability via auto-recovery

## [2.3.0] - 2026-03-06

### Added
- Complete modular architecture redesign (Phase 2)
- 12 security detectors with unified interface:
  - OutputInjectionDetector
  - PromptInjectionDetector
  - CommandInjectionDetector
  - PathTraversalDetector
  - SQLInjectionDetector
  - AgentHijackingDetector
  - ContextManipulationDetector
  - KnowledgePoisoningDetector
  - ExfiltrationGuard
  - SystemPromptLeakDetector
  - BackdoorCodeDetector
  - JailbreakDetector
- BaseDetector abstract base class with template method pattern
- DetectionResult with Builder pattern and frozen dataclass
- ConfigSchema declarative configuration system
- Plugin system with 4 functional plugins:
  - report_formatter: JSON/Markdown/CSV output
  - custom_rules: YAML-based custom detection rules
  - audit_logger: File and SQLite audit logging
  - notification: Webhook/Slack/Console notifications
- Version management system for plugins
- Unified detector registry for centralized management
- Comprehensive test suite with 72 architecture tests
- Attack pattern testing with 205 test cases

### Changed
- Migrated from monolithic to modular architecture
- Standardized all detectors to use new DetectionResult
- Unified configuration interface across all detectors
- File size limit: ≤300 lines per detector

### Fixed
- ThreatLevel handling when detected=False (must be NONE)
- AttackType enum for KnowledgePoisoningDetector
- ConfigSchema parameter compatibility

### Architecture
- Zero references to old phase2.core architecture
- Clean separation between detectors and infrastructure
- Pattern-based detection with confidence scoring

## [2.2.0] - 2026-02-15

### Added
- Initial Phase 2 planning and design documents
- Canary release mechanism foundation
- Error contract standardization

### Notes
- See git history for earlier versions
