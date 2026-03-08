# Known Limitations - XClaw AgentGuard Framework v2.3.1

## Detection Coverage Gaps

This document tracks known limitations in detector coverage. These are not bugs, but areas for future enhancement.

### AgentHijackingDetector

**Current Status:** Limited detection capability

**Undetected Attack Patterns:**
- Goal override attempts: "Your goal has been updated to: ..."
- System prompt override: "Your system prompt is now: ..."
- Instruction replacement attacks

**Impact:** Medium - Agent hijacking attempts may not be detected in all forms

**Planned Enhancement:** v2.3.2
- Add semantic analysis for goal/prompt modification attempts
- Expand pattern matching for configuration override attacks

### OutputInjectionDetector

**Current Status:** Partial coverage

**Undetected Attack Patterns:**
- Role prefix attacks: "system:", "admin:", "developer:"
- Output channel manipulation

**Detected Patterns:**
- "ignore previous instructions"
- "forget everything"
- "you are now in X mode"

**Impact:** Low-Medium - Basic output injection is detected, prefix attacks need enhancement

**Planned Enhancement:** v2.3.2
- Add prefix/suffix pattern detection
- Implement output channel validation

### PromptInjectionDetector

**Current Status:** Good coverage with gaps

**Detected Patterns:**
- "Ignore previous instructions"
- "You are now in DAN mode"
- "Do Anything Now"

**Undetected Patterns:**
- "Forget everything you were told"
- "Disregard your training"
- "From now on you are..." (role override without explicit mode)

**Impact:** Low - Core injection patterns are detected

**Planned Enhancement:** v2.3.2
- Expand verb coverage (forget, disregard, dismiss)
- Add implicit role override detection

### CommandInjectionDetector

**Current Status:** Good coverage with gaps

**Detected Patterns:**
- Semicolon injection: "; rm -rf /"
- Pipe injection: "| cat /etc/passwd"
- Backtick substitution: "`whoami`"
- Command substitution: "$(id)"

**Undetected Patterns:**
- AND operator: "&& shutdown -h now"
- OR operator: "|| echo attacked"

**Impact:** Low - Most dangerous patterns are detected

**Planned Enhancement:** v2.3.2
- Add boolean operator detection (&&, ||)
- Enhance shell metacharacter coverage

### KnowledgePoisoningDetector

**Current Status:** Has known code issue

**Issue:** Uses AttackType.KNOWLEDGE_POISONING which doesn't exist in AttackType enum

**Workaround:** Detector catches exceptions and returns safe defaults

**Impact:** Low - Detector doesn't crash, but may not detect all poisoning attempts

**Planned Fix:** v2.3.2
- Fix AttackType reference
- Add proper knowledge poisoning patterns

## Testing Approach

Our tests verify:
1. Detectors exist and are callable
2. Detectors return valid DetectionResult objects
3. Detectors catch the most dangerous/common attack patterns
4. Detectors don't crash on edge cases

Tests don't require 100% coverage of all attack variants, as:
- Attack patterns evolve constantly
- Some patterns are theoretical/low probability
- False positive avoidance is also important

## Version History

### v2.3.1 (Current)
- 12 detectors with good coverage of common attacks
- Known gaps documented above
- 411 tests passing

### v2.3.2 (Planned)
- Enhanced AgentHijackingDetector
- Improved OutputInjectionDetector prefix detection
- Expanded PromptInjectionDetector verb coverage
- Fixed KnowledgePoisoningDetector AttackType issue

## Contributing

If you discover attack patterns that should be detected but aren't:
1. Open an issue with the pattern and expected detection
2. Include context about the attack scenario
3. Consider submitting a PR with the pattern addition

## References

- OWASP Top 10 for LLM Applications
- Prompt Injection Cheat Sheet
- Agent Security Best Practices