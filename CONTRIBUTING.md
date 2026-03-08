# Contributing to XClaw AgentGuard Framework

Thank you for your interest in contributing! This document provides guidelines for contributing to the framework.

## Project Understanding

Before contributing, please understand what this project is:

- **A library**, not a standalone security product
- Provides **detection tools** that developers integrate into their applications
- Requires **explicit code changes** to use (not automatic protection)

See [README.md](README.md) for detailed project description.

## Contributors

- **XClaw AgentGuard Security Team**

## Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/yourusername/xclaw-agentguard-framework.git
   cd xclaw-agentguard-framework
   ```

3. Install in development mode:
   ```bash
   pip install -e ".[dev]"
   ```

## Code Style

- Follow PEP 8 style guidelines
- Use Black for formatting: `black xclaw_agentguard tests`
- Maximum line length: 100 characters
- Use type hints where appropriate
- Document all public APIs with docstrings

## Testing

- Write tests for new features
- Run tests: `pytest tests/ -v`
- Maintain test coverage > 80%
- Test both success and failure cases
- Include integration tests for new detectors

## Pull Request Process

1. Create a new branch for your feature
2. Make your changes with clear commit messages
3. Add/update tests as needed
4. Update documentation if applicable:
   - README.md for user-facing changes
   - Module README.md for architecture changes
   - DEPLOYMENT.md for setup changes
5. Ensure all CLI commands are implemented (no placeholder commands)
6. Submit a pull request with a clear description

## Documentation Requirements

All contributions must maintain accurate documentation:

- **No exaggeration** - Do not overstate capabilities
- **Clear limitations** - Explicitly state what the code does NOT do
- **Real examples** - All code examples must be tested and working
- **Honest disclosure** - If a feature is partial or incomplete, say so

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain a welcoming community

## Questions?

Feel free to open an issue for questions or discussions.
