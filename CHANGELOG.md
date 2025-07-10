# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of Universal Process Gatherer
- Cross-platform process information gathering (Linux, AIX)
- Binary procfs parsing for AIX systems
- Native Linux procfs parsing
- Security analysis engine with suspicious process detection
- Multiple export formats (JSON, CSV, YAML, CEF)
- Real-time process monitoring
- Command-line interface with multiple subcommands
- Comprehensive process information collection
- Network connection tracking
- Open file descriptor enumeration
- Memory mapping information
- Security context extraction (SELinux, AppArmor, capabilities)
- Performance benchmarks
- GitHub Actions CI/CD pipeline
- Dual licensing (MIT/Apache 2.0)

### Security
- Built-in detection for reverse shells
- Privilege escalation monitoring
- Known malware hash matching
- Fork bomb detection
- Hidden process detection

[Unreleased]: https://github.com/anubhavg-icpl/universal-process-gatherer/compare/v1.0.0...HEAD
