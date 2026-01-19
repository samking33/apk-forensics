# Changelog

All notable changes to fSOC APK Forensics will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-19

### Added
- Initial production release
- Professional CLI interface with skull ASCII art banner
- Claude CLI integration with auto-approval for forensic analysis
- Comprehensive error handling and logging system
- CLI argument parsing (--apk, --quiet, --verbose, --no-color, --version)
- Configuration management via YAML file
- Automated installation script (install.sh)
- Support for single APK files and directory batch processing
- Detailed forensic reports with YARA rules and IoCs
- Dependency checking for Claude CLI and forensic tools
- Rotating log files with configurable retention
- Class-based architecture for maintainability

### Features
- Deep manual APK forensics using Claude AI
- Analysis of permissions, malicious behaviors, C2 infrastructure
- Network IoC extraction (URLs, IPs, domains)
- Cryptocurrency wallet and mining detection
- Attribution analysis (emails, phone numbers, API keys)
- YARA rule generation for detected threats
- Snort/Suricata IDS rule suggestions

### Technical
- Python 3.8+ support
- YAML-based configuration
- Structured logging with file rotation
- Timeout handling for long-running analyses
- Graceful degradation when tools are missing
- Production-ready error handling

## [Unreleased]

### Planned
- JSON output format support
- API mode for programmatic access
- Docker containerization
- Automated testing suite
- CI/CD pipeline integration
