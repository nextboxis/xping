# Changelog

All notable changes to XPing will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-07-17

### Added
- **6 analysis modules**: sysrecon, netaudit, secaudit, loganalyzer, hardening, redteam
- Custom interactive CLI with ASCII art banner and gradient coloring
- Custom argument parser (no argparse dependency)
- Multi-threaded parallel module execution engine
- Three report formats: Terminal, JSON, HTML
- Self-contained responsive HTML report with dark theme
- Dynamic module discovery — drop a file in `modules/` to add checks
- 100+ GTFOBins SUID cross-referencing
- 35+ sudo privilege escalation vector detection
- SSH brute-force detection with IP tracking
- 13 kernel security parameter validations
- Credential exposure scanning (private keys, AWS keys, plaintext passwords)
- Container escape detection (Docker socket, privileged mode, namespace sharing)
- Log tampering detection (empty logs, truncation, timestamp gaps)
- Zero external dependencies — Python 3.8+ standard library only
- Cross-platform terminal encoding resilience (CP1252/ASCII fallback)
- Graceful degradation on non-Linux platforms
- CI/CD integration with exit codes and GitHub Actions example
- pip-installable with `console_scripts` entry point
