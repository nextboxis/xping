# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

XPing is a **security analysis tool** — we take vulnerabilities in our own code seriously.

### If you discover a security issue:

1. **Do NOT open a public GitHub issue.** Security vulnerabilities should be reported privately.
2. **Email**: Send a detailed report to the maintainer with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
3. **Response time**: We aim to acknowledge reports within **48 hours** and provide a fix within **7 days** for critical issues.

### What qualifies as a vulnerability:

- Code injection via module names or user-supplied paths
- Arbitrary command execution beyond intended `run_cmd()` usage
- Information disclosure (e.g., credentials leaked in logs/reports)
- Denial of service (e.g., resource exhaustion bypassing safeguards)
- Supply chain issues in the build/install process

### What does NOT qualify:

- Findings from XPing scanning itself (it's a read-only tool)
- Feature requests for additional security checks
- Issues requiring physical access to the machine being scanned

## Security Design Principles

XPing follows these security principles by design:

1. **Read-only operations** — never modifies system state
2. **No network access** — doesn't phone home or download anything
3. **Zero dependencies** — no pip packages that could be compromised
4. **Timeout-bounded commands** — prevents resource exhaustion
5. **Crash isolation** — module failures don't leak data or crash the tool
6. **Credential masking** — passwords in evidence output are always masked

## Acknowledgments

We gratefully acknowledge security researchers who responsibly disclose vulnerabilities. Contributors will be credited in the CHANGELOG (with permission).
