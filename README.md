#  XPing

<p align="center">
  <img src="assets/xping_banner.png" alt="XPing Banner" width="800">
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img alt="Python 3.8+" src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green?style=flat-square"></a>
  <a href="#"><img alt="Platform: Linux" src="https://img.shields.io/badge/platform-Linux-orange?style=flat-square&logo=linux&logoColor=white"></a>
  <a href="#"><img alt="Dependencies: None" src="https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat-square"></a>
  <a href="#"><img alt="Version: 1.0.0" src="https://img.shields.io/badge/version-1.0.0-blueviolet?style=flat-square"></a>
</p>

<p align="center">
  <strong>All-in-One Linux Security, Hardening & Systems Analysis Toolkit</strong>
</p>

XPing is a production-grade, modular security auditing and reconnaissance tool for Linux systems. Designed with **zero external dependencies** (using the Python 3.8+ standard library only), it runs seamlessly on bare-metal servers, containers, VM instances, or air-gapped secure environments.

XPing performs read-only, non-destructive checks across **7 analysis domains**. It features a **custom interactive CLI menu**, multi-threaded parallel execution, target host/IP configuration, security drift tracking (`xping diff`), and structured reporting (Terminal, JSON, self-contained HTML, and GitHub SARIF v2.1.0).

---

## 📑 Table of Contents

- [Features & Modules](#-features--modules)
- [Requirements & System Resilience](#️-requirements--system-resilience)
- [Quick Start](#-quick-start)
- [CLI Reference](#-cli-reference)
- [Exit Codes](#-exit-codes)
- [Reporting Formats](#-reporting-formats)
- [Architecture](#-architecture)
- [CI/CD Integration](#-cicd-integration)
- [Adding Custom Modules](#-adding-custom-modules)
- [Security Policy & Safety Mechanics](#️-security-policy-safety--reliability-mechanics)
- [Comparison with Other Tools](#-comparison-with-other-tools)
- [Contributing](#-contributing)
- [Changelog](#-changelog)
- [License](#-license)

---

## 🚀 Features & Modules

| Module | Scope of Analysis | Key Detections & System Assets Audited |
| :--- | :--- | :--- |
| **`sysrecon`** | System & OS Recon | OS/kernel version analysis, system uptime, and CPU architecture. Enumerates all users in `/etc/passwd` to identify duplicate UID 0 accounts, system/service accounts with interactive login shells, and blank password fields in `/etc/shadow`. Audits active processes for known malicious keywords, catalogs system/user cron jobs, lists active kernel modules, reads `/proc/mounts`, and scans process environment variables for leaked credentials. |
| **`netaudit`** | Network Attack Surface | Identifies listening TCP and UDP sockets (mapping active processes to port numbers using `ss` or `netstat`). Audits rules in `iptables` or `nftables` for default `ACCEPT` policies on input/forward chains. Analyzes `/etc/resolv.conf` for external DNS configurations, checks interfaces for promiscuous mode sniffers, reads `ipNeigh` for ARP table duplicates (ARP spoofing), and checks `/proc/sys/net/ipv4/ip_forward` status. |
| **`secaudit`** | Security Permissions | Performs recursive scans of `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, and `/opt` to locate SUID/SGID binaries, mapping findings against **100+ GTFOBins exploitable executables**. Inspects file permissions on critical system assets (`/etc/shadow`, `/etc/passwd`, `/etc/gshadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`). Checks password complexity and expiration values in `/etc/login.defs`, and checks capabilities set via `getcap`. |
| **`loganalyzer`** | Forensic Log Auditing | Processes `/var/log/auth.log` or `/var/log/secure` to capture failed SSH logins, brute-force frequency (threshold-based IP tracking), successful logins, and switched sessions (`su`/`sudo`). Scans syslog and kernel logs for OOM (Out of Memory) kills, kernel panics, and process segmentation faults. Audits system log files for truncation or zero-byte resets (log tampering indicator). |
| **`hardening`** | Hardening Checkups | Checks 13 kernel parameter files in `/proc/sys` (including ASLR state, `ptrace_scope`, TCP SYN cookies, ICMP redirects, source routing, and packet logging). Evaluates Mandatory Access Control state (SELinux `getenforce` modes or AppArmor loaded profiles). Checks `/etc/modprobe.d` configurations for USB storage blacklisting, audits `/tmp` and `/var/tmp` for `noexec`/`nosuid`/`nodev` mount flags, and checks automatic update services. |
| **`redteam`** | Attack Path Validation | Analyzes active environment `PATH` configurations for writable directories or current-directory (`.`) inclusions. Evaluates user sudo configurations (`sudo -l`) for **35+ known privilege escalation vectors** (such as passwordless `tar`, `vim`, `find`, `docker`, or compiler tools). Detects unencrypted private SSH keys, AWS access keys, and plain-text passwords in configuration files. Scans shell history files for plain-text password usage. |
| **`container`** | Container & Cloud Audit | Audits Docker daemon socket file permissions, unauthenticated Docker TCP API ports (2375/2376), container capability leaks (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`), accessible cloud metadata IMDS endpoints (AWS 169.254.169.254, GCP, Azure), exposed Kubernetes service account tokens, and container runtime environment boundaries. |

---

## 🛠️ Requirements & System Resilience

- **Runtime**: Python 3.8+ (Standard Library only. No `pip install` required).
- **Target OS**: Linux (Kali, Ubuntu, Debian, RHEL, CentOS, Rocky Linux, Alpine, Arch).
- **Permissions**: Runs as an unprivileged user (with graceful degradation for operations requiring root) or as `root` (highly recommended for complete coverage).
- **Cross-Platform Resilience**:
  - **Graceful Degradation**: If executed on Windows or macOS, XPing runs its platform-independent components, allowing lists, configuration validation, and reporting without crashing.
  - **Console Robustness**: The terminal output automatically detects and intercepts encoding issues (like Windows `CP1252` encoding). It replaces box-drawing symbols with ASCII fallbacks on the fly to prevent `UnicodeEncodeError` crashes.

---

## ⚡ Quick Start

### 1. Clone & Run Directly

```bash
# Clone the repository
git clone https://github.com/giridharan-dev/xping.git
cd xping

# Option A: Run a full security scan outputting to the Terminal
sudo python3 run.py scan --all

# Option B: Run scan for a specific target host or IP address
sudo python3 run.py scan --all --target 192.168.1.50

# Option C: Run specific modules only
sudo python3 run.py scan --modules sysrecon,container

# Option D: Security Drift Analysis between baseline and current scans
python3 run.py diff baseline.json current.json

# Option E: Launch the Interactive Menu Console
python3 run.py
#   [1] Full Security Scan      — Runs all 7 modules sequentially.
#   [2] Selective Scan          — Displays module list; type numbers (e.g. 1,4) to run.
#   [3] Quick Scan (High+)      — Runs full scan filtering out LOW/INFO findings.
#   [4] List Modules            — Lists loaded modules with description text.
#   [5] Generate HTML Report    — Runs full scan, prompts for output file path.
#   [6] Generate JSON Report    — Runs full scan, exports data structure to file.
#   [7] Security Drift Analysis — Compares baseline.json and current.json for drift.
#   [8] Generate SARIF Report   — Exports GitHub Code Scanning SARIF v2.1.0 file.
#   [9] Generate Remediation    — Creates automated bash fix script (remediation.sh).
```

### 2. One-Liner Download & Run

```bash
git clone https://github.com/giridharan-dev/xping.git && cd xping && sudo python3 run.py scan --all
```

### 3. Standalone Installation

You can install XPing globally using `setuptools`:

```bash
sudo pip install -e .

# Run globally from anywhere on the system
sudo xping scan --all -t 192.168.1.100
```

---

## 💻 CLI Reference

XPing includes a custom-built argument parser (independent of the Python `argparse` module).

```text
xping scan [options]
  --all,     -a            Run all available modules
  --modules, -m LIST       Comma-separated list of modules (e.g. sysrecon,container)
  --target,  -t TARGET     Target host or IP address (default: auto-detected local IP)
  --format,  -f FORMAT     Output format: terminal | json | html | sarif (default: terminal)
  --output,  -o PATH       Output file destination (required for json/html/sarif)
  --severity,-s LEVEL      Minimum finding severity: info | low | medium | high | critical
  --generate-fix PATH      Export automated remediation bash script based on findings
  --custom-modules-dir DIR Directory path containing custom plugin modules
  --workers, -w N          Maximum parallel execution threads (default: 4)
  --log-file PATH          Write runtime diagnostics to a JSON log file
  --verbose, -v            Show trace debug logs
  --no-color               Disable all ANSI escape sequences for logging/output

xping diff <base.json> <curr.json>  Security drift analysis between two scan files
xping list                          List available modules and their descriptions
xping --version, -V                 Display the current version
xping --help, -h                    Show the help menu
```

---

## 🔢 Exit Codes

| Code | Meaning |
| :--- | :--- |
| `0` | Scan completed successfully — no critical findings |
| `1` | Error — invalid arguments, missing modules, or runtime failure |
| `2` | Scan completed — **CRITICAL** findings detected |
| `130` | Interrupted — user pressed Ctrl+C |

Use exit codes in CI/CD pipelines to gate deployments based on security posture.

---

## 📋 Reporting Formats

### 1. Interactive Terminal
Features high-contrast severity badges (`⬤ CRITICAL`, `● HIGH`, `◉ MEDIUM`, `○ LOW`), Target IP metadata, file path deep-links, clear evidence outputs, and step-by-step remediation advice.

### 2. Structured JSON
Output structured results containing full metrics, target host/IP, execution timing, findings list, and associated metadata. Perfect for SIEM integration or automation pipelines.

```bash
sudo xping scan --all -f json -o scan_results.json
```

### 3. Responsive HTML
Generates a self-contained, responsive, dark-themed HTML dashboard containing visual stat cards, target IP header, collapsible module sections, and structured code blocks. Requires no external CSS/JS file requests or assets.

```bash
sudo xping scan --all -f html -o security_report.html
```

### 4. GitHub Code Scanning SARIF (v2.1.0)
Generates OASIS SARIF v2.1.0 standard JSON formatted for native integration with GitHub Code Scanning & Security Tab.

```bash
sudo xping scan --all -f sarif -o security_results.sarif
```

### 5. Automated Remediation Bash Script (`--generate-fix`)
Generates an executable bash fix script (`remediation.sh`) with strict safety checks (`set -euo pipefail`) tailored to system findings.

```bash
sudo xping scan --all --generate-fix remediation.sh
```

---

## 📂 Architecture

```text
xping/
├── __init__.py            # Package versioning and attributes
├── cli.py                 # Interactive menus, console spinners, and custom arg parser
├── core/
│   ├── engine.py          # Parallel thread pool execution engine
│   ├── models.py          # Finding, Severity, ScanResult dataclasses
│   ├── reporter.py        # Terminal, HTML, JSON, and SARIF report builders + remediation generator
│   └── logger.py          # Structured logging (standard error & JSON logging)
├── modules/
│   ├── base.py            # Abstract Base Module class
│   ├── sysrecon.py        # OS, cron, env, processes check
│   ├── netaudit.py        # Interface, DNS, ARP, listening ports check
│   ├── secaudit.py        # PAM, SSH configuration, SUID, capability audit
│   ├── loganalyzer.py     # Forensics audit, auth.log, crash trace check
│   ├── hardening.py       # Kernel sysctl, MAC policies, services verification
│   ├── redteam.py         # Privesc, Docker container, keys detection
│   └── container.py       # Docker socket, capability leaks, cloud IMDS check
└── utils/
    └── helpers.py         # Safe command runner, fallback encoding parser
```

---

## 🤖 CI/CD Integration

XPing is designed to fit directly into DevSecOps workflows. Because it returns distinct exit codes depending on scan findings, you can block builds or raise security alerts in CI/CD when critical vulnerabilities are introduced.

### GitHub Actions Workflow Example

Create a workflow file in `.github/workflows/xping-audit.yml`:

```yaml
name: "Security & Hardening Audit"

on:
  push:
    branches: [ "main" ]
  schedule:
    - cron: '0 0 * * *' # Run daily at midnight

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Codebase
        uses: actions/checkout@v4

      - name: Execute XPing System Scan & SARIF Export
        run: |
          # Install command globally
          sudo pip install .
          
          # Run full scan, export HTML report and SARIF for GitHub Code Scanning
          sudo xping scan --all --format sarif --output security_results.sarif --generate-fix remediation.sh

      - name: Upload SARIF to GitHub Security Tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security_results.sarif

      - name: Upload Remediation Script Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: xping-remediation-script
          path: remediation.sh
```

---

## 🔌 Adding Custom Modules

Adding checks to XPing requires zero system registration. Create a Python file inside `xping/modules/` or load plugins dynamically from an external directory (`--custom-modules-dir /etc/xping/plugins`):

```python
from xping.modules.base import BaseModule
from xping.core.models import ModuleResult, Finding, Severity

class CustomAuditModule(BaseModule):
    @property
    def name(self) -> str:
        return "customaudit"

    @property
    def description(self) -> str:
        return "Verify target configuration"

    def run(self) -> ModuleResult:
        findings = []
        
        # Add custom detection logic
        findings.append(self._make_finding(
            title="Custom Compliance Failure",
            description="Configuration deviates from organizational baseline.",
            severity=Severity.MEDIUM,
            evidence="Configuration key = insecure_val",
            remediation="Change key to secure_val in configuration file."
        ))
        
        return ModuleResult(
            module_name=self.name,
            description=self.description,
            findings=findings
        )
```

XPing's scan engine will automatically register, execute, and document findings from the new module on the next run.

---

## 🛡️ Security Policy, Safety & Reliability Mechanics

To run safely in sensitive, high-availability production environments, XPing implements a strict security and resource containment policy:

1. **Strictly Non-Destructive**: 
   All inspections are read-only. XPing never alters files, adjusts iptables rules, starts/stops services, changes permissions, or manipulates system state.
2. **Robust Error & Crash Isolation**:
   Each module runs in its own isolated try-except context. If a single module encounters an error, throws an unhandled exception, or experiences a timeout, the orchestrator log captures the diagnostic traceback and continues execution of the remaining modules.
3. **Execution Timeouts**:
   Command executions (such as SUID binary lookups via `find` or log queries) utilize a strict 30-second execution timeout window. This prevents zombie processes or hung commands from consuming system CPU or blocking execution threads indefinitely.
4. **Memory Constraint Safeguards**:
   Log parsing routines (in `loganalyzer`) are bounded to a maximum of 50,000 lines per file. This prevents Out-of-Memory (OOM) exceptions on large, un-rotated server log targets.
5. **Zero Dependency Footprint**:
   Relies entirely on standard libraries included with Python 3.8+. It does not install external package wheels, configure system hooks, or introduce secondary dependency attack vectors to the system.

---

## ⚖️ Comparison with Other Tools

| Feature | XPing | Lynis | LinPEAS | linux-exploit-suggester |
| :--- | :---: | :---: | :---: | :---: |
| Zero dependencies | ✅ | ❌ (shell) | ❌ (shell) | ❌ (shell) |
| Python-based | ✅ | ❌ | ❌ | ❌ |
| Multi-threaded execution | ✅ | ❌ | ❌ | ❌ |
| HTML report output | ✅ | ✅ | ❌ | ❌ |
| JSON structured output | ✅ | ✅ | ❌ | ❌ |
| SARIF v2.1.0 (GitHub Code Scanning) | ✅ | ❌ | ❌ | ❌ |
| Security Drift Comparison (`xping diff`) | ✅ | ❌ | ❌ | ❌ |
| Automated Remediation Script Generation | ✅ | ❌ | ❌ | ❌ |
| Container & Cloud IMDS Audit | ✅ | ❌ | ✅ | ❌ |
| Interactive CLI menu | ✅ | ❌ | ❌ | ❌ |
| Red team privesc checks | ✅ | ❌ | ✅ | ✅ |
| GTFOBins SUID matching | ✅ | ❌ | ✅ | ❌ |
| Kernel exploit suggestions | ✅ | ❌ | ✅ | ✅ |
| CIS hardening benchmarks | ✅ | ✅ | ❌ | ❌ |
| Log forensics | ✅ | ❌ | ❌ | ❌ |
| CI/CD exit codes | ✅ | ✅ | ❌ | ❌ |
| Pluggable module system | ✅ | ❌ | ❌ | ❌ |
| Cross-platform fallback | ✅ | ❌ | ❌ | ❌ |

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:

- Development setup and code standards
- How to add new analysis modules
- Testing your changes
- Pull request process

---

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

---

## 📄 License

XPing is distributed under the [MIT License](LICENSE).

---

<p align="center">
  <sub>Built with ❤️ for the security community</sub>
</p>
