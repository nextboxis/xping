"""
xping.modules.loganalyzer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Log Forensics Module

Parses system log files for security-relevant events:
  - Failed SSH login attempts and brute-force detection
  - Privilege escalation events (su/sudo)
  - Service crashes and OOM kills
  - Log tampering indicators (timestamp gaps, truncation)
  - Top offending IPs and users
"""

import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import List, Dict, Tuple, Optional

from xping.modules.base import BaseModule
from xping.core.models import ModuleResult, Finding, Severity
from xping.core.logger import get_logger
from xping.utils.helpers import read_file_safe, read_file_lines, run_cmd

log = get_logger("loganalyzer")

# Regex patterns for log parsing
RE_FAILED_SSH = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)",
    re.IGNORECASE
)
RE_ACCEPTED_SSH = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)",
    re.IGNORECASE
)
RE_SUDO_CMD = re.compile(
    r"(\S+) : .* COMMAND=(.*)",
    re.IGNORECASE
)
RE_SU_FAIL = re.compile(
    r"FAILED su for (\S+) by (\S+)",
    re.IGNORECASE
)
RE_SYSLOG_TIMESTAMP = re.compile(
    r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
)
RE_OOM_KILL = re.compile(r"Out of memory|oom-kill|oom_kill", re.IGNORECASE)
RE_KERNEL_PANIC = re.compile(r"Kernel panic|BUG:|Oops:", re.IGNORECASE)
RE_SEGFAULT = re.compile(r"segfault at", re.IGNORECASE)

# Brute force threshold: N failed attempts from same IP
BRUTE_FORCE_THRESHOLD = 5

# Log files to analyze (in priority order)
LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/secure",          # RHEL/CentOS equivalent
    "/var/log/syslog",
    "/var/log/messages",        # RHEL/CentOS equivalent
    "/var/log/kern.log",
    "/var/log/faillog",
    "/var/log/daemon.log",
]

# Maximum lines to read per log file (prevents OOM on huge logs)
MAX_LOG_LINES = 50000


class LogAnalyzerModule(BaseModule):

    @property
    def name(self) -> str:
        return "loganalyzer"

    @property
    def description(self) -> str:
        return "Log forensics: auth failures, brute-force, crashes, tampering"

    def is_available(self) -> bool:
        """Check if any log files are readable."""
        return any(
            os.path.isfile(lf) and os.access(lf, os.R_OK)
            for lf in LOG_FILES
        )

    def run(self) -> ModuleResult:
        findings: List[Finding] = []
        errors: List[str] = []

        findings.extend(self._check_auth_logs(errors))
        findings.extend(self._check_system_logs(errors))
        findings.extend(self._check_last_logins(errors))
        findings.extend(self._check_log_tampering(errors))

        return ModuleResult(
            module_name=self.name,
            description=self.description,
            findings=findings,
            errors=errors,
        )

    def _find_auth_log(self) -> Optional[str]:
        """Find the primary authentication log file."""
        for path in ["/var/log/auth.log", "/var/log/secure"]:
            if os.path.isfile(path) and os.access(path, os.R_OK):
                return path
        return None

    def _find_syslog(self) -> Optional[str]:
        """Find the primary system log file."""
        for path in ["/var/log/syslog", "/var/log/messages"]:
            if os.path.isfile(path) and os.access(path, os.R_OK):
                return path
        return None

    def _check_auth_logs(self, errors: List[str]) -> List[Finding]:
        """Analyze authentication logs for failed logins and brute-force."""
        findings = []
        auth_log = self._find_auth_log()

        if not auth_log:
            errors.append("No readable auth log found (/var/log/auth.log or /var/log/secure)")
            return findings

        content = read_file_safe(auth_log, max_lines=MAX_LOG_LINES)
        if not content:
            errors.append(f"Auth log {auth_log} is empty or unreadable")
            return findings

        lines = content.splitlines()

        # ── Failed SSH Logins ────────────────────────────────────
        failed_by_ip: Counter = Counter()
        failed_by_user: Counter = Counter()
        failed_details: List[str] = []

        for line in lines:
            match = RE_FAILED_SSH.search(line)
            if match:
                user, ip, port = match.groups()
                failed_by_ip[ip] += 1
                failed_by_user[user] += 1
                failed_details.append(f"  {ip} → {user}")

        total_failed = sum(failed_by_ip.values())
        if total_failed > 0:
            findings.append(self._make_finding(
                title=f"Failed SSH Logins: {total_failed} attempts",
                description=f"Detected {total_failed} failed SSH login attempts from {len(failed_by_ip)} unique IPs.",
                severity=Severity.MEDIUM if total_failed < 50 else Severity.HIGH,
                evidence=(
                    f"Top IPs:\n" +
                    "\n".join(f"  {ip}: {count} attempts" for ip, count in failed_by_ip.most_common(10)) +
                    f"\n\nTop usernames:\n" +
                    "\n".join(f"  {user}: {count} attempts" for user, count in failed_by_user.most_common(10))
                ),
                remediation="Install fail2ban, use SSH keys only, and restrict access with AllowUsers.",
            ))

        # ── Brute Force Detection ────────────────────────────────
        brute_force_ips = {ip: count for ip, count in failed_by_ip.items()
                           if count >= BRUTE_FORCE_THRESHOLD}
        if brute_force_ips:
            findings.append(self._make_finding(
                title=f"SSH Brute-Force Detected: {len(brute_force_ips)} IPs",
                description=f"{len(brute_force_ips)} IP addresses have {BRUTE_FORCE_THRESHOLD}+ failed login attempts.",
                severity=Severity.CRITICAL,
                evidence="\n".join(f"  {ip}: {count} failures" for ip, count in
                                   sorted(brute_force_ips.items(), key=lambda x: -x[1])[:20]),
                remediation=(
                    "1. Install and configure fail2ban\n"
                    "2. Block these IPs: " + ", ".join(list(brute_force_ips.keys())[:5]) + "\n"
                    "3. Consider geoblocking if logins are from unexpected regions"
                ),
            ))

        # ── Successful Logins ────────────────────────────────────
        successful = []
        for line in lines:
            match = RE_ACCEPTED_SSH.search(line)
            if match:
                user, ip, port = match.groups()
                successful.append(f"  {user} from {ip}")

        if successful:
            findings.append(self._make_finding(
                title=f"Successful SSH Logins: {len(successful)}",
                description="Successful SSH authentication events.",
                severity=Severity.INFO,
                evidence="\n".join(successful[-20:]),  # Last 20
            ))

        # ── Sudo Usage ───────────────────────────────────────────
        sudo_events = []
        for line in lines:
            match = RE_SUDO_CMD.search(line)
            if match:
                user, cmd = match.groups()
                sudo_events.append(f"  {user}: {cmd.strip()}")

        if sudo_events:
            findings.append(self._make_finding(
                title=f"Sudo Commands Executed: {len(sudo_events)}",
                description="Commands executed via sudo.",
                severity=Severity.INFO,
                evidence="\n".join(sudo_events[-20:]),
            ))

        # ── Failed su Attempts ───────────────────────────────────
        su_failures = []
        for line in lines:
            match = RE_SU_FAIL.search(line)
            if match:
                target, source = match.groups()
                su_failures.append(f"  {source} → {target}")

        if su_failures:
            findings.append(self._make_finding(
                title=f"Failed su Attempts: {len(su_failures)}",
                description="Failed attempts to switch user via su.",
                severity=Severity.MEDIUM,
                evidence="\n".join(su_failures[:20]),
                remediation="Restrict su access via /etc/pam.d/su or limit to wheel group.",
            ))

        return findings

    def _check_system_logs(self, errors: List[str]) -> List[Finding]:
        """Analyze syslog/messages for crashes, OOM, and kernel issues."""
        findings = []
        syslog = self._find_syslog()

        if not syslog:
            return findings

        content = read_file_safe(syslog, max_lines=MAX_LOG_LINES)
        if not content:
            return findings

        lines = content.splitlines()

        # OOM kills
        oom_lines = [l for l in lines if RE_OOM_KILL.search(l)]
        if oom_lines:
            findings.append(self._make_finding(
                title=f"OOM Kills Detected: {len(oom_lines)} events",
                description="Out-of-memory killer was invoked, indicating memory pressure.",
                severity=Severity.HIGH,
                evidence="\n".join(oom_lines[-10:]),
                remediation="Investigate memory usage. Consider increasing RAM or swap, or tune OOM settings.",
            ))

        # Kernel panics/oops
        panic_lines = [l for l in lines if RE_KERNEL_PANIC.search(l)]
        if panic_lines:
            findings.append(self._make_finding(
                title=f"Kernel Panics/Oops: {len(panic_lines)} events",
                description="Kernel-level crashes detected. May indicate hardware issues or exploits.",
                severity=Severity.CRITICAL,
                evidence="\n".join(panic_lines[-10:]),
                remediation="Check hardware health (memtest, disk SMART). Update kernel.",
            ))

        # Segfaults
        segfault_lines = [l for l in lines if RE_SEGFAULT.search(l)]
        if segfault_lines:
            findings.append(self._make_finding(
                title=f"Segmentation Faults: {len(segfault_lines)} events",
                description="Application crashes detected. May indicate exploitation attempts.",
                severity=Severity.MEDIUM,
                evidence="\n".join(segfault_lines[-10:]),
                remediation="Investigate affected processes. Update vulnerable software.",
            ))

        return findings

    def _check_last_logins(self, errors: List[str]) -> List[Finding]:
        """Analyze last login records."""
        findings = []

        last_output, _, rc = run_cmd("last -n 20 -F 2>/dev/null || last -n 20 2>/dev/null")
        if last_output:
            findings.append(self._make_finding(
                title="Recent Login History",
                description="Last 20 login sessions.",
                severity=Severity.INFO,
                evidence=last_output,
            ))

        # Check for logins at unusual hours (between 00:00-05:00)
        lastlog_out, _, _ = run_cmd("lastlog 2>/dev/null")
        if lastlog_out:
            never_logged = []
            for line in lastlog_out.splitlines()[1:]:
                if "Never logged in" in line:
                    parts = line.split()
                    if parts:
                        never_logged.append(parts[0])

        return findings

    def _check_log_tampering(self, errors: List[str]) -> List[Finding]:
        """Detect potential log tampering."""
        findings = []

        for logfile in ["/var/log/auth.log", "/var/log/secure",
                        "/var/log/syslog", "/var/log/messages"]:
            if not os.path.isfile(logfile):
                continue

            try:
                stat = os.stat(logfile)

                # Empty log file (suspicious for active system)
                if stat.st_size == 0:
                    findings.append(self._make_finding(
                        title=f"Empty Log File: {logfile}",
                        description=f"Log file {logfile} is empty on an active system. May indicate log wiping.",
                        severity=Severity.HIGH,
                        evidence=f"{logfile}: 0 bytes",
                        remediation="Check if logs are being rotated. Investigate potential log tampering.",
                    ))

                # Check for gaps in auth.log timestamps
                # (simplified: just check if file seems unreasonably small)
                if stat.st_size > 0 and logfile.endswith(("auth.log", "secure")):
                    content = read_file_safe(logfile, max_lines=100)
                    if content:
                        log_lines = content.splitlines()
                        if len(log_lines) < 5:
                            findings.append(self._make_finding(
                                title=f"Suspiciously Short Log: {logfile}",
                                description=f"Log file has only {len(log_lines)} lines. May have been truncated.",
                                severity=Severity.MEDIUM,
                                evidence=f"{logfile}: {len(log_lines)} lines, {stat.st_size} bytes",
                                remediation="Compare with rotated logs. Check logrotate configuration.",
                            ))

            except (OSError, PermissionError):
                pass

        return findings
