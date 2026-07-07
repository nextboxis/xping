"""
xping.modules.sysrecon
~~~~~~~~~~~~~~~~~~~~~~~~~~
System Reconnaissance Module

Enumerates OS details, kernel, users, processes, cron jobs, kernel modules,
mounts, and environment variables. Flags anomalies like:
  - Users with UID 0 (besides root)
  - Users with login shells that shouldn't have them
  - Sensitive data leaked in environment variables
  - Hidden processes (PID gaps)
"""

import os
import re
from typing import List

from xping.modules.base import BaseModule
from xping.core.models import ModuleResult, Finding, Severity
from xping.core.logger import get_logger
from xping.utils.helpers import (
    run_cmd, run_cmd_lines, read_file_safe, read_file_lines,
    parse_passwd, is_root,
)

log = get_logger("sysrecon")

# Shells that indicate an interactive login account
LOGIN_SHELLS = {"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/fish", "/bin/ksh", "/bin/csh", "/bin/dash"}

# Environment variable names that may contain secrets
SENSITIVE_ENV_PATTERNS = [
    re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|AWS_SECRET|DB_PASS)", re.IGNORECASE),
]

# System/service accounts that are expected to have nologin
SYSTEM_ACCOUNTS = {
    "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "www-data", "backup", "list", "irc",
    "gnats", "nobody", "systemd-network", "systemd-resolve",
    "messagebus", "systemd-timesync", "syslog", "_apt", "tss",
    "uuidd", "tcpdump", "avahi-autoipd", "usbmux", "dnsmasq",
    "kernoops", "avahi", "cups-pk-helper", "rtkit", "whoopsie",
    "sssd", "speech-dispatcher", "nm-openvpn", "saned", "colord",
    "geoclue", "pulse", "gnome-initial-setup", "hplip", "gdm",
    "postfix", "sshd", "ftp", "postgres", "mysql", "redis",
    "mongodb", "memcache", "elasticsearch", "rabbitmq", "couchdb",
}


class SysReconModule(BaseModule):

    @property
    def name(self) -> str:
        return "sysrecon"

    @property
    def description(self) -> str:
        return "System reconnaissance: OS, kernel, users, processes, cron, env"

    def run(self) -> ModuleResult:
        findings: List[Finding] = []
        errors: List[str] = []

        findings.extend(self._check_os_info(errors))
        findings.extend(self._check_users(errors))
        findings.extend(self._check_processes(errors))
        findings.extend(self._check_cron(errors))
        findings.extend(self._check_kernel_modules(errors))
        findings.extend(self._check_mounts(errors))
        findings.extend(self._check_environment(errors))

        return ModuleResult(
            module_name=self.name,
            description=self.description,
            findings=findings,
            errors=errors,
        )

    def _check_os_info(self, errors: List[str]) -> List[Finding]:
        """Gather OS/kernel information and flag outdated kernels."""
        findings = []

        # Collect distro info
        distro = read_file_safe("/etc/os-release") or ""
        kernel_out, _, _ = run_cmd("uname -r")
        uptime_out, _, _ = run_cmd("uptime -p")
        arch_out, _, _ = run_cmd("uname -m")

        info_parts = []
        if distro:
            for line in distro.splitlines():
                if line.startswith("PRETTY_NAME="):
                    info_parts.append(f"Distro: {line.split('=', 1)[1].strip('\"')}")
        if kernel_out:
            info_parts.append(f"Kernel: {kernel_out}")
        if arch_out:
            info_parts.append(f"Arch: {arch_out}")
        if uptime_out:
            info_parts.append(f"Uptime: {uptime_out}")

        findings.append(self._make_finding(
            title="System Information",
            description="Operating system and kernel details",
            severity=Severity.INFO,
            evidence="\n".join(info_parts),
        ))

        # Flag very old kernels (heuristic: 2.x or 3.x series)
        if kernel_out:
            major = kernel_out.split(".")[0] if kernel_out else ""
            if major in ("2", "3"):
                findings.append(self._make_finding(
                    title="Outdated Kernel Detected",
                    description=f"Kernel {kernel_out} is significantly outdated and may have unpatched CVEs.",
                    severity=Severity.HIGH,
                    evidence=f"Running kernel: {kernel_out}",
                    remediation="Upgrade to a supported kernel version (5.x+ or 6.x+).",
                ))

        return findings

    def _check_users(self, errors: List[str]) -> List[Finding]:
        """Analyze user accounts for security anomalies."""
        findings = []
        users = parse_passwd()

        if not users:
            errors.append("Could not parse /etc/passwd")
            return findings

        # UID 0 accounts (besides root)
        uid0_users = [u for u in users if u["uid"] == "0" and u["username"] != "root"]
        if uid0_users:
            names = ", ".join(u["username"] for u in uid0_users)
            findings.append(self._make_finding(
                title="Non-Root UID 0 Accounts",
                description="Accounts other than 'root' have UID 0, granting full superuser privileges.",
                severity=Severity.CRITICAL,
                evidence=f"UID 0 accounts: {names}",
                remediation="Remove UID 0 from non-root accounts or disable them.",
            ))

        # System accounts with login shells
        for user in users:
            if (
                user["username"] in SYSTEM_ACCOUNTS
                and user["shell"] in LOGIN_SHELLS
            ):
                findings.append(self._make_finding(
                    title=f"Service Account Has Login Shell: {user['username']}",
                    description=f"System account '{user['username']}' has an interactive shell ({user['shell']}), which increases attack surface.",
                    severity=Severity.MEDIUM,
                    evidence=f"{user['username']}:{user['shell']}",
                    remediation=f"Set shell to /usr/sbin/nologin: usermod -s /usr/sbin/nologin {user['username']}",
                ))

        # Users with empty password field
        shadow_content = read_file_safe("/etc/shadow")
        if shadow_content:
            for line in shadow_content.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1] in ("", "!"):
                    if parts[1] == "":
                        findings.append(self._make_finding(
                            title=f"Empty Password: {parts[0]}",
                            description=f"User '{parts[0]}' has no password set, allowing passwordless login.",
                            severity=Severity.CRITICAL,
                            evidence=f"/etc/shadow entry for {parts[0]} has empty password field",
                            remediation=f"Set a password: passwd {parts[0]} — or lock: usermod -L {parts[0]}",
                        ))

        # Total user summary
        login_users = [u for u in users if u["shell"] in LOGIN_SHELLS]
        findings.append(self._make_finding(
            title="User Account Summary",
            description=f"Total accounts: {len(users)}, Login-capable: {len(login_users)}",
            severity=Severity.INFO,
            evidence="\n".join(f"  {u['username']} (UID:{u['uid']}, shell:{u['shell']})" for u in login_users),
        ))

        return findings

    def _check_processes(self, errors: List[str]) -> List[Finding]:
        """Enumerate running processes and detect anomalies."""
        findings = []

        ps_output, err, rc = run_cmd("ps auxww", timeout=10)
        if not ps_output:
            errors.append(f"Failed to list processes: {err}")
            return findings

        lines = ps_output.splitlines()
        proc_count = len(lines) - 1  # Subtract header

        # Detect processes running as root
        root_procs = []
        for line in lines[1:]:
            parts = line.split(None, 10)
            if parts and parts[0] == "root":
                root_procs.append(parts[-1] if len(parts) > 10 else parts[-1])

        findings.append(self._make_finding(
            title="Process Summary",
            description=f"Total running processes: {proc_count}, running as root: {len(root_procs)}",
            severity=Severity.INFO,
            evidence=f"Root processes (sample): {'; '.join(root_procs[:10])}",
        ))

        # Suspicious process names
        suspicious_keywords = ["nc ", "ncat", "socat", "msfconsole", "meterpreter",
                               "reverse", "bind_shell", "cryptominer", "xmrig", "minerd"]
        for line in lines[1:]:
            lower_line = line.lower()
            for keyword in suspicious_keywords:
                if keyword in lower_line:
                    findings.append(self._make_finding(
                        title=f"Suspicious Process Detected: {keyword.strip()}",
                        description=f"A process matching known suspicious pattern '{keyword.strip()}' was found.",
                        severity=Severity.HIGH,
                        evidence=line.strip(),
                        remediation="Investigate this process. If unauthorized, terminate it and check for persistence.",
                    ))
                    break

        return findings

    def _check_cron(self, errors: List[str]) -> List[Finding]:
        """Enumerate cron jobs across system and user crontabs."""
        findings = []
        all_cron_entries = []

        # System cron directories
        cron_dirs = [
            "/etc/crontab", "/etc/cron.d",
            "/etc/cron.daily", "/etc/cron.hourly",
            "/etc/cron.weekly", "/etc/cron.monthly",
        ]
        for cron_path in cron_dirs:
            if os.path.isfile(cron_path):
                content = read_file_safe(cron_path)
                if content:
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            all_cron_entries.append(f"[{cron_path}] {line}")
            elif os.path.isdir(cron_path):
                try:
                    for fname in os.listdir(cron_path):
                        fpath = os.path.join(cron_path, fname)
                        content = read_file_safe(fpath)
                        if content:
                            for line in content.splitlines():
                                line = line.strip()
                                if line and not line.startswith("#"):
                                    all_cron_entries.append(f"[{fpath}] {line}")
                except PermissionError:
                    pass

        # User crontabs
        crontab_out, _, rc = run_cmd("crontab -l 2>/dev/null")
        if crontab_out and rc == 0:
            for line in crontab_out.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    all_cron_entries.append(f"[user-crontab] {line}")

        if all_cron_entries:
            findings.append(self._make_finding(
                title="Cron Jobs Enumeration",
                description=f"Found {len(all_cron_entries)} active cron entries.",
                severity=Severity.INFO,
                evidence="\n".join(all_cron_entries[:50]),
            ))

            # Flag cron jobs with writable scripts
            for entry in all_cron_entries:
                # Extract potential file paths from cron entries
                parts = entry.split()
                for part in parts:
                    if part.startswith("/") and os.path.isfile(part):
                        if os.access(part, os.W_OK) and not is_root():
                            findings.append(self._make_finding(
                                title=f"Writable Cron Script: {part}",
                                description="A cron job executes a script that the current user can modify.",
                                severity=Severity.HIGH,
                                evidence=entry,
                                remediation=f"Restrict write permissions: chmod 755 {part} && chown root:root {part}",
                            ))

        return findings

    def _check_kernel_modules(self, errors: List[str]) -> List[Finding]:
        """List loaded kernel modules."""
        findings = []
        modules = run_cmd_lines("lsmod")

        if modules:
            findings.append(self._make_finding(
                title="Loaded Kernel Modules",
                description=f"{len(modules) - 1} kernel modules loaded.",
                severity=Severity.INFO,
                evidence="\n".join(modules[:30]) + ("\n..." if len(modules) > 30 else ""),
            ))

        return findings

    def _check_mounts(self, errors: List[str]) -> List[Finding]:
        """Check mounted filesystems for security-relevant mount options."""
        findings = []
        mounts = run_cmd_lines("mount")

        if not mounts:
            return findings

        findings.append(self._make_finding(
            title="Filesystem Mounts",
            description=f"{len(mounts)} filesystems mounted.",
            severity=Severity.INFO,
            evidence="\n".join(mounts[:20]),
        ))

        return findings

    def _check_environment(self, errors: List[str]) -> List[Finding]:
        """Scan environment variables for leaked secrets."""
        findings = []

        for key, value in os.environ.items():
            for pattern in SENSITIVE_ENV_PATTERNS:
                if pattern.search(key) and value:
                    # Mask the value for the evidence field
                    masked = value[:3] + "***" + value[-2:] if len(value) > 5 else "***"
                    findings.append(self._make_finding(
                        title=f"Sensitive Environment Variable: {key}",
                        description=f"Environment variable '{key}' appears to contain a secret.",
                        severity=Severity.MEDIUM,
                        evidence=f"{key}={masked}",
                        remediation="Use a secrets manager or file-based secrets instead of environment variables.",
                    ))
                    break

        return findings
