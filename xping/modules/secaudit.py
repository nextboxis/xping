"""
xping.modules.secaudit
~~~~~~~~~~~~~~~~~~~~~~~~~~
Security Audit Module

Deep filesystem and configuration security analysis:
  - SUID/SGID binary enumeration with GTFOBins cross-referencing
  - World-writable files/directories
  - SSH hardening checks
  - Sudo configuration analysis
  - PAM configuration review
  - Password policy validation
  - Capability-enabled binaries
  - Sensitive file permission checks
"""

import os
import stat
from typing import List, Set

from xping.modules.base import BaseModule
from xping.core.models import ModuleResult, Finding, Severity
from xping.core.logger import get_logger
from xping.utils.helpers import (
    run_cmd, run_cmd_lines, read_file_safe, read_file_lines,
    file_permissions_octal, file_owner, is_root,
)

log = get_logger("secaudit")

# SUID binaries known to be exploitable for privilege escalation
# Source: GTFOBins (https://gtfobins.github.io)
GTFOBINS_SUID = {
    "aria2c", "arp", "ash", "awk", "base64", "bash", "busybox", "cat",
    "chmod", "chown", "cp", "csh", "curl", "cut", "dash", "date", "dd",
    "dialog", "diff", "dmsetup", "docker", "ed", "emacs", "env", "expand",
    "expect", "file", "find", "flock", "fmt", "fold", "gdb", "gimp",
    "git", "grep", "head", "hping3", "iconv", "install", "ionice", "ip",
    "jjs", "join", "jq", "ksh", "ld.so", "less", "logsave", "lua",
    "make", "man", "mawk", "more", "mv", "mysql", "nano", "nawk",
    "nice", "nl", "nmap", "node", "od", "openssl", "perl", "pg",
    "php", "pic", "pico", "python", "python2", "python3", "readelf",
    "restic", "rev", "rlwrap", "rsync", "ruby", "run-parts", "rview",
    "rvim", "sed", "setarch", "shuf", "socat", "sort", "sqlite3",
    "start-stop-daemon", "stdbuf", "strace", "strings", "su", "sysctl",
    "tail", "tar", "taskset", "tclsh", "tee", "time", "timeout",
    "ul", "unexpand", "uniq", "unshare", "vi", "vim", "watch",
    "wget", "xargs", "xxd", "zip", "zsh",
}

# Sensitive files that should have strict permissions
SENSITIVE_FILES = {
    "/etc/shadow":        ("0640", "root"),
    "/etc/gshadow":       ("0640", "root"),
    "/etc/passwd":        ("0644", "root"),
    "/etc/group":         ("0644", "root"),
    "/etc/ssh/sshd_config": ("0600", "root"),
    "/etc/sudoers":       ("0440", "root"),
    "/etc/crontab":       ("0644", "root"),
    "/root/.ssh":         ("0700", "root"),
}


class SecAuditModule(BaseModule):

    @property
    def name(self) -> str:
        return "secaudit"

    @property
    def description(self) -> str:
        return "Security audit: SUID, permissions, SSH, sudo, PAM, passwords"

    def run(self) -> ModuleResult:
        findings: List[Finding] = []
        errors: List[str] = []

        findings.extend(self._check_suid_sgid(errors))
        findings.extend(self._check_world_writable(errors))
        findings.extend(self._check_ssh_config(errors))
        findings.extend(self._check_sudo(errors))
        findings.extend(self._check_pam(errors))
        findings.extend(self._check_password_policy(errors))
        findings.extend(self._check_capabilities(errors))
        findings.extend(self._check_sensitive_files(errors))
        findings.extend(self._check_unowned_files(errors))

        return ModuleResult(
            module_name=self.name,
            description=self.description,
            findings=findings,
            errors=errors,
        )

    def _check_suid_sgid(self, errors: List[str]) -> List[Finding]:
        """
        Find all SUID/SGID binaries and flag those in the GTFOBins list.

        Why this matters:
            SUID binaries run with the file owner's privileges (usually root).
            If a SUID binary can spawn a shell or read/write arbitrary files,
            any user can escalate to root.
        """
        findings = []

        # Search common paths to limit scan time
        search_paths = "/usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /bin /sbin /opt"
        output, err, rc = run_cmd(
            f"find {search_paths} -perm /4000 -o -perm /2000 2>/dev/null",
            timeout=60
        )

        if not output:
            if err:
                errors.append(f"SUID/SGID scan error: {err}")
            return findings

        suid_files = [f for f in output.splitlines() if f.strip()]
        gtfobins_hits = []
        all_suid = []

        for fpath in suid_files:
            basename = os.path.basename(fpath)
            all_suid.append(fpath)

            if basename in GTFOBINS_SUID:
                gtfobins_hits.append(fpath)
                findings.append(self._make_finding(
                    title=f"GTFOBins SUID Binary: {basename}",
                    description=(
                        f"SUID binary '{fpath}' is listed in GTFOBins and may allow "
                        f"privilege escalation to root via known techniques."
                    ),
                    severity=Severity.HIGH,
                    evidence=fpath,
                    remediation=f"Remove SUID bit if not needed: chmod u-s {fpath}",
                ))

        findings.append(self._make_finding(
            title="SUID/SGID Binary Summary",
            description=(
                f"Found {len(all_suid)} SUID/SGID binaries, "
                f"{len(gtfobins_hits)} match GTFOBins exploitable list."
            ),
            severity=Severity.INFO if not gtfobins_hits else Severity.MEDIUM,
            evidence="\n".join(all_suid[:40]),
        ))

        return findings

    def _check_world_writable(self, errors: List[str]) -> List[Finding]:
        """Find world-writable files outside /tmp and /proc."""
        findings = []

        output, _, _ = run_cmd(
            "find / -xdev -type f -perm -0002 "
            "-not -path '/proc/*' -not -path '/sys/*' "
            "-not -path '/tmp/*' -not -path '/var/tmp/*' "
            "-not -path '/dev/*' 2>/dev/null",
            timeout=60
        )

        if output:
            files = output.splitlines()[:30]
            if files:
                findings.append(self._make_finding(
                    title=f"World-Writable Files: {len(files)} found",
                    description="Files writable by any user can be tampered with by attackers.",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(files),
                    remediation="Remove world-write permission: chmod o-w <file>",
                ))

        # World-writable directories without sticky bit
        dir_output, _, _ = run_cmd(
            "find / -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) "
            "-not -path '/proc/*' -not -path '/sys/*' 2>/dev/null",
            timeout=60
        )
        if dir_output:
            dirs = dir_output.splitlines()[:20]
            if dirs:
                findings.append(self._make_finding(
                    title=f"World-Writable Directories Without Sticky Bit: {len(dirs)}",
                    description="Directories writable by all users without the sticky bit allow any user to delete others' files.",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(dirs),
                    remediation="Set sticky bit: chmod +t <directory>",
                ))

        return findings

    def _check_ssh_config(self, errors: List[str]) -> List[Finding]:
        """Audit SSH server configuration for hardening issues."""
        findings = []
        config = read_file_safe("/etc/ssh/sshd_config")

        if not config:
            return findings

        lines = config.splitlines()

        # Build effective config (last directive wins, ignore comments)
        directives = {}
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                directives[parts[0].lower()] = parts[1]

        # Checks with (directive, bad_value, severity, description, remediation)
        checks = [
            ("permitrootlogin", "yes", Severity.CRITICAL,
             "SSH allows direct root login, enabling brute-force attacks against the root account.",
             "Set 'PermitRootLogin no' or 'PermitRootLogin prohibit-password' in sshd_config"),

            ("passwordauthentication", "yes", Severity.MEDIUM,
             "SSH allows password authentication, which is weaker than key-based auth.",
             "Set 'PasswordAuthentication no' and use SSH keys"),

            ("permitemptypasswords", "yes", Severity.CRITICAL,
             "SSH allows login with empty passwords.",
             "Set 'PermitEmptyPasswords no' in sshd_config"),

            ("x11forwarding", "yes", Severity.LOW,
             "X11 forwarding is enabled, which increases the attack surface.",
             "Set 'X11Forwarding no' unless specifically required"),

            ("protocol", "1", Severity.CRITICAL,
             "SSH Protocol 1 is enabled. It has known cryptographic weaknesses.",
             "Set 'Protocol 2' in sshd_config"),

            ("usepam", "no", Severity.MEDIUM,
             "PAM is disabled for SSH, bypassing system authentication policies.",
             "Set 'UsePAM yes' in sshd_config"),

            ("maxauthtries", None, Severity.MEDIUM,
             "MaxAuthTries is not set or is too high, allowing brute-force attempts.",
             "Set 'MaxAuthTries 3' in sshd_config"),
        ]

        for directive, bad_value, severity, desc, remed in checks:
            actual = directives.get(directive, "")

            if bad_value is None:
                # Check for missing directive
                if directive not in directives:
                    findings.append(self._make_finding(
                        title=f"SSH: {directive} not configured",
                        description=desc,
                        severity=severity,
                        evidence=f"{directive} not found in sshd_config",
                        remediation=remed,
                    ))
                elif directive == "maxauthtries":
                    try:
                        val = int(actual)
                        if val > 5:
                            findings.append(self._make_finding(
                                title=f"SSH: MaxAuthTries too high ({val})",
                                description=desc,
                                severity=severity,
                                evidence=f"MaxAuthTries {val}",
                                remediation=remed,
                            ))
                    except ValueError:
                        pass
            elif actual.lower() == bad_value.lower():
                findings.append(self._make_finding(
                    title=f"SSH: {directive} = {actual}",
                    description=desc,
                    severity=severity,
                    evidence=f"{directive} {actual}",
                    remediation=remed,
                ))

        return findings

    def _check_sudo(self, errors: List[str]) -> List[Finding]:
        """Analyze sudo configuration for dangerous rules."""
        findings = []

        # Check /etc/sudoers and /etc/sudoers.d/
        sudoers = read_file_safe("/etc/sudoers")
        if not sudoers:
            errors.append("Cannot read /etc/sudoers (need root)")
            return findings

        lines = sudoers.splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("Defaults"):
                continue

            # NOPASSWD detection
            if "NOPASSWD" in line:
                # ALL=(ALL) NOPASSWD: ALL is extremely dangerous
                if "NOPASSWD: ALL" in line or "NOPASSWD:ALL" in line:
                    findings.append(self._make_finding(
                        title="Sudo: NOPASSWD ALL Rule",
                        description="A sudo rule allows passwordless execution of ALL commands. Any compromise of this user grants full root.",
                        severity=Severity.CRITICAL,
                        evidence=line,
                        remediation="Restrict NOPASSWD to specific, necessary commands only.",
                    ))
                else:
                    findings.append(self._make_finding(
                        title="Sudo: NOPASSWD Rule",
                        description="A sudo rule allows passwordless execution of some commands.",
                        severity=Severity.MEDIUM,
                        evidence=line,
                        remediation="Review whether NOPASSWD is truly necessary for these commands.",
                    ))

            # Check for shell access via sudo
            shell_cmds = ["/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/env", "/usr/bin/python"]
            for cmd in shell_cmds:
                if cmd in line and "!" not in line.split(cmd)[0]:
                    findings.append(self._make_finding(
                        title=f"Sudo: Shell Access via {os.path.basename(cmd)}",
                        description=f"Sudo allows execution of {cmd}, which can spawn an interactive root shell.",
                        severity=Severity.HIGH,
                        evidence=line,
                        remediation=f"Remove {cmd} from sudo permissions unless absolutely required.",
                    ))

        return findings

    def _check_pam(self, errors: List[str]) -> List[Finding]:
        """Review PAM configuration for common issues."""
        findings = []
        pam_dir = "/etc/pam.d"

        if not os.path.isdir(pam_dir):
            return findings

        # Check common-auth or system-auth for password complexity
        for auth_file in ["common-auth", "system-auth", "password-auth"]:
            content = read_file_safe(os.path.join(pam_dir, auth_file))
            if content:
                if "pam_faildelay" not in content and "faillock" not in content:
                    findings.append(self._make_finding(
                        title="PAM: No Login Delay/Lockout",
                        description=f"No brute-force protection (pam_faildelay/faillock) found in {auth_file}.",
                        severity=Severity.MEDIUM,
                        evidence=f"Checked: /etc/pam.d/{auth_file}",
                        remediation="Add pam_faillock or pam_faildelay to PAM configuration.",
                    ))
                break

        return findings

    def _check_password_policy(self, errors: List[str]) -> List[Finding]:
        """Check password aging and complexity policies."""
        findings = []
        login_defs = read_file_safe("/etc/login.defs")

        if not login_defs:
            return findings

        policies = {}
        for line in login_defs.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split()
                if len(parts) >= 2:
                    policies[parts[0]] = parts[1]

        # Check PASS_MAX_DAYS
        max_days = policies.get("PASS_MAX_DAYS", "")
        try:
            if int(max_days) > 90 or int(max_days) == 99999:
                findings.append(self._make_finding(
                    title=f"Password Expiry Too Long: {max_days} days",
                    description="Passwords don't expire frequently enough, increasing compromise window.",
                    severity=Severity.MEDIUM,
                    evidence=f"PASS_MAX_DAYS = {max_days}",
                    remediation="Set PASS_MAX_DAYS to 90 or less in /etc/login.defs",
                ))
        except ValueError:
            pass

        # Check PASS_MIN_LEN
        min_len = policies.get("PASS_MIN_LEN", "")
        try:
            if int(min_len) < 8:
                findings.append(self._make_finding(
                    title=f"Weak Minimum Password Length: {min_len}",
                    description="Minimum password length is below recommended 8 characters.",
                    severity=Severity.MEDIUM,
                    evidence=f"PASS_MIN_LEN = {min_len}",
                    remediation="Set PASS_MIN_LEN to 12+ in /etc/login.defs",
                ))
        except ValueError:
            pass

        return findings

    def _check_capabilities(self, errors: List[str]) -> List[Finding]:
        """Find binaries with Linux capabilities set."""
        findings = []

        output, _, rc = run_cmd("getcap -r /usr/bin /usr/sbin /usr/local/bin 2>/dev/null", timeout=30)
        if not output:
            return findings

        lines = output.splitlines()
        dangerous_caps = {"cap_setuid", "cap_setgid", "cap_sys_admin",
                          "cap_sys_ptrace", "cap_dac_override", "cap_net_raw"}

        for line in lines:
            for cap in dangerous_caps:
                if cap in line.lower():
                    findings.append(self._make_finding(
                        title=f"Dangerous Capability: {cap}",
                        description=f"Binary has {cap} capability, which may allow privilege escalation.",
                        severity=Severity.HIGH,
                        evidence=line.strip(),
                        remediation=f"Remove capability if not needed: setcap -r {line.split()[0]}",
                    ))
                    break

        return findings

    def _check_sensitive_files(self, errors: List[str]) -> List[Finding]:
        """Verify permissions on security-critical files."""
        findings = []

        for filepath, (expected_perms, expected_owner) in SENSITIVE_FILES.items():
            if not os.path.exists(filepath):
                continue

            actual_perms = file_permissions_octal(filepath)
            owner_info = file_owner(filepath)

            if actual_perms and actual_perms != expected_perms:
                # Check if permissions are MORE permissive than expected
                try:
                    actual_int = int(actual_perms, 8)
                    expected_int = int(expected_perms, 8)
                    if actual_int > expected_int:
                        findings.append(self._make_finding(
                            title=f"Overly Permissive: {filepath}",
                            description=f"File has permissions {actual_perms}, expected {expected_perms}.",
                            severity=Severity.HIGH,
                            evidence=f"Permissions: {actual_perms} (expected: {expected_perms})",
                            remediation=f"chmod {expected_perms} {filepath}",
                        ))
                except ValueError:
                    pass

            if owner_info and owner_info[0] != expected_owner:
                findings.append(self._make_finding(
                    title=f"Wrong Owner: {filepath}",
                    description=f"File owned by '{owner_info[0]}', expected '{expected_owner}'.",
                    severity=Severity.HIGH,
                    evidence=f"Owner: {owner_info[0]}:{owner_info[1]} (expected: {expected_owner})",
                    remediation=f"chown {expected_owner} {filepath}",
                ))

        return findings

    def _check_unowned_files(self, errors: List[str]) -> List[Finding]:
        """Find files with no valid owner or group."""
        findings = []

        output, _, _ = run_cmd(
            "find /usr /etc /var -xdev \\( -nouser -o -nogroup \\) 2>/dev/null",
            timeout=60
        )

        if output:
            files = output.splitlines()[:20]
            if files:
                findings.append(self._make_finding(
                    title=f"Unowned Files: {len(files)} found",
                    description="Files with no valid owner may indicate deleted accounts or compromised packages.",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(files),
                    remediation="Assign proper ownership or remove these files.",
                ))

        return findings
