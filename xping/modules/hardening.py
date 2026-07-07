"""
xping.modules.hardening
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Hardening Checker Module

Validates system configuration against CIS-inspired security benchmarks:
  - Kernel security parameters (ASLR, ptrace, SYN cookies, etc.)
  - SELinux/AppArmor mandatory access control
  - Core dump restrictions
  - USB storage restrictions
  - Filesystem mount options (noexec, nosuid on /tmp)
  - NTP synchronization
  - Bootloader password
  - Unused/unnecessary services
"""

import os
from typing import List, Dict, Tuple, Optional

from xping.modules.base import BaseModule
from xping.core.models import ModuleResult, Finding, Severity
from xping.core.logger import get_logger
from xping.utils.helpers import (
    run_cmd, run_cmd_lines, read_file_safe, read_file_lines,
)

log = get_logger("hardening")

# Kernel parameters to check: (sysctl_path, expected_value, severity, description, remediation)
KERNEL_CHECKS = [
    (
        "/proc/sys/kernel/randomize_va_space", "2", Severity.HIGH,
        "ASLR (Address Space Layout Randomization) is not fully enabled. "
        "ASLR randomizes memory addresses to make exploitation harder.",
        "echo 2 > /proc/sys/kernel/randomize_va_space && sysctl -w kernel.randomize_va_space=2"
    ),
    (
        "/proc/sys/kernel/yama/ptrace_scope", "1", Severity.MEDIUM,
        "ptrace scope is unrestricted. Any process can ptrace any other process "
        "owned by the same user, enabling credential dumping.",
        "echo 1 > /proc/sys/kernel/yama/ptrace_scope"
    ),
    (
        "/proc/sys/net/ipv4/tcp_syncookies", "1", Severity.MEDIUM,
        "SYN cookies are disabled. The system is vulnerable to SYN flood DoS attacks.",
        "sysctl -w net.ipv4.tcp_syncookies=1"
    ),
    (
        "/proc/sys/net/ipv4/conf/all/accept_redirects", "0", Severity.MEDIUM,
        "ICMP redirects are accepted. An attacker could redirect network traffic.",
        "sysctl -w net.ipv4.conf.all.accept_redirects=0"
    ),
    (
        "/proc/sys/net/ipv4/conf/all/send_redirects", "0", Severity.MEDIUM,
        "ICMP redirect sending is enabled. Not needed on non-router systems.",
        "sysctl -w net.ipv4.conf.all.send_redirects=0"
    ),
    (
        "/proc/sys/net/ipv4/conf/all/accept_source_route", "0", Severity.MEDIUM,
        "Source-routed packets are accepted. An attacker can specify packet routes.",
        "sysctl -w net.ipv4.conf.all.accept_source_route=0"
    ),
    (
        "/proc/sys/net/ipv4/conf/all/log_martians", "1", Severity.LOW,
        "Martian packet logging is disabled. Suspicious packets won't be logged.",
        "sysctl -w net.ipv4.conf.all.log_martians=1"
    ),
    (
        "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", "1", Severity.LOW,
        "System responds to ICMP broadcast pings (Smurf amplification vector).",
        "sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"
    ),
    (
        "/proc/sys/net/ipv6/conf/all/accept_ra", "0", Severity.MEDIUM,
        "IPv6 Router Advertisements are accepted. Can be used for MITM attacks.",
        "sysctl -w net.ipv6.conf.all.accept_ra=0"
    ),
    (
        "/proc/sys/kernel/kptr_restrict", "1", Severity.MEDIUM,
        "Kernel pointer exposure is unrestricted. Leaks kernel ASLR layout to unprivileged users.",
        "echo 1 > /proc/sys/kernel/kptr_restrict"
    ),
    (
        "/proc/sys/kernel/dmesg_restrict", "1", Severity.LOW,
        "Kernel log (dmesg) is accessible to unprivileged users. May leak sensitive info.",
        "echo 1 > /proc/sys/kernel/dmesg_restrict"
    ),
    (
        "/proc/sys/fs/protected_hardlinks", "1", Severity.MEDIUM,
        "Hardlink protection is disabled. Enables TOCTOU race condition attacks.",
        "echo 1 > /proc/sys/fs/protected_hardlinks"
    ),
    (
        "/proc/sys/fs/protected_symlinks", "1", Severity.MEDIUM,
        "Symlink protection is disabled. Enables symlink-based attacks in world-writable dirs.",
        "echo 1 > /proc/sys/fs/protected_symlinks"
    ),
]

# Services that should generally be disabled on hardened systems
UNNECESSARY_SERVICES = {
    "telnet": ("Telnet", Severity.HIGH, "Cleartext remote shell"),
    "vsftpd": ("FTP", Severity.MEDIUM, "Consider SFTP instead"),
    "rpcbind": ("RPCBind", Severity.MEDIUM, "RPC port mapper — often unnecessary"),
    "avahi-daemon": ("Avahi/mDNS", Severity.LOW, "mDNS service discovery — usually unnecessary on servers"),
    "cups": ("CUPS", Severity.LOW, "Print service — unnecessary on servers"),
    "bluetooth": ("Bluetooth", Severity.LOW, "Bluetooth service — unnecessary on servers"),
    "nfs-server": ("NFS", Severity.MEDIUM, "Network File System"),
    "xinetd": ("xinetd", Severity.MEDIUM, "Legacy super-server"),
    "rsh": ("rsh", Severity.HIGH, "Remote shell — cleartext, no encryption"),
    "rlogin": ("rlogin", Severity.HIGH, "Remote login — no encryption"),
}


class HardeningModule(BaseModule):

    @property
    def name(self) -> str:
        return "hardening"

    @property
    def description(self) -> str:
        return "Hardening checks: kernel params, SELinux, mounts, services"

    def run(self) -> ModuleResult:
        findings: List[Finding] = []
        errors: List[str] = []

        findings.extend(self._check_kernel_params(errors))
        findings.extend(self._check_mac(errors))
        findings.extend(self._check_core_dumps(errors))
        findings.extend(self._check_usb_storage(errors))
        findings.extend(self._check_mount_options(errors))
        findings.extend(self._check_ntp(errors))
        findings.extend(self._check_bootloader(errors))
        findings.extend(self._check_services(errors))
        findings.extend(self._check_auto_updates(errors))

        return ModuleResult(
            module_name=self.name,
            description=self.description,
            findings=findings,
            errors=errors,
        )

    def _check_kernel_params(self, errors: List[str]) -> List[Finding]:
        """Validate kernel security parameters against recommended values."""
        findings = []
        passed = 0
        failed = 0

        for proc_path, expected, severity, description, remediation in KERNEL_CHECKS:
            actual_lines = read_file_lines(proc_path)
            actual = actual_lines[0] if actual_lines else None

            if actual is None:
                continue  # File doesn't exist, skip silently

            if actual != expected:
                failed += 1
                param_name = proc_path.replace("/proc/sys/", "").replace("/", ".")
                findings.append(self._make_finding(
                    title=f"Kernel: {param_name} = {actual} (expected {expected})",
                    description=description,
                    severity=severity,
                    evidence=f"{proc_path}: {actual} (expected: {expected})",
                    remediation=remediation,
                ))
            else:
                passed += 1

        findings.append(self._make_finding(
            title=f"Kernel Hardening: {passed} passed, {failed} failed",
            description=f"Checked {passed + failed} kernel parameters. {failed} need remediation.",
            severity=Severity.INFO if failed == 0 else Severity.MEDIUM,
            evidence=f"Passed: {passed}, Failed: {failed}, Total: {passed + failed}",
        ))

        return findings

    def _check_mac(self, errors: List[str]) -> List[Finding]:
        """Check Mandatory Access Control (SELinux/AppArmor) status."""
        findings = []

        # SELinux
        se_out, _, se_rc = run_cmd("getenforce 2>/dev/null")
        if se_rc == 0 and se_out:
            status = se_out.strip()
            if status.lower() == "enforcing":
                findings.append(self._make_finding(
                    title="SELinux: Enforcing",
                    description="SELinux is in enforcing mode. Mandatory access control is active.",
                    severity=Severity.INFO,
                    evidence=f"getenforce: {status}",
                ))
            elif status.lower() == "permissive":
                findings.append(self._make_finding(
                    title="SELinux: Permissive Mode",
                    description="SELinux is in permissive mode. Violations are logged but not enforced.",
                    severity=Severity.MEDIUM,
                    evidence=f"getenforce: {status}",
                    remediation="Set SELinux to enforcing: setenforce 1 && edit /etc/selinux/config",
                ))
            else:
                findings.append(self._make_finding(
                    title="SELinux: Disabled",
                    description="SELinux is disabled. No mandatory access control is active.",
                    severity=Severity.HIGH,
                    evidence=f"getenforce: {status}",
                    remediation="Enable SELinux: edit /etc/selinux/config, set SELINUX=enforcing, reboot.",
                ))
            return findings

        # AppArmor
        aa_out, _, aa_rc = run_cmd("aa-status 2>/dev/null || apparmor_status 2>/dev/null")
        if aa_rc == 0 and aa_out:
            profile_count = 0
            for line in aa_out.splitlines():
                if "profiles are loaded" in line or "profiles are in" in line:
                    try:
                        profile_count += int(line.strip().split()[0])
                    except (ValueError, IndexError):
                        pass

            if profile_count > 0:
                findings.append(self._make_finding(
                    title=f"AppArmor: Active ({profile_count} profiles)",
                    description="AppArmor mandatory access control is active.",
                    severity=Severity.INFO,
                    evidence=aa_out[:500],
                ))
            else:
                findings.append(self._make_finding(
                    title="AppArmor: No Profiles Loaded",
                    description="AppArmor is installed but no profiles are loaded.",
                    severity=Severity.MEDIUM,
                    evidence=aa_out[:500],
                    remediation="Load AppArmor profiles for critical services.",
                ))
            return findings

        # Neither found
        findings.append(self._make_finding(
            title="No MAC System Detected",
            description="Neither SELinux nor AppArmor is active. The system lacks mandatory access control.",
            severity=Severity.HIGH,
            evidence="getenforce and aa-status both failed",
            remediation="Install and enable SELinux or AppArmor.",
        ))

        return findings

    def _check_core_dumps(self, errors: List[str]) -> List[Finding]:
        """Check if core dumps are restricted."""
        findings = []

        # /proc/sys/fs/suid_dumpable
        dumpable = read_file_lines("/proc/sys/fs/suid_dumpable")
        if dumpable and dumpable[0] != "0":
            findings.append(self._make_finding(
                title="SUID Core Dumps Enabled",
                description="SUID programs can produce core dumps, potentially leaking sensitive data.",
                severity=Severity.MEDIUM,
                evidence=f"fs.suid_dumpable = {dumpable[0]}",
                remediation="echo 0 > /proc/sys/fs/suid_dumpable",
            ))

        # limits.conf
        limits = read_file_safe("/etc/security/limits.conf")
        if limits and "core" not in limits:
            findings.append(self._make_finding(
                title="Core Dumps Not Restricted in limits.conf",
                description="No core dump size limit in /etc/security/limits.conf.",
                severity=Severity.LOW,
                evidence="No 'core' directive found in /etc/security/limits.conf",
                remediation="Add '* hard core 0' to /etc/security/limits.conf",
            ))

        return findings

    def _check_usb_storage(self, errors: List[str]) -> List[Finding]:
        """Check if USB storage is disabled."""
        findings = []

        # Check if usb-storage module is blacklisted
        modprobe_blacklist = read_file_safe("/etc/modprobe.d/blacklist.conf") or ""
        usb_files = []
        if os.path.isdir("/etc/modprobe.d"):
            try:
                for f in os.listdir("/etc/modprobe.d"):
                    content = read_file_safe(os.path.join("/etc/modprobe.d", f))
                    if content:
                        usb_files.append(content)
            except PermissionError:
                pass

        all_modprobe = modprobe_blacklist + "\n".join(usb_files)
        if "usb-storage" not in all_modprobe and "usb_storage" not in all_modprobe:
            findings.append(self._make_finding(
                title="USB Storage Not Disabled",
                description="USB storage module is not blacklisted. USB devices can be mounted.",
                severity=Severity.LOW,
                evidence="usb-storage not found in /etc/modprobe.d/ blacklists",
                remediation="echo 'install usb-storage /bin/true' >> /etc/modprobe.d/disable-usb-storage.conf",
            ))

        return findings

    def _check_mount_options(self, errors: List[str]) -> List[Finding]:
        """Verify security mount options on sensitive partitions."""
        findings = []

        mount_output, _, _ = run_cmd("mount")
        if not mount_output:
            return findings

        mounts: Dict[str, str] = {}
        for line in mount_output.splitlines():
            parts = line.split()
            if len(parts) >= 6 and "on" in parts:
                on_idx = parts.index("on")
                mount_point = parts[on_idx + 1] if on_idx + 1 < len(parts) else ""
                # Options are typically in parentheses at the end
                options = ""
                for p in parts:
                    if p.startswith("(") and p.endswith(")"):
                        options = p.strip("()")
                mounts[mount_point] = options

        # /tmp should have noexec, nosuid, nodev
        tmp_opts = mounts.get("/tmp", "")
        if "/tmp" in mounts:
            missing = []
            for opt in ["noexec", "nosuid", "nodev"]:
                if opt not in tmp_opts:
                    missing.append(opt)
            if missing:
                findings.append(self._make_finding(
                    title=f"/tmp Missing Mount Options: {', '.join(missing)}",
                    description=f"/tmp is missing security mount options: {', '.join(missing)}. Attackers often stage payloads in /tmp.",
                    severity=Severity.MEDIUM,
                    evidence=f"/tmp options: {tmp_opts or 'defaults'}",
                    remediation=f"Add '{','.join(missing)}' to /tmp mount options in /etc/fstab",
                ))
        else:
            findings.append(self._make_finding(
                title="/tmp Not a Separate Partition",
                description="/tmp is not mounted as a separate partition with restricted options.",
                severity=Severity.MEDIUM,
                evidence="/tmp not found as separate mount point",
                remediation="Create a separate /tmp partition with noexec,nosuid,nodev options.",
            ))

        # /var/tmp should also have noexec
        if "/var/tmp" in mounts:
            vartmp_opts = mounts["/var/tmp"]
            if "noexec" not in vartmp_opts:
                findings.append(self._make_finding(
                    title="/var/tmp Missing noexec",
                    description="/var/tmp allows execution, which can be abused for staging attacks.",
                    severity=Severity.LOW,
                    evidence=f"/var/tmp options: {vartmp_opts or 'defaults'}",
                    remediation="Add 'noexec' to /var/tmp mount options in /etc/fstab",
                ))

        return findings

    def _check_ntp(self, errors: List[str]) -> List[Finding]:
        """Check if time synchronization is configured."""
        findings = []

        # Check for active NTP service
        ntp_services = ["chronyd", "ntpd", "systemd-timesyncd"]
        active = False

        for svc in ntp_services:
            out, _, rc = run_cmd(f"systemctl is-active {svc} 2>/dev/null")
            if rc == 0 and out and "active" in out.lower():
                active = True
                findings.append(self._make_finding(
                    title=f"NTP Active: {svc}",
                    description=f"Time synchronization via {svc} is active.",
                    severity=Severity.INFO,
                    evidence=f"{svc}: active",
                ))
                break

        if not active:
            timedatectl_out, _, _ = run_cmd("timedatectl show 2>/dev/null")
            if timedatectl_out and "NTP=yes" in timedatectl_out:
                active = True

        if not active:
            findings.append(self._make_finding(
                title="No NTP Synchronization Detected",
                description="Time synchronization is not active. Log timestamps may be unreliable.",
                severity=Severity.MEDIUM,
                evidence="No active NTP service found",
                remediation="Enable systemd-timesyncd: timedatectl set-ntp true",
            ))

        return findings

    def _check_bootloader(self, errors: List[str]) -> List[Finding]:
        """Check if bootloader is password-protected."""
        findings = []

        grub_cfg_paths = [
            "/boot/grub/grub.cfg",
            "/boot/grub2/grub.cfg",
            "/boot/efi/EFI/*/grub.cfg",
        ]

        grub_content = None
        for path in grub_cfg_paths:
            content = read_file_safe(path)
            if content:
                grub_content = content
                break

        if grub_content:
            if "password" not in grub_content.lower() and "password_pbkdf2" not in grub_content.lower():
                findings.append(self._make_finding(
                    title="Bootloader Not Password Protected",
                    description="GRUB bootloader has no password. An attacker with physical access can boot into single-user mode.",
                    severity=Severity.MEDIUM,
                    evidence="No 'password' directive found in grub.cfg",
                    remediation="Set GRUB password: grub-mkpasswd-pbkdf2, then add to /etc/grub.d/40_custom",
                ))

        return findings

    def _check_services(self, errors: List[str]) -> List[Finding]:
        """Detect unnecessary or dangerous services."""
        findings = []

        for svc_name, (display_name, severity, desc) in UNNECESSARY_SERVICES.items():
            out, _, rc = run_cmd(f"systemctl is-active {svc_name} 2>/dev/null")
            if rc == 0 and out and out.strip() == "active":
                findings.append(self._make_finding(
                    title=f"Unnecessary Service Active: {display_name} ({svc_name})",
                    description=f"{display_name} is running. {desc}",
                    severity=severity,
                    evidence=f"systemctl is-active {svc_name}: active",
                    remediation=f"systemctl stop {svc_name} && systemctl disable {svc_name}",
                ))

        return findings

    def _check_auto_updates(self, errors: List[str]) -> List[Finding]:
        """Check if automatic security updates are configured."""
        findings = []

        # Debian/Ubuntu: unattended-upgrades
        if os.path.isfile("/etc/apt/apt.conf.d/20auto-upgrades"):
            content = read_file_safe("/etc/apt/apt.conf.d/20auto-upgrades")
            if content and '"1"' in content:
                findings.append(self._make_finding(
                    title="Automatic Updates: Enabled (apt)",
                    description="Unattended upgrades are configured.",
                    severity=Severity.INFO,
                    evidence=content.strip(),
                ))
                return findings

        # RHEL/CentOS: dnf-automatic or yum-cron
        for svc in ["dnf-automatic.timer", "yum-cron"]:
            out, _, rc = run_cmd(f"systemctl is-active {svc} 2>/dev/null")
            if rc == 0 and out and "active" in out:
                findings.append(self._make_finding(
                    title=f"Automatic Updates: Enabled ({svc})",
                    description="Automatic security updates are configured.",
                    severity=Severity.INFO,
                    evidence=f"{svc}: active",
                ))
                return findings

        findings.append(self._make_finding(
            title="No Automatic Updates Detected",
            description="Automatic security updates are not configured. The system may miss critical patches.",
            severity=Severity.MEDIUM,
            evidence="No unattended-upgrades, dnf-automatic, or yum-cron detected",
            remediation="Enable automatic security updates for your distribution.",
        ))

        return findings
