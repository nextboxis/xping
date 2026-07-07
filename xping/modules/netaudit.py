"""
xping.modules.netaudit
~~~~~~~~~~~~~~~~~~~~~~~~~~
Network Audit Module

Analyzes the network attack surface from the defender's perspective:
  - Listening ports and associated processes
  - Active connections to external IPs
  - Firewall rule analysis
  - DNS configuration
  - ARP cache anomalies
  - Dangerous service detection (telnet, FTP, etc.)
"""

import os
import re
from typing import List, Dict, Set

from xping.modules.base import BaseModule
from xping.core.models import ModuleResult, Finding, Severity
from xping.core.logger import get_logger
from xping.utils.helpers import run_cmd, run_cmd_lines, read_file_lines

log = get_logger("netaudit")

# Ports that should almost never be exposed
DANGEROUS_PORTS = {
    21: ("FTP", "Cleartext protocol — use SFTP instead"),
    23: ("Telnet", "Cleartext remote shell — use SSH instead"),
    25: ("SMTP", "Mail relay — ensure authentication is required"),
    69: ("TFTP", "Unauthenticated file transfer"),
    111: ("RPCBind", "RPC service mapper — high attack surface"),
    135: ("MSRPC", "Microsoft RPC — common attack vector"),
    139: ("NetBIOS", "Legacy file sharing — often unnecessary"),
    445: ("SMB", "File sharing — frequent target of exploits"),
    512: ("rexec", "Remote execution — unencrypted"),
    513: ("rlogin", "Remote login — no encryption"),
    514: ("rsh", "Remote shell — no encryption"),
    1099: ("Java RMI", "Remote Method Invocation — deserialization attacks"),
    1433: ("MSSQL", "Database — should not be exposed externally"),
    1521: ("Oracle DB", "Database — should not be exposed externally"),
    2049: ("NFS", "Network File System — access control issues"),
    3306: ("MySQL", "Database — should not be exposed externally"),
    3389: ("RDP", "Remote Desktop — brute-force target"),
    5432: ("PostgreSQL", "Database — should not be exposed externally"),
    5900: ("VNC", "Remote desktop — weak auth common"),
    6379: ("Redis", "In-memory store — often unauthed"),
    8080: ("HTTP-Alt", "Alternative HTTP — verify intentional"),
    9200: ("Elasticsearch", "Search engine — often unauthed"),
    11211: ("Memcached", "Cache — amplification attack vector"),
    27017: ("MongoDB", "Database — historically no default auth"),
}

# Private IP ranges — connections outside these are "external"
PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.", "127.", "::1", "fe80:", "fd")


class NetAuditModule(BaseModule):

    @property
    def name(self) -> str:
        return "netaudit"

    @property
    def description(self) -> str:
        return "Network audit: ports, connections, firewall, DNS, ARP"

    def is_available(self) -> bool:
        """Needs ss or netstat to function."""
        stdout, _, rc = run_cmd("which ss || which netstat", timeout=5)
        return rc == 0 and bool(stdout)

    def run(self) -> ModuleResult:
        findings: List[Finding] = []
        errors: List[str] = []

        findings.extend(self._check_listening_ports(errors))
        findings.extend(self._check_active_connections(errors))
        findings.extend(self._check_firewall(errors))
        findings.extend(self._check_dns(errors))
        findings.extend(self._check_interfaces(errors))
        findings.extend(self._check_arp(errors))

        return ModuleResult(
            module_name=self.name,
            description=self.description,
            findings=findings,
            errors=errors,
        )

    def _check_listening_ports(self, errors: List[str]) -> List[Finding]:
        """Enumerate listening TCP/UDP ports and flag dangerous ones."""
        findings = []

        # Try ss first, fall back to netstat
        output, err, rc = run_cmd("ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null")
        if not output:
            errors.append("Cannot enumerate listening ports (ss/netstat failed)")
            return findings

        lines = output.splitlines()
        listening_services = []
        dangerous_found = []

        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) < 5:
                continue

            proto = parts[0] if parts[0] in ("tcp", "udp", "tcp6", "udp6") else ""
            if not proto:
                continue

            local_addr = parts[4] if len(parts) > 4 else ""
            process_info = ""
            # ss format: last column often has users:((...))
            for p in parts:
                if "users:" in p or "pid=" in p:
                    process_info = p

            listening_services.append(f"{proto:6s} {local_addr:30s} {process_info}")

            # Extract port number
            port_str = local_addr.rsplit(":", 1)[-1] if ":" in local_addr else ""
            try:
                port = int(port_str)
            except ValueError:
                continue

            # Check against dangerous ports list
            if port in DANGEROUS_PORTS:
                svc_name, risk = DANGEROUS_PORTS[port]
                # Determine if bound to all interfaces (0.0.0.0 or ::)
                bind_all = any(x in local_addr for x in ("0.0.0.0", "::", "*"))
                sev = Severity.HIGH if bind_all else Severity.MEDIUM

                dangerous_found.append(self._make_finding(
                    title=f"Dangerous Port Open: {port}/{proto} ({svc_name})",
                    description=f"{svc_name} on port {port} is listening{' on all interfaces' if bind_all else ''}. {risk}",
                    severity=sev,
                    evidence=line.strip(),
                    remediation=f"Disable {svc_name} if not needed, or restrict to localhost binding.",
                ))

        findings.append(self._make_finding(
            title="Listening Services Summary",
            description=f"{len(listening_services)} listening ports detected.",
            severity=Severity.INFO,
            evidence="\n".join(listening_services[:30]),
        ))
        findings.extend(dangerous_found)

        return findings

    def _check_active_connections(self, errors: List[str]) -> List[Finding]:
        """Identify established connections, especially to external IPs."""
        findings = []

        output, _, rc = run_cmd("ss -tnp state established 2>/dev/null || netstat -tnp 2>/dev/null | grep ESTABLISHED")
        if not output:
            return findings

        lines = output.splitlines()
        external_connections = []

        for line in lines:
            parts = line.split()
            if len(parts) < 5:
                continue
            remote = parts[4] if len(parts) > 4 else parts[-1]
            remote_ip = remote.rsplit(":", 1)[0] if ":" in remote else remote

            # Check if remote IP is external
            is_private = any(remote_ip.startswith(prefix) for prefix in PRIVATE_PREFIXES)
            if not is_private and remote_ip not in ("", "0.0.0.0", "*"):
                external_connections.append(line.strip())

        if external_connections:
            findings.append(self._make_finding(
                title=f"External Connections: {len(external_connections)} active",
                description="Active connections to non-private IP addresses detected. Verify these are legitimate.",
                severity=Severity.MEDIUM,
                evidence="\n".join(external_connections[:20]),
                remediation="Audit each external connection. Block unauthorized outbound traffic with firewall rules.",
            ))

        return findings

    def _check_firewall(self, errors: List[str]) -> List[Finding]:
        """Analyze firewall configuration."""
        findings = []

        # Check iptables
        ipt_out, ipt_err, ipt_rc = run_cmd("iptables -L -n --line-numbers 2>/dev/null")

        if ipt_rc != 0 or not ipt_out:
            # Try nftables
            nft_out, _, nft_rc = run_cmd("nft list ruleset 2>/dev/null")
            if nft_rc != 0 or not nft_out:
                findings.append(self._make_finding(
                    title="No Firewall Detected",
                    description="Neither iptables nor nftables returned rules. The system may have no active firewall.",
                    severity=Severity.HIGH,
                    evidence=f"iptables: {ipt_err or 'not available'}\nnftables: not available",
                    remediation="Configure iptables or nftables with a default-deny inbound policy.",
                ))
                return findings
            else:
                findings.append(self._make_finding(
                    title="Firewall Rules (nftables)",
                    description="nftables firewall rules detected.",
                    severity=Severity.INFO,
                    evidence=nft_out[:2000],
                ))
                return findings

        # Parse iptables output
        lines = ipt_out.splitlines()

        # Check for default ACCEPT policies (dangerous)
        for line in lines:
            if "Chain" in line and "policy ACCEPT" in line:
                chain_name = line.split()[1] if len(line.split()) > 1 else "unknown"
                if chain_name in ("INPUT", "FORWARD"):
                    findings.append(self._make_finding(
                        title=f"Firewall Default ACCEPT Policy: {chain_name}",
                        description=f"The {chain_name} chain has a default ACCEPT policy, meaning all traffic is allowed unless explicitly denied.",
                        severity=Severity.HIGH,
                        evidence=line.strip(),
                        remediation=f"Set default policy to DROP: iptables -P {chain_name} DROP",
                    ))

        # Count rules
        rule_count = sum(1 for l in lines if l.strip() and not l.startswith("Chain") and "target" not in l.lower())
        findings.append(self._make_finding(
            title="Firewall Rules Summary",
            description=f"iptables has {rule_count} rules configured.",
            severity=Severity.INFO,
            evidence=ipt_out[:2000],
        ))

        return findings

    def _check_dns(self, errors: List[str]) -> List[Finding]:
        """Analyze DNS configuration."""
        findings = []
        resolv = read_file_lines("/etc/resolv.conf")

        if not resolv:
            errors.append("Cannot read /etc/resolv.conf")
            return findings

        nameservers = [l.split()[1] for l in resolv if l.startswith("nameserver") and len(l.split()) > 1]

        if nameservers:
            findings.append(self._make_finding(
                title="DNS Configuration",
                description=f"Configured nameservers: {', '.join(nameservers)}",
                severity=Severity.INFO,
                evidence="\n".join(resolv),
            ))

            # Flag if using public DNS on a supposedly private network
            public_dns = [ns for ns in nameservers
                          if not any(ns.startswith(p) for p in PRIVATE_PREFIXES)]
            if public_dns:
                findings.append(self._make_finding(
                    title="Public DNS Servers Configured",
                    description=f"Using public DNS resolvers: {', '.join(public_dns)}. DNS queries may be visible to third parties.",
                    severity=Severity.LOW,
                    evidence=f"Public nameservers: {', '.join(public_dns)}",
                    remediation="Consider using a local DNS resolver with DNSSEC or DNS-over-TLS.",
                ))

        return findings

    def _check_interfaces(self, errors: List[str]) -> List[Finding]:
        """List network interfaces and check for promiscuous mode."""
        findings = []

        ip_out, _, rc = run_cmd("ip -br addr 2>/dev/null || ifconfig -a 2>/dev/null")
        if ip_out:
            findings.append(self._make_finding(
                title="Network Interfaces",
                description="Active network interfaces and addresses.",
                severity=Severity.INFO,
                evidence=ip_out[:1500],
            ))

        # Check for promiscuous mode (may indicate packet sniffing)
        promisc_out, _, _ = run_cmd("ip link show 2>/dev/null | grep PROMISC")
        if promisc_out:
            findings.append(self._make_finding(
                title="Promiscuous Mode Interface Detected",
                description="One or more network interfaces are in promiscuous mode, which may indicate packet sniffing.",
                severity=Severity.HIGH,
                evidence=promisc_out,
                remediation="Disable promiscuous mode if not intentional: ip link set <iface> promisc off",
            ))

        # IP forwarding check
        fwd = read_file_lines("/proc/sys/net/ipv4/ip_forward")
        if fwd and fwd[0] == "1":
            findings.append(self._make_finding(
                title="IP Forwarding Enabled",
                description="IPv4 forwarding is enabled. This system can route packets between interfaces.",
                severity=Severity.MEDIUM,
                evidence="net.ipv4.ip_forward = 1",
                remediation="Disable if not needed: sysctl -w net.ipv4.ip_forward=0",
            ))

        return findings

    def _check_arp(self, errors: List[str]) -> List[Finding]:
        """Analyze ARP cache for potential poisoning."""
        findings = []

        arp_out, _, rc = run_cmd("ip neigh show 2>/dev/null || arp -an 2>/dev/null")
        if not arp_out:
            return findings

        lines = arp_out.splitlines()

        # Detect duplicate MAC addresses (ARP spoofing indicator)
        mac_to_ips: Dict[str, List[str]] = {}
        for line in lines:
            parts = line.split()
            mac = None
            ip = None
            for i, p in enumerate(parts):
                if re.match(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", p, re.IGNORECASE):
                    mac = p
                if re.match(r"\d+\.\d+\.\d+\.\d+", p):
                    ip = p
            if mac and ip:
                mac_to_ips.setdefault(mac, []).append(ip)

        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                findings.append(self._make_finding(
                    title="Potential ARP Spoofing Detected",
                    description=f"MAC address {mac} is associated with multiple IPs: {', '.join(ips)}. This may indicate ARP poisoning.",
                    severity=Severity.HIGH,
                    evidence=f"MAC: {mac} → IPs: {', '.join(ips)}",
                    remediation="Investigate with arp-scan. Use static ARP entries for critical hosts.",
                ))

        return findings
