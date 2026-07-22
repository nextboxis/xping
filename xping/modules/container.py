"""
xping.modules.container
~~~~~~~~~~~~~~~~~~~~~~
Container & Cloud Security Analysis Module.

Audits:
  - Docker/Podman socket permissions (/var/run/docker.sock)
  - Exposed Docker daemon TCP ports (2375, 2376)
  - Container environment & privileged container execution detection
  - Cloud provider IMDS (AWS/GCP/Azure) accessibility
  - Plaintext cloud CLI credential files (~/.aws, ~/.gcp, ~/.azure)
"""

import os
import stat
from pathlib import Path
from typing import List, Optional

from xping.modules.base import BaseModule
from xping.core.models import ModuleResult, Finding, Severity
from xping.utils.helpers import run_cmd, read_file_lines


class ContainerModule(BaseModule):
    """Audits container configurations, Docker daemon sockets, and cloud metadata access."""

    @property
    def name(self) -> str:
        return "container"

    @property
    def description(self) -> str:
        return "Container runtime, Docker socket, and Cloud IMDS security audit"

    def is_available(self) -> bool:
        # Runs on all platforms with non-destructive read-only checks
        return True

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, description=self.description)

        self._check_docker_socket(result)
        self._check_docker_tcp_ports(result)
        self._check_container_environment(result)
        self._check_cloud_credentials(result)
        self._check_cloud_imds(result)

        return result

    def _check_docker_socket(self, result: ModuleResult) -> None:
        """Check for dangerously permissive Docker socket file permissions."""
        sock_paths = [
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/var/run/podman/podman.sock",
        ]

        for path in sock_paths:
            if not os.path.exists(path):
                continue

            try:
                st = os.stat(path)
                mode = st.st_mode
                
                # Check world writeable
                if mode & stat.S_IWOTH:
                    result.findings.append(
                        self._make_finding(
                            title=f"World-Writable Container Socket ({os.path.basename(path)})",
                            description=f"The container socket at {path} is world-writable. Any local user can gain root access via Docker API.",
                            severity=Severity.CRITICAL,
                            evidence=f"Permissions: {oct(mode)}, Path: {path}",
                            remediation=f"Restrict socket permissions: sudo chmod 660 {path} && sudo chown root:docker {path}",
                            cis_tag="CIS Docker 2.1",
                            nist_tag="NIST AC-6",
                        )
                    )
                # Check non-root group access
                elif mode & stat.S_IWGRP:
                    result.findings.append(
                        self._make_finding(
                            title=f"Group-Writable Container Socket ({os.path.basename(path)})",
                            description=f"The container socket at {path} is group-writable. Users in the socket group have root-equivalent privileges.",
                            severity=Severity.HIGH,
                            evidence=f"Permissions: {oct(mode)}, Path: {path}",
                            remediation="Audit group membership for docker/podman groups and grant access strictly to authorized administrators.",
                            cis_tag="CIS Docker 2.2",
                            nist_tag="NIST AC-6",
                        )
                    )
            except Exception as e:
                result.errors.append(f"Failed to check socket stat on {path}: {e}")

    def _check_docker_tcp_ports(self, result: ModuleResult) -> None:
        """Check if Docker daemon TCP listener ports are active."""
        ss_out, _, code = run_cmd("ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null", timeout=5)
        if not ss_out or code != 0:
            return

        lines = ss_out.splitlines()
        for line in lines:
            if ":2375 " in line or ":2375\t" in line:
                result.findings.append(
                    self._make_finding(
                        title="Unencrypted Docker TCP Socket Listener Detected (Port 2375)",
                        description="Docker daemon is listening on TCP port 2375 without TLS authentication. Remote unauthenticated users can execute arbitrary commands as root.",
                        severity=Severity.CRITICAL,
                        evidence=line.strip(),
                        remediation="Disable TCP listening in /etc/docker/daemon.json or bind strictly to 127.0.0.1 with TLS (port 2376).",
                        cis_tag="CIS Docker 2.3",
                        nist_tag="NIST SC-8",
                    )
                )
            elif ":2376 " in line or ":2376\t" in line:
                result.findings.append(
                    self._make_finding(
                        title="TLS Docker TCP Socket Listener Active (Port 2376)",
                        description="Docker daemon TCP port 2376 is listening. Ensure TLS mutual authentication (client certificates) is strictly enforced.",
                        severity=Severity.MEDIUM,
                        evidence=line.strip(),
                        remediation="Verify docker daemon tlsverify configuration in /etc/docker/daemon.json.",
                        cis_tag="CIS Docker 2.4",
                        nist_tag="NIST SC-8",
                    )
                )

    def _check_container_environment(self, result: ModuleResult) -> None:
        """Detect if executing inside a container and evaluate privilege state."""
        in_container = False
        container_type = ""

        if os.path.exists("/.dockerenv"):
            in_container = True
            container_type = "Docker"
        elif os.path.exists("/run/secrets/kubernetes.io"):
            in_container = True
            container_type = "Kubernetes"

        cgroup_lines = read_file_lines("/proc/1/cgroup")
        if cgroup_lines:
            for line in cgroup_lines:
                if "docker" in line:
                    in_container = True
                    container_type = container_type or "Docker"
                    break
                elif "kubepods" in line:
                    in_container = True
                    container_type = container_type or "Kubernetes"
                    break

        if in_container:
            result.findings.append(
                self._make_finding(
                    title=f"Running Inside {container_type} Container",
                    description=f"System environment is executing inside a {container_type} container workload.",
                    severity=Severity.INFO,
                    evidence=f"Container type: {container_type}",
                    remediation="Ensure container runs with non-root user and minimal Linux capabilities.",
                )
            )

            # Check if privileged container
            devices = os.listdir("/dev") if os.path.exists("/dev") else []
            if "kmsg" in devices or "mem" in devices:
                result.findings.append(
                    self._make_finding(
                        title="Privileged Container Execution Detected",
                        description="Container appears to be running with --privileged flag. Direct device node access (/dev/kmsg, /dev/mem) permits container escape.",
                        severity=Severity.CRITICAL,
                        evidence="Host device nodes present in container filesystem.",
                        remediation="Drop --privileged flag and grant specific capabilities via --cap-add instead.",
                        cis_tag="CIS Docker 5.4",
                        nist_tag="NIST AC-6",
                    )
                )

    def _check_cloud_credentials(self, result: ModuleResult) -> None:
        """Check home directories for unencrypted cloud provider credentials."""
        home = Path.home()
        cloud_files = [
            (home / ".aws" / "credentials", "AWS Credentials File"),
            (home / ".aws" / "config", "AWS Config File"),
            (home / ".azure" / "azureProfile.json", "Azure Profile Configuration"),
            (home / ".gcp" / "credentials.db", "GCP Credentials Database"),
            (home / ".config" / "gcloud" / "credentials.db", "Google Cloud CLI Credentials"),
        ]

        for file_path, label in cloud_files:
            if file_path.exists() and file_path.is_file():
                try:
                    mode = file_path.stat().st_mode
                    is_readable_by_others = bool(mode & stat.S_IROTH)
                    sev = Severity.HIGH if is_readable_by_others else Severity.LOW

                    result.findings.append(
                        self._make_finding(
                            title=f"Unencrypted {label} Found ({file_path.name})",
                            description=f"{label} located at {file_path}. Ensure access permissions are restricted.",
                            severity=sev,
                            evidence=f"Path: {file_path}, Permissions: {oct(mode)}",
                            remediation=f"Restrict permissions: chmod 600 {file_path}",
                            nist_tag="NIST IA-2",
                        )
                    )
                except Exception as e:
                    result.errors.append(f"Error checking cloud credential file {file_path}: {e}")

    def _check_cloud_imds(self, result: ModuleResult) -> None:
        """Check accessibility of Cloud Instance Metadata Service (IMDS)."""
        # Read-only curl check with 2s timeout
        imds_url = "http://169.254.169.254/latest/meta-data/"
        curl_out, _, code = run_cmd(
            f"curl -s --connect-timeout 2 -m 2 -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' '{imds_url}' 2>/dev/null",
            timeout=3,
        )

        if code == 0 and curl_out and len(curl_out) > 0:
            result.findings.append(
                self._make_finding(
                    title="Cloud Instance Metadata Service (IMDS) Accessible",
                    description="The Cloud Metadata Service (169.254.169.254) is reachable from this system. Ensure IMDSv2 is enforced to mitigate SSRF exposure.",
                    severity=Severity.MEDIUM,
                    evidence=f"IMDS HTTP Response Length: {len(curl_out)} bytes",
                    remediation="Require IMDSv2 (token-based header) and disable IMDSv1 on AWS EC2 instances.",
                    cis_tag="CIS AWS 1.6",
                    nist_tag="NIST SC-7",
                )
            )
