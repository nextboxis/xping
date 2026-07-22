"""
xping.core.models
~~~~~~~~~~~~~~~~~~~~~
Data models for findings, severity levels, and module results.

Uses dataclasses for clean serialization and type safety.
Enum-based severity ensures consistent ordering and comparison.
"""

import enum
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any


class Severity(enum.IntEnum):
    """
    Severity levels ordered by impact (highest = most critical).
    IntEnum allows direct comparison: Severity.CRITICAL > Severity.LOW
    """
    INFO     = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4

    @classmethod
    def from_string(cls, s: str) -> "Severity":
        """Parse severity from string, defaulting to INFO on unknown input."""
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO,
        }
        return mapping.get(s.lower().strip(), cls.INFO)


@dataclass
class Finding:
    """
    A single security finding produced by an analysis module.

    Attributes:
        module:       Name of the module that generated this finding.
        title:        Short, descriptive title (used in reports).
        description:  Detailed explanation of the issue.
        severity:     Impact level (CRITICAL → INFO).
        evidence:     Raw data supporting the finding (command output, file contents).
        remediation:  Actionable fix instructions.
        cve_refs:     Optional list of related CVE identifiers.
        metadata:     Arbitrary key-value pairs for module-specific data.
    """
    module: str
    title: str
    description: str
    severity: Severity
    evidence: str = ""
    remediation: str = ""
    cve_refs: List[str] = field(default_factory=list)
    cis_tag: str = ""
    nist_tag: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON export."""
        d = asdict(self)
        d["severity"] = self.severity.name
        return d

    @property
    def severity_score(self) -> int:
        return int(self.severity)


@dataclass
class ModuleResult:
    """
    Aggregated output from a single analysis module run.

    Attributes:
        module_name:    Identifier of the module.
        description:    What the module analyzes.
        findings:       List of security findings.
        execution_time: Wall-clock seconds the module took.
        errors:         Any non-fatal errors encountered.
        skipped:        Whether the module was skipped (e.g., missing perms).
        skip_reason:    Why the module was skipped.
    """
    module_name: str
    description: str = ""
    findings: List[Finding] = field(default_factory=list)
    execution_time: float = 0.0
    errors: List[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for JSON export."""
        return {
            "module_name": self.module_name,
            "description": self.description,
            "findings": [f.to_dict() for f in self.findings],
            "finding_count": len(self.findings),
            "critical_count": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
            "high_count": sum(1 for f in self.findings if f.severity == Severity.HIGH),
            "execution_time": round(self.execution_time, 3),
            "errors": self.errors,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
        }

    @property
    def has_critical(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)


@dataclass
class ScanResult:
    """
    Top-level container for an entire XPing scan.
    """
    scan_id: str = ""
    timestamp: str = ""
    hostname: str = ""
    target_ip: str = ""
    kernel: str = ""
    run_as_root: bool = False
    module_results: List[ModuleResult] = field(default_factory=list)
    total_execution_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        all_findings = []
        for mr in self.module_results:
            all_findings.extend(mr.findings)

        severity_counts = {s.name: 0 for s in Severity}
        for f in all_findings:
            severity_counts[f.severity.name] += 1

        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "target_ip": self.target_ip,
            "kernel": self.kernel,
            "run_as_root": self.run_as_root,
            "total_findings": len(all_findings),
            "severity_summary": severity_counts,
            "total_execution_time": round(self.total_execution_time, 3),
            "modules": [mr.to_dict() for mr in self.module_results],
        }

    @property
    def total_findings(self) -> int:
        return sum(len(mr.findings) for mr in self.module_results)

    @property
    def overall_risk(self) -> str:
        """Compute overall risk rating from findings."""
        crits = sum(1 for mr in self.module_results for f in mr.findings if f.severity == Severity.CRITICAL)
        highs = sum(1 for mr in self.module_results for f in mr.findings if f.severity == Severity.HIGH)
        if crits > 0:
            return "CRITICAL"
        elif highs >= 3:
            return "HIGH"
        elif highs > 0:
            return "MEDIUM"
        else:
            return "LOW"
