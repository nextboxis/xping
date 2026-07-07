"""
xping.modules.base
~~~~~~~~~~~~~~~~~~~~~~
Abstract base class for all analysis modules.

Every module must implement:
  - name:         Machine-readable identifier (lowercase, no spaces)
  - description:  Human-readable one-liner
  - run():        Execute analysis and return ModuleResult
  - is_available(): Check if prerequisites are met
"""

import abc
from xping.core.models import ModuleResult, Finding, Severity


class BaseModule(abc.ABC):
    """Abstract base for XPing analysis modules."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Machine-readable module identifier."""
        ...

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Human-readable one-line description."""
        ...

    @abc.abstractmethod
    def run(self) -> ModuleResult:
        """
        Execute the module's analysis.

        Returns:
            ModuleResult containing all findings, errors, and timing.
        """
        ...

    def is_available(self) -> bool:
        """
        Check whether this module can run in the current environment.
        Override to check for required commands, files, or permissions.
        Default: always available.
        """
        return True

    def _make_finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        evidence: str = "",
        remediation: str = "",
        cve_refs: list = None,
        **metadata,
    ) -> Finding:
        """Convenience method to create a Finding pre-populated with module name."""
        return Finding(
            module=self.name,
            title=title,
            description=description,
            severity=severity,
            evidence=evidence,
            remediation=remediation,
            cve_refs=cve_refs or [],
            metadata=metadata,
        )
