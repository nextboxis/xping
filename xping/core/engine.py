"""
xping.core.engine
~~~~~~~~~~~~~~~~~~~~~
Central orchestrator that discovers, loads, and executes analysis modules
in parallel using ThreadPoolExecutor.

Design decisions:
  - Parallel execution via threads (not processes) because modules are
    I/O-bound (reading files, running commands), not CPU-bound.
  - Dynamic module discovery allows adding new modules by simply dropping
    a file into XPing/modules/ without modifying this file.
  - Each module runs in isolation; a crash in one module never kills others.
"""

import os
import time
import uuid
import platform
import importlib
import pkgutil
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Dict, Type

from xping.core.models import ScanResult, ModuleResult, Severity
from xping.core.logger import get_logger
from xping.modules.base import BaseModule
from xping.utils.helpers import run_cmd, is_root

log = get_logger("engine")


class ScanEngine:
    """
    Discovers and orchestrates analysis modules.

    Usage:
        engine = ScanEngine()
        result = engine.run_scan()
    """

    def __init__(
        self,
        modules: Optional[List[str]] = None,
        max_workers: int = 4,
        severity_threshold: Severity = Severity.INFO,
    ):
        """
        Args:
            modules:             List of module names to run. None = all.
            max_workers:         Thread pool size for parallel execution.
            severity_threshold:  Only include findings at or above this level.
        """
        self.requested_modules = modules
        self.max_workers = max_workers
        self.severity_threshold = severity_threshold
        # Map of module_name -> module_class, populated by _discover_modules()
        self._registry: Dict[str, Type[BaseModule]] = {}
        self._discover_modules()

    def _discover_modules(self) -> None:
        """
        Dynamically import all modules from xping.modules package
        and register any class that inherits from BaseModule.

        Why dynamic discovery:
            Adding a new analysis module requires zero changes to existing
            code — just create a new file in XPing/modules/.
        """
        import xping.modules as modules_pkg

        package_path = os.path.dirname(modules_pkg.__file__)

        for _, module_name, _ in pkgutil.iter_modules([package_path]):
            if module_name in ("__init__", "base"):
                continue
            try:
                mod = importlib.import_module(f"xping.modules.{module_name}")
                # Find all BaseModule subclasses in the imported module
                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseModule)
                        and attr is not BaseModule
                    ):
                        instance = attr()
                        self._registry[instance.name] = attr
                        log.debug(f"Registered module: {instance.name}")
            except Exception as e:
                log.error(f"Failed to load module '{module_name}': {e}")

    def _get_modules_to_run(self) -> List[BaseModule]:
        """Resolve which modules to execute based on user selection."""
        if self.requested_modules:
            selected = []
            for name in self.requested_modules:
                name = name.strip().lower()
                if name in self._registry:
                    selected.append(self._registry[name]())
                else:
                    log.warning(f"Unknown module '{name}'. Available: {list(self._registry.keys())}")
            return selected
        # Default: all registered modules
        return [cls() for cls in self._registry.values()]

    def _run_single_module(self, module: BaseModule) -> ModuleResult:
        """
        Execute a single module with full error isolation.
        A module crash returns a ModuleResult with the error recorded,
        never propagates exceptions to the engine.
        """
        log.info(f"Starting module: {module.name}")
        start = time.monotonic()

        try:
            # Check if module can run in the current environment
            if not module.is_available():
                elapsed = time.monotonic() - start
                log.warning(f"Module '{module.name}' skipped: not available in this environment")
                return ModuleResult(
                    module_name=module.name,
                    description=module.description,
                    execution_time=elapsed,
                    skipped=True,
                    skip_reason="Module prerequisites not met (missing commands or permissions)",
                )

            result = module.run()
            result.execution_time = time.monotonic() - start

            # Apply severity filter
            if self.severity_threshold > Severity.INFO:
                result.findings = [
                    f for f in result.findings
                    if f.severity >= self.severity_threshold
                ]

            finding_count = len(result.findings)
            crit_count = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
            log.info(
                f"Completed module: {module.name} — "
                f"{finding_count} findings ({crit_count} critical) "
                f"in {result.execution_time:.2f}s"
            )
            return result

        except Exception as e:
            elapsed = time.monotonic() - start
            log.error(f"Module '{module.name}' crashed: {e}", exc_info=True)
            return ModuleResult(
                module_name=module.name,
                description=module.description,
                execution_time=elapsed,
                errors=[f"Module crashed: {type(e).__name__}: {e}"],
            )

    def _collect_system_info(self) -> Dict[str, str]:
        """Gather basic system metadata for the scan header."""
        hostname_out, _, _ = run_cmd("hostname", timeout=5)
        kernel_out, _, _ = run_cmd("uname -r", timeout=5)
        return {
            "hostname": hostname_out or platform.node(),
            "kernel": kernel_out or platform.release(),
        }

    def run_scan(self) -> ScanResult:
        """
        Execute the full scan pipeline:
        1. Collect system metadata
        2. Run all selected modules in parallel
        3. Aggregate results into ScanResult
        """
        scan_start = time.monotonic()
        log.info("=" * 60)
        log.info("XPing scan initiated")
        log.info(f"Running as: {'root' if is_root() else 'unprivileged user'}")
        log.info("=" * 60)

        sys_info = self._collect_system_info()
        modules = self._get_modules_to_run()

        if not modules:
            log.error("No modules to execute. Aborting scan.")
            return ScanResult(
                scan_id=str(uuid.uuid4())[:8],
                timestamp=datetime.now(timezone.utc).isoformat(),
                hostname=sys_info.get("hostname", "unknown"),
                kernel=sys_info.get("kernel", "unknown"),
                run_as_root=is_root(),
                total_execution_time=time.monotonic() - scan_start,
            )

        log.info(f"Executing {len(modules)} modules: {[m.name for m in modules]}")

        # Parallel execution with thread pool
        results: List[ModuleResult] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_to_module = {
                pool.submit(self._run_single_module, mod): mod
                for mod in modules
            }
            for future in as_completed(future_to_module):
                mod = future_to_module[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    log.error(f"Unexpected error collecting result from {mod.name}: {e}")
                    results.append(ModuleResult(
                        module_name=mod.name,
                        errors=[f"Result collection failed: {e}"],
                    ))

        # Sort results by module name for consistent output
        results.sort(key=lambda r: r.module_name)

        total_time = time.monotonic() - scan_start
        scan_result = ScanResult(
            scan_id=str(uuid.uuid4())[:8],
            timestamp=datetime.now(timezone.utc).isoformat(),
            hostname=sys_info.get("hostname", "unknown"),
            kernel=sys_info.get("kernel", "unknown"),
            run_as_root=is_root(),
            module_results=results,
            total_execution_time=total_time,
        )

        log.info("=" * 60)
        log.info(
            f"Scan complete — {scan_result.total_findings} findings, "
            f"overall risk: {scan_result.overall_risk}, "
            f"time: {total_time:.2f}s"
        )
        log.info("=" * 60)

        return scan_result

    def list_modules(self) -> List[Dict[str, str]]:
        """List all registered modules with descriptions."""
        return [
            {"name": name, "description": cls().description}
            for name, cls in sorted(self._registry.items())
        ]
