"""
xping.core.logger
~~~~~~~~~~~~~~~~~~~~~
Structured logging with dual output: colored console + JSON-lines file.

Each module gets its own named logger via get_logger(module_name),
maintaining traceability in concurrent execution.
"""

import logging
import os
import sys
import json
from datetime import datetime
from typing import Optional


# ── JSON Formatter for File Logs ─────────────────────────────────────────

class JSONFormatter(logging.Formatter):
    """Emit each log record as a single JSON line for machine parsing."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False)


# ── Colored Console Formatter ────────────────────────────────────────────

class ColoredFormatter(logging.Formatter):
    """ANSI-colored log output for terminal readability."""

    COLORS = {
        logging.DEBUG:    "\033[36m",    # Cyan
        logging.INFO:     "\033[92m",    # Green
        logging.WARNING:  "\033[93m",    # Yellow
        logging.ERROR:    "\033[91m",    # Red
        logging.CRITICAL: "\033[41;97m", # White on Red bg
    }
    RESET = "\033[0m"

    def __init__(self, use_color: bool = True):
        super().__init__()
        self.use_color = use_color and sys.stderr.isatty()

    def format(self, record: logging.LogRecord) -> str:
        level = record.levelname.ljust(8)
        module = record.name.split(".")[-1].ljust(12)
        msg = record.getMessage()

        if self.use_color:
            color = self.COLORS.get(record.levelno, "")
            return f"{color}{level}{self.RESET} │ {module} │ {msg}"
        return f"{level} │ {module} │ {msg}"


# ── Logger Setup ─────────────────────────────────────────────────────────

_initialized = False


def setup_logging(
    log_file: Optional[str] = None,
    verbose: bool = False,
    no_color: bool = False
) -> None:
    """
    Initialize the logging system. Call once at startup.

    Args:
        log_file: Path to write JSON-lines log file. None = no file logging.
        verbose:  If True, set console level to DEBUG.
        no_color: If True, disable ANSI colors in console output.
    """
    global _initialized
    if _initialized:
        return
    _initialized = True

    root = logging.getLogger("XPing")
    root.setLevel(logging.DEBUG)

    # Prevent duplicate handlers on re-import
    root.handlers.clear()

    # Console handler (stderr so stdout stays clean for piping)
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(ColoredFormatter(use_color=not no_color))
    root.addHandler(console)

    # File handler (JSON lines)
    if log_file:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(JSONFormatter())
            root.addHandler(fh)
        except (OSError, PermissionError) as e:
            root.warning(f"Cannot write log file {log_file}: {e}")


def get_logger(name: str) -> logging.Logger:
    """
    Get a named child logger under the XPing namespace.

    Usage:
        log = get_logger("sysrecon")
        log.info("Scanning users...")
    """
    return logging.getLogger(f"xping.{name}")
