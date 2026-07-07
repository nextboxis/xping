"""
xping.utils.helpers
~~~~~~~~~~~~~~~~~~~~~~~
Low-level utility functions for safe command execution, file reading,
user parsing, and terminal formatting.

Design decisions:
  - All shell commands go through run_cmd() which enforces timeouts and
    captures stderr separately so callers can distinguish clean output
    from error diagnostics.
  - File reads never raise on permission errors; they return None so
    callers can degrade gracefully without try/except clutter.
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import Optional, List, Dict, Tuple

try:
    import pwd
    import grp
    HAS_PWD_GRP = True
except ImportError:
    HAS_PWD_GRP = False
import builtins

def safe_print(*args, sep=" ", end="\n", file=None):
    if file is None:
        file = sys.stdout
    try:
        builtins_print(*args, sep=sep, end=end, file=file)
    except UnicodeEncodeError:
        encoding = getattr(file, "encoding", "utf-8") or "utf-8"
        text = sep.join(str(arg) for arg in args) + end
        file.write(text.encode(encoding, errors="replace").decode(encoding))
        file.flush()

builtins_print = builtins.print
builtins.print = safe_print



# ── Terminal Colors ──────────────────────────────────────────────────────

class Colors:
    """ANSI escape codes for terminal output. Disabled when not a TTY."""

    _enabled: bool = sys.stdout.isatty()

    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"

    @classmethod
    def disable(cls) -> None:
        cls._enabled = False

    @classmethod
    def colorize(cls, text: str, color: str) -> str:
        if not cls._enabled:
            return text
        return f"{color}{text}{cls.RESET}"


def ansi_color(text: str, color: str) -> str:
    """Wrap text in ANSI color codes."""
    return Colors.colorize(text, color)


# ── Safe Command Execution ──────────────────────────────────────────────

def run_cmd(
    cmd: str,
    timeout: int = 30,
    shell: bool = True,
    suppress_errors: bool = False
) -> Tuple[Optional[str], Optional[str], int]:
    """
    Execute a shell command safely with timeout enforcement.

    Returns:
        (stdout, stderr, returncode) — stdout/stderr are None on exception.

    Why shell=True by default:
        Many audit commands use pipes, redirects, and glob expansion.
        We accept the trade-off because all commands are hardcoded by
        XPing modules, never from user input.
    """
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        if not suppress_errors:
            pass  # Logged by caller
        return None, f"Command timed out after {timeout}s: {cmd}", -1
    except FileNotFoundError:
        return None, f"Command not found: {cmd}", -1
    except Exception as e:
        return None, f"Command execution error: {e}", -1


def run_cmd_lines(cmd: str, timeout: int = 30) -> List[str]:
    """Execute command and return stdout split into non-empty lines."""
    stdout, _, rc = run_cmd(cmd, timeout=timeout)
    if stdout and rc == 0:
        return [line for line in stdout.splitlines() if line.strip()]
    return []


# ── Safe File Operations ────────────────────────────────────────────────

def read_file_safe(path: str, max_lines: int = 0) -> Optional[str]:
    """
    Read file contents with graceful failure on permission/missing errors.

    Args:
        path: Absolute or relative path to read.
        max_lines: If > 0, read only this many lines (for large log files).

    Returns:
        File contents as string, or None if unreadable.
    """
    try:
        fpath = Path(path)
        if not fpath.exists():
            return None
        if not os.access(str(fpath), os.R_OK):
            return None
        with open(fpath, "r", errors="replace") as f:
            if max_lines > 0:
                lines = []
                for i, line in enumerate(f):
                    if i >= max_lines:
                        break
                    lines.append(line)
                return "".join(lines)
            return f.read()
    except (PermissionError, OSError, IOError):
        return None


def read_file_lines(path: str, max_lines: int = 0) -> List[str]:
    """Read file and return non-empty stripped lines."""
    content = read_file_safe(path, max_lines=max_lines)
    if content is None:
        return []
    return [line.strip() for line in content.splitlines() if line.strip()]


# ── System Information Helpers ───────────────────────────────────────────

def is_root() -> bool:
    """Check if running as root (UID 0)."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows admin check fallback
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False


def get_current_user() -> str:
    """Get the username of the current process."""
    if HAS_PWD_GRP:
        try:
            return pwd.getpwuid(os.getuid()).pw_name
        except (KeyError, AttributeError):
            pass
    return os.environ.get("USER", os.environ.get("USERNAME", "unknown"))


def parse_passwd() -> List[Dict[str, str]]:
    """
    Parse /etc/passwd into structured records.

    Returns list of dicts with keys:
        username, password, uid, gid, comment, home, shell
    """
    records = []
    lines = read_file_lines("/etc/passwd")
    for line in lines:
        parts = line.split(":")
        if len(parts) >= 7:
            records.append({
                "username": parts[0],
                "password": parts[1],
                "uid": parts[2],
                "gid": parts[3],
                "comment": parts[4],
                "home": parts[5],
                "shell": parts[6],
            })
    return records


def parse_group() -> List[Dict[str, str]]:
    """Parse /etc/group into structured records."""
    records = []
    lines = read_file_lines("/etc/group")
    for line in lines:
        parts = line.split(":")
        if len(parts) >= 4:
            records.append({
                "name": parts[0],
                "password": parts[1],
                "gid": parts[2],
                "members": parts[3],
            })
    return records


def file_permissions_octal(path: str) -> Optional[str]:
    """Get file permissions in octal format (e.g., '0644')."""
    try:
        stat = os.stat(path)
        return oct(stat.st_mode)[-4:]
    except (OSError, FileNotFoundError):
        return None


def file_owner(path: str) -> Optional[Tuple[str, str]]:
    """Get (owner_name, group_name) for a file."""
    if not HAS_PWD_GRP:
        return None
    try:
        stat = os.stat(path)
        owner = pwd.getpwuid(stat.st_uid).pw_name
        group = grp.getgrgid(stat.st_gid).gr_name
        return owner, group
    except (OSError, KeyError, AttributeError, FileNotFoundError):
        return None


def format_bytes(num_bytes: int) -> str:
    """Human-readable byte formatting."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def severity_icon(severity: str) -> str:
    """Return a colored icon for severity level."""
    icons = {
        "CRITICAL": ansi_color("⬤ CRITICAL", Colors.BG_RED + Colors.WHITE),
        "HIGH":     ansi_color("● HIGH", Colors.RED),
        "MEDIUM":   ansi_color("◉ MEDIUM", Colors.YELLOW),
        "LOW":      ansi_color("○ LOW", Colors.BLUE),
        "INFO":     ansi_color("· INFO", Colors.DIM),
    }
    return icons.get(severity.upper(), severity)
