"""
xping.cli
~~~~~~~~~
Custom interactive CLI interface for XPing.

Features:
  - ASCII art banner with gradient coloring
  - Custom argument parser (no argparse dependency)
  - Interactive menu mode when run without arguments
  - Live scan progress with spinner animation
  - Module selection & Target IP configuration
  - Security drift analysis (`xping diff`)
  - SARIF v2.1.0 GitHub Security integration & automated fix script generation
  - External custom plugin module loading

Usage:
    python3 run.py                                           # Interactive mode
    python3 run.py scan --all                                # Full scan
    python3 run.py scan --all -t 192.168.1.50                # Target IP scan
    python3 run.py scan -m sysrecon,container                # Specific modules
    python3 run.py scan --all -f html -o report.html         # HTML report
    python3 run.py scan --all -f sarif -o report.sarif       # SARIF export
    python3 run.py scan --all --generate-fix fix.sh          # Remediation script
    python3 run.py diff baseline.json current.json           # Security drift analysis
    python3 run.py list                                      # List modules
"""

import sys
import os
import time
import threading
from typing import List, Optional, Dict, Tuple, Any

from xping import __version__
from xping.core.logger import setup_logging, get_logger
from xping.core.models import Severity


# ═══════════════════════════════════════════════════════════════════════
# Terminal Rendering Primitives
# ═══════════════════════════════════════════════════════════════════════

def _supports_unicode() -> bool:
    """Check if the terminal can render Unicode box-drawing characters."""
    encoding = getattr(sys.stdout, "encoding", "") or ""
    return encoding.lower().replace("-", "") in ("utf8", "utf16", "utf32", "utf8sig")


class Term:
    """Low-level terminal output with ANSI support detection."""

    _color_enabled: bool = sys.stdout.isatty()

    # Colors
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITALIC  = "\033[3m"
    ULINE   = "\033[4m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BG_RED  = "\033[41m"
    BG_BLUE = "\033[44m"
    BG_CYAN = "\033[46m"
    BG_GRAY = "\033[100m"

    # Box-drawing characters — Unicode if supported, ASCII fallback
    if _supports_unicode():
        TL = "╭"  # top-left
        TR = "╮"  # top-right
        BL = "╰"  # bottom-left
        BR = "╯"  # bottom-right
        H  = "─"  # horizontal
        V  = "│"  # vertical
        LT = "├"  # left-T
        RT = "┤"  # right-T
    else:
        TL = "+"
        TR = "+"
        BL = "+"
        BR = "+"
        H  = "-"
        V  = "|"
        LT = "+"
        RT = "+"

    @classmethod
    def disable_color(cls) -> None:
        cls._color_enabled = False

    @classmethod
    def c(cls, text: str, *styles: str) -> str:
        """Colorize text with one or more ANSI styles."""
        if not cls._color_enabled:
            return text
        prefix = "".join(styles)
        return f"{prefix}{text}{cls.RESET}"

    @classmethod
    def write(cls, text: str = "") -> None:
        """Write to stdout without newline."""
        try:
            sys.stdout.write(text)
            sys.stdout.flush()
        except UnicodeEncodeError:
            encoding = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"
            sys.stdout.write(text.encode(encoding, errors="replace").decode(encoding))
            sys.stdout.flush()

    @classmethod
    def writeln(cls, text: str = "") -> None:
        """Write line to stdout."""
        print(text)

    @classmethod
    def clear_line(cls) -> None:
        """Clear the current terminal line."""
        cls.write("\r\033[K")

    @classmethod
    def hide_cursor(cls) -> None:
        if cls._color_enabled:
            cls.write("\033[?25l")

    @classmethod
    def show_cursor(cls) -> None:
        if cls._color_enabled:
            cls.write("\033[?25h")


# ═══════════════════════════════════════════════════════════════════════
# ASCII Art Banner
# ═══════════════════════════════════════════════════════════════════════

BANNER_LINES = [
    r"__  ______  _             ",
    r"\ \/ /  _ \(_)_ __   __ _ ",
    r" \  /| |_) | | '_ \ / _` |",
    r" /  \|  __/| | | | | (_| |",
    r"/_/\_\_|   |_|_| |_|\__, |",
    r"                    |___/ ",
]

TAGLINE = "All-in-One Linux Security & Systems Analysis Toolkit"


def print_banner() -> None:
    """Display the XPing ASCII art banner with gradient coloring."""
    gradient = [Term.CYAN, Term.BLUE, Term.MAGENTA, Term.BLUE, Term.CYAN, Term.BLUE]
    Term.writeln()
    for i, line in enumerate(BANNER_LINES):
        color = gradient[i % len(gradient)]
        Term.writeln(f"  {Term.c(line, color, Term.BOLD)}")
    Term.writeln(f"  {Term.c(TAGLINE, Term.DIM)}")
    Term.writeln(f"  {Term.c(f'v{__version__}', Term.CYAN)} {Term.c('|', Term.DIM)} {Term.c('Python ' + sys.version.split()[0], Term.DIM)}")
    Term.writeln()


# ═══════════════════════════════════════════════════════════════════════
# Custom Argument Parser
# ═══════════════════════════════════════════════════════════════════════

class ParsedArgs:
    """Container for parsed command-line arguments."""

    def __init__(self):
        self.command: Optional[str] = None
        self.all: bool = False
        self.modules: Optional[str] = None
        self.target: Optional[str] = None
        self.format: str = "terminal"
        self.output: Optional[str] = None
        self.severity: str = "info"
        self.workers: int = 4
        self.log_file: Optional[str] = None
        self.verbose: bool = False
        self.no_color: bool = False
        self.version: bool = False
        self.help: bool = False
        self.interactive: bool = False
        self.generate_fix: Optional[str] = None
        self.custom_modules_dir: Optional[str] = None
        self.diff_files: List[str] = []


def parse_args(argv: List[str]) -> ParsedArgs:
    """
    Custom argument parser — no argparse dependency.

    Supports both long (--flag) and short (-f) forms.
    Handles positional commands (scan, list, diff) and key=value style.
    """
    args = ParsedArgs()

    # Flag definitions: (long, short, attr_name, expects_value, type)
    flags = [
        ("--all",                "-a",  "all",                False, bool),
        ("--modules",            "-m",  "modules",            True,  str),
        ("--target",             "-t",  "target",             True,  str),
        ("--target-ip",          None,  "target",             True,  str),
        ("--format",             "-f",  "format",             True,  str),
        ("--output",             "-o",  "output",             True,  str),
        ("--severity",           "-s",  "severity",           True,  str),
        ("--workers",            "-w",  "workers",            True,  int),
        ("--log-file",           None,  "log_file",           True,  str),
        ("--verbose",            "-v",  "verbose",            False, bool),
        ("--no-color",           None,  "no_color",           False, bool),
        ("--version",            "-V",  "version",            False, bool),
        ("--help",               "-h",  "help",               False, bool),
        ("--generate-fix",       None,  "generate_fix",       True,  str),
        ("--custom-modules-dir", None,  "custom_modules_dir", True,  str),
    ]

    # Build lookup tables
    flag_by_name: Dict[str, Tuple[str, bool, type]] = {}
    for long, short, attr, expects_val, typ in flags:
        flag_by_name[long] = (attr, expects_val, typ)
        if short:
            flag_by_name[short] = (attr, expects_val, typ)

    i = 0
    while i < len(argv):
        token = argv[i]

        if token in flag_by_name:
            attr, expects_val, typ = flag_by_name[token]
            if expects_val:
                if i + 1 >= len(argv):
                    Term.writeln(Term.c(f"  Error: {token} requires a value", Term.RED))
                    sys.exit(1)
                i += 1
                val = argv[i]
                if typ == int:
                    try:
                        val = int(val)
                    except ValueError:
                        Term.writeln(Term.c(f"  Error: {token} expects an integer, got '{val}'", Term.RED))
                        sys.exit(1)
                setattr(args, attr, val)
            else:
                setattr(args, attr, True)

        elif token in ("scan", "list", "diff"):
            args.command = token
            if token == "diff":
                # Remaining positional tokens are baseline and current JSON file paths
                i += 1
                while i < len(argv) and not argv[i].startswith("-"):
                    args.diff_files.append(argv[i])
                    i += 1
                continue

        elif not token.startswith("-"):
            # Unknown positional — treat as command
            Term.writeln(Term.c(f"  Unknown command: '{token}'", Term.RED))
            Term.writeln(f"  Available commands: scan, list, diff")
            sys.exit(1)

        else:
            Term.writeln(Term.c(f"  Unknown flag: '{token}'", Term.RED))
            Term.writeln(f"  Run 'xping --help' for usage.")
            sys.exit(1)

        i += 1

    # Validate format
    valid_formats = ("terminal", "json", "html", "sarif")
    if args.format not in valid_formats:
        Term.writeln(Term.c(f"  Error: --format must be one of: {', '.join(valid_formats)}", Term.RED))
        sys.exit(1)

    # Validate severity
    valid_severities = ("info", "low", "medium", "high", "critical")
    if args.severity not in valid_severities:
        Term.writeln(Term.c(f"  Error: --severity must be one of: {', '.join(valid_severities)}", Term.RED))
        sys.exit(1)

    return args


# ═══════════════════════════════════════════════════════════════════════
# Styled Help System
# ═══════════════════════════════════════════════════════════════════════

def print_help() -> None:
    """Display the custom styled help screen."""
    print_banner()

    w = 66  # Box width

    # Header box
    Term.writeln(f"  {Term.c(Term.TL + Term.H * w + Term.TR, Term.CYAN)}")
    Term.writeln(f"  {Term.c(Term.V, Term.CYAN)}  {Term.c('USAGE & COMMAND REFERENCE', Term.BOLD + Term.WHITE)}{'':38}{Term.c(Term.V, Term.CYAN)}")
    Term.writeln(f"  {Term.c(Term.BL + Term.H * w + Term.BR, Term.CYAN)}")
    Term.writeln()

    # Usage patterns
    cmds = [
        ("xping", "Launch interactive menu console"),
        ("xping scan --all", "Full system security scan"),
        ("xping scan --all -t <target_ip>", "Scan target host / IP address"),
        ("xping scan -m <modules>", "Scan specific modules (e.g. sysrecon,container)"),
        ("xping diff <base.json> <curr.json>", "Security drift analysis between two scans"),
        ("xping list", "List available modules & descriptions"),
        ("xping --help, -h", "Show this help screen"),
        ("xping --version, -V", "Display XPing version"),
    ]
    for cmd, desc in cmds:
        Term.writeln(f"    {Term.c(cmd.ljust(34), Term.GREEN)} {Term.c(desc, Term.DIM)}")

    # Scan options
    Term.writeln()
    Term.writeln(f"  {Term.c('SCAN & AUDIT OPTIONS', Term.BOLD + Term.WHITE)}")
    Term.writeln(f"  {Term.c('-' * 45, Term.DIM)}")

    opts = [
        ("--all,     -a", "Run all available modules"),
        ("--modules, -m", "Comma-separated module list"),
        ("--target,  -t", "Target host or IP address (default: auto-detected local IP)"),
        ("--format,  -f", "Output format: terminal | json | html | sarif"),
        ("--output,  -o", "Report output file destination"),
        ("--severity,-s", "Min severity: info | low | medium | high | critical"),
        ("--generate-fix", "Export automated remediation bash script"),
        ("--custom-modules-dir", "Directory path containing custom plugin modules"),
        ("--workers, -w", "Parallel thread pool count (default: 4)"),
        ("--log-file",    "Write runtime diagnostics to JSON log file"),
        ("--verbose, -v", "Enable debug trace logging"),
        ("--no-color",    "Disable ANSI escape colors"),
    ]
    for flag, desc in opts:
        Term.writeln(f"    {Term.c(flag.ljust(20), Term.YELLOW)} {desc}")

    # Section 1: Security Drift Analysis
    Term.writeln()
    Term.writeln(f"  {Term.c('SECTION: SECURITY DRIFT ANALYSIS (xping diff)', Term.BOLD + Term.CYAN)}")
    Term.writeln(f"  {Term.c('-' * 55, Term.DIM)}")
    Term.writeln(f"    {Term.c('Compare two JSON scan results to track added, resolved, and persistent risks:', Term.DIM)}")
    Term.writeln(f"    {Term.c('$', Term.DIM)} {Term.c('xping scan --all -f json -o baseline.json', Term.WHITE)}")
    Term.writeln(f"    {Term.c('$', Term.DIM)} {Term.c('xping scan --all -f json -o current.json', Term.WHITE)}")
    Term.writeln(f"    {Term.c('$', Term.DIM)} {Term.c('xping diff baseline.json current.json', Term.GREEN + Term.BOLD)}")

    # Section 2: Automated Remediation & CI/CD Exports
    Term.writeln()
    Term.writeln(f"  {Term.c('SECTION: AUTOMATED REMEDIATION & CI/CD EXPORTS', Term.BOLD + Term.CYAN)}")
    Term.writeln(f"  {Term.c('-' * 55, Term.DIM)}")
    Term.writeln(f"    {Term.c('Generate executable fix scripts or export SARIF for GitHub Security Tab:', Term.DIM)}")
    Term.writeln(f"    {Term.c('$', Term.DIM)} {Term.c('sudo xping scan --all --generate-fix fix.sh', Term.WHITE)}")
    Term.writeln(f"    {Term.c('$', Term.DIM)} {Term.c('sudo xping scan --all -f sarif -o security_results.sarif', Term.WHITE)}")

    # Section 3: Custom Plugin Modules
    Term.writeln()
    Term.writeln(f"  {Term.c('SECTION: CUSTOM PLUGIN MODULES', Term.BOLD + Term.CYAN)}")
    Term.writeln(f"  {Term.c('-' * 55, Term.DIM)}")
    Term.writeln(f"    {Term.c('Dynamically load custom organizational checks from an external directory:', Term.DIM)}")
    Term.writeln(f"    {Term.c('$', Term.DIM)} {Term.c('sudo xping scan --all --custom-modules-dir /etc/xping/plugins/', Term.WHITE)}")

    # Examples
    Term.writeln()
    Term.writeln(f"  {Term.c('QUICK EXAMPLES', Term.BOLD + Term.WHITE)}")
    Term.writeln(f"  {Term.c('-' * 45, Term.DIM)}")

    examples = [
        "sudo python3 run.py scan --all",
        "python3 run.py scan -m sysrecon,container -s high",
        "sudo python3 run.py scan --all -f html -o report.html",
        "sudo python3 run.py scan --all -f sarif -o security.sarif --generate-fix fix.sh",
        "python3 run.py diff baseline.json current.json",
    ]
    for ex in examples:
        Term.writeln(f"    {Term.c('$', Term.DIM)} {Term.c(ex, Term.CYAN)}")

    Term.writeln()


# ═══════════════════════════════════════════════════════════════════════
# Live Scan Progress Spinner
# ═══════════════════════════════════════════════════════════════════════

class ScanProgress:
    """
    Animated progress spinner that runs in a background thread.
    Shows which module is currently being scanned.
    """

    FRAMES = ["[*   ]", "[ *  ]", "[  * ]", "[   *]", "[  * ]", "[ *  ]"]

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._message = "Initializing..."
        self._module_status: Dict[str, str] = {}  # module -> status
        self._start_time = 0.0

    def start(self) -> None:
        self._running = True
        self._start_time = time.time()
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        Term.clear_line()
        Term.show_cursor()

    def update(self, message: str) -> None:
        self._message = message

    def _animate(self) -> None:
        Term.hide_cursor()
        frame_idx = 0
        while self._running:
            elapsed = time.time() - self._start_time
            frame = self.FRAMES[frame_idx % len(self.FRAMES)]
            status_line = (
                f"\r  {Term.c(frame, Term.CYAN, Term.BOLD)} "
                f"{Term.c(self._message, Term.WHITE)} "
                f"{Term.c(f'({elapsed:.0f}s)', Term.DIM)}"
            )
            Term.write(f"\r\033[K{status_line}")
            frame_idx += 1
            time.sleep(0.15)
        Term.show_cursor()


# ═══════════════════════════════════════════════════════════════════════
# Interactive Mode
# ═══════════════════════════════════════════════════════════════════════

def interactive_mode() -> int:
    """
    Full interactive menu when xping is run without arguments.
    Presents numbered options and guides the user through scan configuration.
    """
    print_banner()

    Term.writeln(f"  {Term.c(Term.TL + Term.H * 50 + Term.TR, Term.CYAN)}")
    Term.writeln(f"  {Term.c(Term.V, Term.CYAN)}  {Term.c('MAIN MENU', Term.BOLD + Term.WHITE)}{'':40}{Term.c(Term.V, Term.CYAN)}")
    Term.writeln(f"  {Term.c(Term.BL + Term.H * 50 + Term.BR, Term.CYAN)}")
    Term.writeln()

    menu_items = [
        ("1", "Full Security Scan",           "Run all modules"),
        ("2", "Selective Module Scan",         "Choose specific modules"),
        ("3", "Quick Scan (High+ Only)",       "Fast scan, critical findings only"),
        ("4", "List Available Modules",        "Show module details"),
        ("5", "Generate HTML Report",          "Full scan with HTML output"),
        ("6", "Generate JSON Report",          "Full scan with JSON output"),
        ("7", "Security Drift Analysis",       "Compare baseline & current scan files"),
        ("8", "Generate SARIF Report",          "Export GitHub Code Scanning report"),
        ("9", "Generate Remediation Script",   "Create automated bash fix script"),
        ("H", "Help & Reference",              "Display command documentation"),
        ("0", "Exit",                          ""),
    ]

    for key, title, desc in menu_items:
        num = Term.c(f"  [{key}]", Term.CYAN + Term.BOLD)
        name = Term.c(title, Term.WHITE)
        detail = Term.c(f"  {desc}", Term.DIM) if desc else ""
        Term.writeln(f"  {num} {name}{detail}")

    Term.writeln()

    try:
        choice = input(f"  {Term.c('>', Term.GREEN + Term.BOLD)} Select option (or type 'help'): ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        Term.writeln(f"\n  {Term.c('Goodbye!', Term.DIM)}")
        return 0

    if choice in ("0", "exit", "quit"):
        Term.writeln(f"\n  {Term.c('Goodbye!', Term.DIM)}")
        return 0

    elif choice in ("h", "help", "?"):
        print_help()
        return 0

    elif choice == "1":
        return run_scan(all_modules=True, severity="info", fmt="terminal")

    elif choice == "2":
        return interactive_module_select()

    elif choice == "3":
        return run_scan(all_modules=True, severity="high", fmt="terminal")

    elif choice == "4":
        return cmd_list()

    elif choice == "5":
        output = input(f"  {Term.c('>', Term.GREEN + Term.BOLD)} Output path [xping_report.html]: ").strip()
        if not output:
            output = "xping_report.html"
        return run_scan(all_modules=True, severity="info", fmt="html", output=output)

    elif choice == "6":
        output = input(f"  {Term.c('>', Term.GREEN + Term.BOLD)} Output path [xping_report.json]: ").strip()
        if not output:
            output = "xping_report.json"
        return run_scan(all_modules=True, severity="info", fmt="json", output=output)

    elif choice == "7":
        f1 = input(f"  {Term.c('>', Term.GREEN + Term.BOLD)} Baseline JSON path [baseline.json]: ").strip() or "baseline.json"
        f2 = input(f"  {Term.c('>', Term.GREEN + Term.BOLD)} Current JSON path [current.json]: ").strip() or "current.json"
        return cmd_diff([f1, f2])

    elif choice == "8":
        output = input(f"  {Term.c('>', Term.GREEN + Term.BOLD)} Output path [xping_report.sarif]: ").strip() or "xping_report.sarif"
        return run_scan(all_modules=True, severity="info", fmt="sarif", output=output)

    elif choice == "9":
        output = input(f"  {Term.c('>', Term.GREEN + Term.BOLD)} Fix script path [remediation.sh]: ").strip() or "remediation.sh"
        return run_scan(all_modules=True, severity="info", fmt="terminal", generate_fix=output)

    else:
        Term.writeln(Term.c(f"\n  Invalid option: '{choice}'. Type 'help' for usage guidance.", Term.RED))
        return 1


def interactive_module_select() -> int:
    """Let the user pick specific modules from a numbered list."""
    from xping.core.engine import ScanEngine

    engine = ScanEngine(modules=[])
    available = engine.list_modules()

    Term.writeln()
    Term.writeln(f"  {Term.c('SELECT MODULES', Term.BOLD + Term.WHITE)} {Term.c('(comma-separated numbers)', Term.DIM)}")
    Term.writeln(f"  {Term.c('-' * 45, Term.DIM)}")

    for i, mod in enumerate(available, 1):
        num = Term.c(f"  [{i}]", Term.CYAN + Term.BOLD)
        name = Term.c(mod["name"].ljust(15), Term.GREEN)
        desc = Term.c(mod["description"], Term.DIM)
        Term.writeln(f"  {num} {name} {desc}")

    Term.writeln()
    try:
        selection = input(f"  {Term.c('>', Term.GREEN + Term.BOLD)} Enter numbers (e.g., 1,3,5): ").strip()
    except (KeyboardInterrupt, EOFError):
        return 0

    if not selection:
        Term.writeln(Term.c("  No modules selected.", Term.YELLOW))
        return 1

    # Parse selection
    selected_modules = []
    for part in selection.split(","):
        part = part.strip()
        try:
            idx = int(part) - 1
            if 0 <= idx < len(available):
                selected_modules.append(available[idx]["name"])
            else:
                Term.writeln(Term.c(f"  Invalid number: {part}", Term.RED))
                return 1
        except ValueError:
            # Allow module names directly
            if any(m["name"] == part for m in available):
                selected_modules.append(part)
            else:
                Term.writeln(Term.c(f"  Unknown module: '{part}'", Term.RED))
                return 1

    if not selected_modules:
        Term.writeln(Term.c("  No valid modules selected.", Term.YELLOW))
        return 1

    Term.writeln(f"\n  {Term.c('Selected:', Term.DIM)} {', '.join(Term.c(m, Term.GREEN) for m in selected_modules)}")
    return run_scan(modules=selected_modules, severity="info", fmt="terminal")


# ═══════════════════════════════════════════════════════════════════════
# Scan Execution with Progress
# ═══════════════════════════════════════════════════════════════════════

def run_scan(
    all_modules: bool = False,
    modules: Optional[List[str]] = None,
    target: Optional[str] = None,
    severity: str = "info",
    fmt: str = "terminal",
    output: Optional[str] = None,
    workers: int = 4,
    verbose: bool = False,
    generate_fix: Optional[str] = None,
    custom_modules_dir: Optional[str] = None,
) -> int:
    """
    Execute a scan with animated progress display.

    This wraps the ScanEngine with a live spinner showing
    elapsed time and current status.
    """
    from xping.core.engine import ScanEngine
    from xping.core.reporter import Reporter

    Term.writeln()
    Term.writeln(f"  {Term.c(Term.TL + Term.H * 50 + Term.TR, Term.CYAN)}")
    Term.writeln(f"  {Term.c(Term.V, Term.CYAN)}  {Term.c('SCAN INITIATED', Term.BOLD + Term.WHITE)}{'':35}{Term.c(Term.V, Term.CYAN)}")
    Term.writeln(f"  {Term.c(Term.BL + Term.H * 50 + Term.BR, Term.CYAN)}")

    sev_threshold = Severity.from_string(severity)

    # Config summary
    mod_desc = "ALL" if all_modules else ", ".join(modules or [])
    Term.writeln(f"  {Term.c('Modules:', Term.DIM)}  {Term.c(mod_desc, Term.WHITE)}")
    if target:
        Term.writeln(f"  {Term.c('Target IP:', Term.DIM)} {Term.c(target, Term.WHITE)}")
    Term.writeln(f"  {Term.c('Severity:', Term.DIM)} {Term.c('>= ' + severity.upper(), Term.YELLOW)}")
    Term.writeln(f"  {Term.c('Format:', Term.DIM)}   {Term.c(fmt, Term.WHITE)}")
    if output:
        Term.writeln(f"  {Term.c('Output:', Term.DIM)}   {Term.c(output, Term.WHITE)}")
    if generate_fix:
        Term.writeln(f"  {Term.c('Fix Script:', Term.DIM)} {Term.c(generate_fix, Term.WHITE)}")
    Term.writeln()

    # Start progress spinner
    progress = ScanProgress()
    progress.update("Loading modules...")
    progress.start()

    try:
        engine = ScanEngine(
            modules=None if all_modules else modules,
            max_workers=workers,
            severity_threshold=sev_threshold,
            custom_modules_dir=custom_modules_dir,
            target_ip=target,
        )

        progress.update("Running security analysis...")
        scan_result = engine.run_scan()

    finally:
        progress.stop()

    # Clear spinner line and show completion
    Term.writeln(f"  {Term.c('[DONE]', Term.GREEN + Term.BOLD)} Scan complete in {scan_result.total_execution_time:.2f}s")
    Term.writeln(f"  {Term.c('[>>>>]', Term.CYAN + Term.BOLD)} {scan_result.total_findings} findings detected")
    Term.writeln()

    # Generate report
    reporter = Reporter(scan_result)

    if fmt == "terminal":
        reporter.print_terminal()
    else:
        # Always print terminal summary too
        reporter.print_terminal()

        output_path = reporter.generate(fmt=fmt, output_path=output)
        if output_path:
            Term.writeln()
            Term.writeln(f"  {Term.c(Term.TL + Term.H * 50 + Term.TR, Term.GREEN)}")
            Term.writeln(f"  {Term.c(Term.V, Term.GREEN)} Report saved: {Term.c(output_path, Term.WHITE + Term.BOLD)}")
            Term.writeln(f"  {Term.c(Term.BL + Term.H * 50 + Term.BR, Term.GREEN)}")
            Term.writeln()

    if generate_fix:
        fix_path = reporter.generate_remediation_script(generate_fix)
        Term.writeln(f"  {Term.c('[FIX]', Term.GREEN + Term.BOLD)} Automated remediation script saved to: {fix_path}")
        Term.writeln()

    # Return non-zero if critical findings
    if scan_result.overall_risk == "CRITICAL":
        return 2
    return 0


# ═══════════════════════════════════════════════════════════════════════
# List Modules Command
# ═══════════════════════════════════════════════════════════════════════

def cmd_list() -> int:
    """Display available modules with styled formatting."""
    from xping.core.engine import ScanEngine

    engine = ScanEngine(modules=[])
    available = engine.list_modules()

    Term.writeln()
    Term.writeln(f"  {Term.c(Term.TL + Term.H * 60 + Term.TR, Term.CYAN)}")
    Term.writeln(f"  {Term.c(Term.V, Term.CYAN)}  {Term.c('AVAILABLE MODULES', Term.BOLD + Term.WHITE)}{'':42}{Term.c(Term.V, Term.CYAN)}")
    Term.writeln(f"  {Term.c(Term.BL + Term.H * 60 + Term.BR, Term.CYAN)}")
    Term.writeln()

    # Module icons
    icons = {
        "sysrecon":    "SYS",
        "netaudit":    "NET",
        "secaudit":    "SEC",
        "loganalyzer": "LOG",
        "hardening":   "HRD",
        "redteam":     "RED",
        "container":   "CTR",
    }

    for mod in available:
        icon = icons.get(mod["name"], "MOD")
        badge = Term.c(f" {icon} ", Term.BG_CYAN + Term.WHITE + Term.BOLD)
        name = Term.c(mod["name"].ljust(14), Term.GREEN + Term.BOLD)
        desc = mod["description"]
        Term.writeln(f"  {badge} {name} {desc}")

    Term.writeln()
    Term.writeln(f"  {Term.c('Total:', Term.DIM)} {len(available)} modules")
    Term.writeln(f"  {Term.c('Usage:', Term.DIM)} xping scan -m {','.join(m['name'] for m in available[:2])}")
    Term.writeln()
    return 0


# ═══════════════════════════════════════════════════════════════════════
# Security Drift Command
# ═══════════════════════════════════════════════════════════════════════

def cmd_diff(diff_files: List[str]) -> int:
    """Compare baseline scan JSON and current scan JSON for drift analysis."""
    import json
    from xping.core.reporter import Reporter

    if len(diff_files) < 2:
        Term.writeln(Term.c("  Error: xping diff requires 2 JSON files: baseline.json current.json", Term.RED))
        return 1

    file1, file2 = diff_files[0], diff_files[1]
    if not os.path.exists(file1) or not os.path.exists(file2):
        Term.writeln(Term.c("  Error: Specified JSON report file does not exist.", Term.RED))
        return 1

    try:
        with open(file1, "r", encoding="utf-8") as f:
            base_json = json.load(f)
        with open(file2, "r", encoding="utf-8") as f:
            curr_json = json.load(f)

        res = Reporter.compare_scans(base_json, curr_json)

        Term.writeln()
        Term.writeln(f"  {Term.c(Term.TL + Term.H * 60 + Term.TR, Term.CYAN)}")
        Term.writeln(f"  {Term.c(Term.V, Term.CYAN)}  {Term.c('SECURITY DRIFT ANALYSIS', Term.BOLD + Term.WHITE)}{'':35}{Term.c(Term.V, Term.CYAN)}")
        Term.writeln(f"  {Term.c(Term.BL + Term.H * 60 + Term.BR, Term.CYAN)}")
        Term.writeln()
        Term.writeln(f"  {Term.c('Baseline Scan:', Term.DIM)} {res['baseline_id']}")
        Term.writeln(f"  {Term.c('Current Scan:', Term.DIM)}  {res['current_id']}")
        Term.writeln()
        Term.writeln(f"  ▶ {Term.c('New / Added Findings:', Term.RED + Term.BOLD)}  {res['added_count']}")
        Term.writeln(f"  ▶ {Term.c('Resolved Findings:', Term.GREEN + Term.BOLD)}    {res['resolved_count']}")
        Term.writeln(f"  ▶ {Term.c('Persistent Findings:', Term.YELLOW)} {res['persistent_count']}")
        Term.writeln()

        if res["added_findings"]:
            Term.writeln(f"  {Term.c('━━━ NEW FINDINGS (REQUIRES REVIEW) ━━━', Term.RED + Term.BOLD)}")
            for f in res["added_findings"]:
                Term.writeln(f"  + [{f.get('severity', 'INFO')}] [{f.get('module', 'UNKNOWN')}] {f.get('title', '')}")
            Term.writeln()

        if res["resolved_findings"]:
            Term.writeln(f"  {Term.c('━━━ RESOLVED FINDINGS ━━━', Term.GREEN + Term.BOLD)}")
            for f in res["resolved_findings"]:
                Term.writeln(f"  - [{f.get('severity', 'INFO')}] [{f.get('module', 'UNKNOWN')}] {f.get('title', '')}")
            Term.writeln()

        return 0 if res["added_count"] == 0 else 2

    except Exception as e:
        Term.writeln(Term.c(f"  Failed to parse or compare JSON scan files: {e}", Term.RED))
        return 1


# ═══════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════

def check_linux() -> bool:
    """Verify we're running on Linux."""
    return sys.platform.startswith("linux")


def main() -> int:
    """
    XPing CLI entry point.

    Dispatches to:
      - Interactive menu (no args)
      - Help screen (--help)
      - Scan command (scan ...)
      - List command (list)
    """
    argv = sys.argv[1:]
    args = parse_args(argv)

    # Install unicode-safe print wrapper for terminal output
    from xping.utils.helpers import install_safe_print
    install_safe_print()

    # Handle --version before anything else
    if args.version:
        Term.writeln(f"XPing v{__version__}")
        return 0

    # Handle --help
    if args.help:
        print_help()
        return 0

    # Disable colors if requested
    if args.no_color:
        Term.disable_color()
        from xping.utils.helpers import Colors
        Colors.disable()

    # Initialize logging
    setup_logging(
        log_file=args.log_file,
        verbose=args.verbose,
        no_color=args.no_color,
    )

    log = get_logger("cli")

    # Platform check
    if not check_linux():
        log.warning(
            "XPing is designed for Linux. "
            "Some modules may not function correctly on this platform."
        )

    # No command provided — launch interactive mode
    if not args.command:
        try:
            return interactive_mode()
        except KeyboardInterrupt:
            Term.writeln(f"\n\n  {Term.c('Interrupted. Goodbye!', Term.DIM)}")
            return 130

    # ── Dispatch commands ──

    try:
        if args.command == "list":
            print_banner()
            return cmd_list()

        elif args.command == "diff":
            print_banner()
            return cmd_diff(args.diff_files)

        elif args.command == "scan":
            print_banner()

            # Validate: need --all or --modules
            if not args.all and not args.modules:
                Term.writeln(Term.c("  Error: specify --all or --modules <list>", Term.RED))
                Term.writeln(f"  {Term.c('Tip:', Term.YELLOW)} xping scan --all")
                Term.writeln(f"  {Term.c('Tip:', Term.YELLOW)} xping scan -m sysrecon,netaudit")
                Term.writeln()
                return 1

            module_list = None
            if args.modules:
                module_list = [m.strip() for m in args.modules.split(",")]

            return run_scan(
                all_modules=args.all,
                modules=module_list,
                target=args.target,
                severity=args.severity,
                fmt=args.format,
                output=args.output,
                workers=args.workers,
                verbose=args.verbose,
                generate_fix=args.generate_fix,
                custom_modules_dir=args.custom_modules_dir,
            )

        else:
            Term.writeln(Term.c(f"  Unknown command: '{args.command}'", Term.RED))
            print_help()
            return 1

    except KeyboardInterrupt:
        Term.writeln(f"\n\n  {Term.c('Scan interrupted by user.', Term.YELLOW)}")
        Term.show_cursor()
        return 130
    except Exception as e:
        log.error(f"Fatal error: {e}", exc_info=True)
        Term.writeln(Term.c(f"\n  Fatal error: {e}", Term.RED))
        Term.show_cursor()
        return 1


if __name__ == "__main__":
    sys.exit(main())
