# Contributing to XPing

Thank you for your interest in contributing to XPing! This guide will help you get started.

## 📋 Code of Conduct

Be respectful, professional, and constructive. Security tooling is serious business — collaboration over competition.

## 🛠️ Development Setups

```bash
# Clone the repository
git clone https://github.com/giridharan-dev/xping.git
cd xping

# Run directly (no install required)
sudo python3 run.py scan --all

# Or install in development mode
pip install -e .
```

## 📐 Code Standards

### Style
- **Python 3.8+ compatibility** — no walrus operator, no `match/case`
- **Type hints** on all function signatures
- **Docstrings** on all public classes and methods
- Follow PEP 8 naming conventions

### Zero Dependencies Rule
XPing uses **only the Python standard library**. Do not add `pip` dependencies. This is a core design principle that allows XPing to run on air-gapped and minimal systems.

### Architecture Principles
- **Read-only** — never modify system state
- **Crash-isolated** — modules must not crash the engine
- **Timeout-bounded** — all commands use `run_cmd()` with timeouts
- **Graceful degradation** — handle missing files/commands without errors

## 🔌 Adding a New Module

1. Create a file in `xping/modules/` (e.g., `xping/modules/mycheck.py`)
2. Inherit from `BaseModule`
3. Implement `name`, `description`, and `run()` properties/methods
4. Optionally override `is_available()` for environment checks

```python
from xping.modules.base import BaseModule
from xping.core.models import ModuleResult, Finding, Severity

class MyCheckModule(BaseModule):
    @property
    def name(self) -> str:
        return "mycheck"

    @property
    def description(self) -> str:
        return "Description of what this module checks"

    def run(self) -> ModuleResult:
        findings = []
        # Your analysis logic here
        return ModuleResult(
            module_name=self.name,
            description=self.description,
            findings=findings,
        )
```

The engine auto-discovers modules — no registration needed.

## 🧪 Testing Your Changes

```bash
# Verify imports work
python3 -c "import xping; print(xping.__version__)"

# Run help screen
python3 run.py --help

# Quick functional test (Linux only)
sudo python3 run.py scan --all --severity high

# Test specific module
sudo python3 run.py scan -m sysrecon
```

## 📝 Commit Messages

Use clear, descriptive commit messages:

```
feat(modules): add container runtime detection to sysrecon
fix(reporter): correct HTML escaping in evidence blocks
docs: update README with new module documentation
```

## 🔀 Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Make your changes with tests
4. Ensure `python3 run.py --help` works
5. Submit a PR with a clear description

## 🐛 Reporting Bugs

Open an issue with:
- XPing version (`xping --version`)
- Python version (`python3 --version`)
- Linux distro and kernel (`uname -a`)
- Expected vs actual behavior
- Relevant log output (`--verbose` flag)

## 💡 Feature Requests

Open an issue tagged `[FEATURE]` describing:
- What security check or capability you'd like
- Why it matters (attack scenario, compliance requirement, etc.)
- Example evidence/output format

---

Thank you for helping make Linux systems more secure! 🛡️
