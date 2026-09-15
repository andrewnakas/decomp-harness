"""`decomp doctor`: is this machine able to run the pipeline, and are the
lessons' checks still satisfied?"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ..core import lessons

if TYPE_CHECKING:
    from ..core.config import Project

GHIDRA_HINTS = (
    "/opt/homebrew/opt/ghidra/libexec",
    "/usr/local/opt/ghidra/libexec",
    "/opt/ghidra",
)


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    severity: str = "error"   # error | warn | info

    def line(self) -> str:
        mark = "ok  " if self.ok else ("WARN" if self.severity == "warn" else "FAIL")
        return f"{mark}\t{self.name}\t{self.detail}"


@dataclass
class DoctorResult:
    checks: list[Check] = field(default_factory=list)

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.ok and c.severity == "error"]

    def brief(self) -> str:
        body = "\n".join(c.line() for c in self.checks)
        bad = len(self.failures)
        tail = f"\n{bad} blocking issue(s)" if bad else "\nall clear"
        return body + tail


def find_ghidra() -> Path | None:
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    candidates = [Path(env)] if env else []
    candidates += [Path(h) for h in GHIDRA_HINTS]
    for c in candidates:
        if (c / "support" / "analyzeHeadless").is_file():
            return c
    return None


JDK_HINTS = (
    "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
    "/usr/local/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
    "/usr/lib/jvm/java-21-openjdk-amd64",
    "/usr/lib/jvm/java-21-openjdk",
)

MIN_JDK = 21


def _java_version(java_bin: str | None) -> int | None:
    """Major version of a java binary, or None if it cannot be determined."""
    if not java_bin:
        return None
    text = _version([java_bin, "-version"])
    for token in text.replace('"', " ").split():
        head = token.split(".")[0]
        if head.isdigit():
            return int(head)
    return None


def find_jdk() -> tuple[Path, int] | None:
    """Locate a JDK new enough for Ghidra. JAVA_HOME wins, then PATH, then hints."""
    candidates: list[Path] = []
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidates.append(Path(java_home))
    on_path = shutil.which("java")
    if on_path:
        candidates.append(Path(on_path).parent.parent)
    candidates += [Path(h) for h in JDK_HINTS]

    for home in candidates:
        java_bin = home / "bin" / "java"
        if not java_bin.is_file():
            continue
        major = _java_version(str(java_bin))
        if major and major >= MIN_JDK:
            return home, major
    return None


def _version(argv: list[str]) -> str:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        return (p.stdout or p.stderr).strip().splitlines()[0][:60] if (p.stdout or p.stderr) else ""
    except Exception:
        return ""


def run(project: "Project | None" = None) -> DoctorResult:
    import sys

    checks: list[Check] = []

    # --- runtime -----------------------------------------------------------
    py = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = (3, 12) <= sys.version_info[:2] < (3, 14)
    checks.append(Check(
        "python", py_ok, f"{py} (PyGhidra needs 3.9-3.13)",
        severity="error" if not py_ok else "info",
    ))

    # --- ghidra ------------------------------------------------------------
    gh = find_ghidra()
    if gh:
        checks.append(Check("ghidra", True, str(gh)))
        pyghidra_whl = list((gh / "Ghidra/Features/PyGhidra/pypkg/dist").glob("pyghidra-*.whl"))
        checks.append(Check(
            "pyghidra-wheel", bool(pyghidra_whl),
            pyghidra_whl[0].name if pyghidra_whl else "bundled wheel not found",
            severity="warn",
        ))
    else:
        checks.append(Check("ghidra", False, "set GHIDRA_INSTALL_DIR or brew install ghidra"))

    try:
        import pyghidra  # noqa: F401
        checks.append(Check("pyghidra-module", True, "importable"))
    except ImportError:
        checks.append(Check(
            "pyghidra-module", False,
            "pip install the bundled wheel (see docs) - analyze stage needs it",
            severity="warn",
        ))

    jdk = find_jdk()
    if jdk:
        checks.append(Check("java", True, f"{jdk[1]} at {jdk[0]}"))
    else:
        current = _java_version(shutil.which("java"))
        detail = (
            f"found Java {current}, Ghidra needs 21+"
            if current
            else "no JDK found; Ghidra needs 21+"
        )
        checks.append(Check(
            "java", False,
            f"{detail} (brew install openjdk@21, or set JAVA_HOME)",
        ))

    # --- providers ---------------------------------------------------------
    for name, login_cmd in (("claude", "claude  (then /login)"), ("codex", "codex login")):
        exe = shutil.which(name)
        if not exe:
            checks.append(Check(f"provider:{name}", False, f"not on PATH; install it",
                                severity="warn"))
            continue
        checks.append(Check(f"provider:{name}", True, _version([name, "--version"])))

    if project is not None:
        from ..adapters.provider import get_provider
        for name in ("claude", "codex"):
            if not shutil.which(name):
                continue
            try:
                health = get_provider(project, name).health()
            except Exception as exc:
                checks.append(Check(f"login:{name}", False, str(exc)[:80], severity="warn"))
                continue
            checks.append(Check(
                f"login:{name}", health.logged_in,
                health.detail or health.login_hint, severity="warn",
            ))

    # --- optional tools ----------------------------------------------------
    for tool, why in (
        ("objdiff-cli", "byte-match oracle (phase 5)"),
        ("m2c", "zero-token drafts for matching targets (phase 5)"),
        ("rizin", "fast strings/xrefs (optional)"),
        ("clang-format", "formats generated port bodies"),
        ("rsync", "remote build/session stages"),
        ("ssh", "remote build/session stages"),
    ):
        checks.append(Check(f"tool:{tool}", bool(shutil.which(tool)), why, severity="warn"))

    # --- project -----------------------------------------------------------
    if project is not None:
        checks.append(Check("project", True, str(project.root)))
        target = project.target_row()
        checks.append(Check(
            "target", target is not None,
            f"{target['name']} @ 0x{target['base_addr']:08X}" if target else "run `decomp import`",
            severity="warn",
        ))
        for host_name in (project.get("hosts", {}) or {}):
            host = project.host(host_name)
            ok = _ssh_ok(host.ssh) if host.ssh else True
            checks.append(Check(f"host:{host_name}", ok, host.ssh or "local", severity="warn"))
        for key, ok, msg in lessons.run_checks(project):
            checks.append(Check(f"lesson:{key}", ok, msg, severity="warn"))

    return DoctorResult(checks=checks)


def _ssh_ok(target: str) -> bool:
    try:
        p = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6", target, "true"],
            capture_output=True, timeout=15,
        )
        return p.returncode == 0
    except Exception:
        return False
