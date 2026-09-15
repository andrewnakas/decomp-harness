"""Lessons: traps that cost time once, encoded as checks so they never cost it again.

Seeded from the skate3-audio CLAUDE.md. Each lesson can carry a check that runs
in `decomp doctor` or at a stage boundary, so the harness enforces what a
session brief could only ask an agent to remember.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .stages import now_iso

if TYPE_CHECKING:
    from .config import Project


@dataclass(frozen=True)
class Lesson:
    key: str
    title: str
    body: str
    trigger: str = ""          # stage this guards ("" = advisory only)
    check_kind: str = "none"   # none | python | shell
    check_ref: str = ""
    severity: str = "warn"     # warn | error
    source: str = ""


# Distilled from the audio project's hard-earned traps. Bodies stay one or two
# sentences: they are rendered into the model brief, where every token counts.
SEED_LESSONS: tuple[Lesson, ...] = (
    Lesson(
        key="fixhelpers_before_decompile",
        title="Run FixHelpers before decompiling",
        body=(
            "Xenon prologues call __savegprlr_*/__restgprlr_* stubs. Ghidra models them as "
            "ordinary functions, losing r3 to a fake return value, so most functions get wrong "
            "parameters and struct-offset work is silently corrupt."
        ),
        trigger="analyze",
        check_kind="python",
        check_ref="decomp.core.lessons:check_fixhelpers_applied",
        severity="error",
        source="skate3-audio CLAUDE.md",
    ),
    Lesson(
        key="build_artifact_verified",
        title="Verify the build artifact, never the exit status",
        body=(
            "A pipe after `|| true` once made a failed build report success and the next session "
            "silently ran the previous binary. Check the object file, the nm symbol, and that the "
            "binary is newer than its sources."
        ),
        trigger="build",
        check_kind="python",
        check_ref="decomp.core.lessons:check_build_verified",
        severity="error",
        source="skate3-audio docs/port-loop.md",
    ),
    Lesson(
        key="no_stale_session",
        title="Never run a session against a stale binary",
        body="The armed port set must match what was built; refuse the session otherwise.",
        trigger="session",
        check_kind="python",
        check_ref="decomp.core.lessons:check_session_build_fresh",
        severity="error",
        source="skate3-audio docs/port-loop.md",
    ),
    Lesson(
        key="negative_controls_required",
        title="A verdict is worthless until a control has failed",
        body=(
            "Arm deliberately mutated ports every session and require them to diverge. One control "
            "once failed to apply (its anchor matched twice) and passed as an unmodified port."
        ),
        trigger="verify",
        check_kind="python",
        check_ref="decomp.core.lessons:check_negative_controls",
        severity="error",
        source="skate3-audio docs/port-loop.md",
    ),
    Lesson(
        key="title_update_flag",
        title="Sessions need the title update installed",
        body=(
            "Without --skate3_install_tu the installer overlay blocks the main guest thread on a "
            "critical section and the game reports 100% silent submits with zero voices. Cost: 1 hour."
        ),
        trigger="session",
        check_kind="python",
        check_ref="decomp.core.lessons:check_session_flags",
        severity="error",
        source="skate3-audio CLAUDE.md",
    ),
    Lesson(
        key="hooked_funcs_regenerated",
        title="Regenerate the hooked-function header after adding a hook",
        body="Adding REX_FUNC(sub_X) without rerunning gen_hooked_funcs.sh fails the link.",
        trigger="build",
        check_kind="none",
        source="skate3recomp tools/gen_hooked_funcs.sh",
    ),
    Lesson(
        key="cmake_flag_trap",
        title="Never put defines in CMAKE_CXX_FLAGS",
        body=(
            "It invalidates every third-party library and turns a 200-file rebuild into 700. Use "
            "target_compile_definitions on the game target."
        ),
        trigger="build",
        check_kind="none",
        source="skate3-audio CLAUDE.md",
    ),
    Lesson(
        key="mxcsr_sigfpe",
        title="Host float work inside a guest call can SIGFPE",
        body=(
            "The audio worker enters guest code with MXCSR 0x0000, all FP exceptions unmasked. "
            "Mask exceptions around host-only work in hooks; native guest math runs under the "
            "guest's own mode."
        ),
        trigger="port",
        check_kind="none",
        source="skate3-audio CLAUDE.md",
    ),
    Lesson(
        key="compute_lis_constants",
        title="Compute lis-based addresses, never read them by eye",
        body=(
            "Address is ((imm & 0xFFFF) << 16) + offset. Misreading one digit produced the "
            "project's first shadow divergence; the arithmetic is three characters of Python."
        ),
        trigger="port",
        check_kind="none",
        source="skate3-audio CLAUDE.md",
    ),
    Lesson(
        key="keep_64bit_intermediates",
        title="Keep 64-bit intermediates; cast only at stores",
        body=(
            "RexGlue's add and mullw are 64-bit on zero-extended operands, so sums carry into bit "
            "32. A truncated chain leaves memory byte-identical but the returned register wrong; "
            "one such bug surfaced only on the 120th call."
        ),
        trigger="port",
        check_kind="none",
        source="skate3-audio docs/port-loop.md",
    ),
    Lesson(
        key="real_data_not_synthetic",
        title="Synthetic tests never caught a format bug here; real data caught every one",
        body="Unit tests prove self-consistency, which is exactly what a wrong assumption preserves.",
        trigger="",
        check_kind="none",
        source="skate3-audio CLAUDE.md",
    ),
    Lesson(
        key="no_offset_grep",
        title="Grepping decompiled offsets does not discriminate",
        body=(
            "Offsets like +0x30 and +0xCC appear across unrelated structures; three hunts failed "
            "this way. Query the harvested field accesses by typed base, or instrument the runtime."
        ),
        trigger="",
        check_kind="none",
        source="skate3-audio CLAUDE.md",
    ),
    Lesson(
        key="distribution_not_head",
        title="Do not generalize from the head of a distribution",
        body=(
            "Three confident wrong answers came from checking the first few records. Verify across "
            "the whole distribution; a coherent story that explains several loose ends at once is "
            "the most dangerous kind."
        ),
        trigger="",
        check_kind="none",
        source="skate3-audio CLAUDE.md",
    ),
    Lesson(
        key="window_refusal_is_a_result",
        title="A window builder that refuses too often is also wrong",
        body=(
            "Skipped calls are a first-class result, not a footnote: green over a third of calls "
            "covers less than it looks. Two ports were re-read from 34% to 90% and 66% to 99%."
        ),
        trigger="verify",
        check_kind="none",
        source="skate3-audio docs/port-loop.md",
    ),
)


def seed(project: Project) -> int:
    """Insert the seed lessons that are not already present. Returns count added."""
    added = 0
    for lesson in SEED_LESSONS:
        exists = project.db.scalar("SELECT 1 FROM lesson WHERE key=?", (lesson.key,))
        if exists:
            continue
        project.db.execute(
            "INSERT INTO lesson (key, title, body, trigger, check_kind, check_ref, severity, "
            "source, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                lesson.key,
                lesson.title,
                lesson.body,
                lesson.trigger,
                lesson.check_kind,
                lesson.check_ref,
                lesson.severity,
                lesson.source,
                now_iso(),
            ),
        )
        added += 1
    return added


def for_stage(project: Project, stage: str) -> list[dict]:
    return project.db.query("SELECT * FROM lesson WHERE trigger=? ORDER BY id", (stage,))


def all_lessons(project: Project) -> list[dict]:
    return project.db.query("SELECT * FROM lesson ORDER BY id")


def bump(project: Project, key: str) -> None:
    project.db.execute("UPDATE lesson SET hits = hits + 1 WHERE key=?", (key,))


# ---------------------------------------------------------------- checks
# Each returns (ok, message). They are deliberately cheap and side-effect free.


def check_fixhelpers_applied(project: Project, **_: object) -> tuple[bool, str]:
    done = project.db.meta_get("engine.fixhelpers_applied")
    if done:
        return True, f"FixHelpers applied ({done})"
    return False, "FixHelpers has not been applied to the Ghidra program"


def check_build_verified(project: Project, **_: object) -> tuple[bool, str]:
    row = project.db.one("SELECT * FROM build ORDER BY id DESC LIMIT 1")
    if not row:
        return True, "no build yet"
    if row.get("ok") and row.get("nm_symbols_ok"):
        return True, f"build {row['id']} verified ({row.get('found_syms')} symbols)"
    return False, f"build {row['id']} did not pass symbol/mtime verification"


def check_session_build_fresh(project: Project, **_: object) -> tuple[bool, str]:
    build = project.db.one("SELECT * FROM build WHERE ok=1 ORDER BY id DESC LIMIT 1")
    if not build:
        return False, "no successful build to run a session against"
    return True, f"latest good build is {build['id']}"


def check_negative_controls(project: Project, **_: object) -> tuple[bool, str]:
    row = project.db.one("SELECT * FROM session ORDER BY id DESC LIMIT 1")
    if not row:
        return True, "no session yet"
    if row.get("negcontrol_ok"):
        return True, f"session {row['id']} controls diverged as required"
    return False, f"session {row['id']} has no failing negative control; verdicts untrusted"


def check_session_flags(project: Project, **_: object) -> tuple[bool, str]:
    flags = project.get("session.required_flags", [])
    if not flags:
        return True, "no required session flags configured"
    return True, f"required flags configured: {' '.join(flags)}"


def run_checks(project: Project, stage: str = "") -> list[tuple[str, bool, str]]:
    """Run the checks for a stage (or all of them). Returns (key, ok, message)."""
    import importlib

    rows = for_stage(project, stage) if stage else all_lessons(project)
    results: list[tuple[str, bool, str]] = []
    for row in rows:
        if row.get("check_kind") != "python" or not row.get("check_ref"):
            continue
        mod_name, _, func_name = row["check_ref"].partition(":")
        try:
            mod = importlib.import_module(mod_name)
            fn = getattr(mod, func_name)
            ok, msg = fn(project)
        except Exception as exc:
            ok, msg = False, f"check raised: {exc}"
        results.append((row["key"], ok, msg))
    return results
