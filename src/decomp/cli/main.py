"""decomp — mechanical harness for AI-driven reverse engineering.

Commands are thin wrappers: they parse arguments, call a pipeline stage, and
print its brief(). All logic lives in decomp.pipeline / decomp.core.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer

from ..core import out
from ..core.config import open_project

app = typer.Typer(
    name="decomp",
    help="Mechanical harness for AI-driven decompilation. Powered by Claude.",
    no_args_is_help=True,
    add_completion=False,
)
import_app = typer.Typer(help="Ingest what is already known.", no_args_is_help=True)
llm_app = typer.Typer(help="Provider smoke tests and the token ledger.", no_args_is_help=True)
lesson_app = typer.Typer(help="Traps recorded as checks.", no_args_is_help=True)
app.add_typer(import_app, name="import")
app.add_typer(llm_app, name="llm")
app.add_typer(lesson_app, name="lesson")

ProjectOpt = Annotated[Optional[Path], typer.Option("--project", "-C", help="Project directory")]
JsonOpt = Annotated[bool, typer.Option("--json", help="Machine-readable output")]


def _open(project: Path | None):
    try:
        return open_project(project)
    except FileNotFoundError as exc:
        out.fail(str(exc))


# --------------------------------------------------------------------- init
@app.command()
def init(
    directory: Annotated[Path, typer.Argument(help="Project directory")] = Path("."),
    target: Annotated[str, typer.Option(help="Target preset: xex | elf | rawimage")] = "rawimage",
    name: Annotated[str, typer.Option(help="Project name")] = "",
    recomp: Annotated[str, typer.Option(help="Path to a recompilation consumer repo")] = "",
    force: Annotated[bool, typer.Option(help="Overwrite an existing decomp.toml")] = False,
    json_out: JsonOpt = False,
):
    """Create a project: decomp.toml, the database, and .decomp/."""
    from ..pipeline.init_project import init as do_init

    out.set_json(json_out)
    out.emit(do_init(directory, target=target, name=name, recomp=recomp, force=force))


# ------------------------------------------------------------------- doctor
@app.command()
def doctor(project: ProjectOpt = None, json_out: JsonOpt = False):
    """Check tools, providers, hosts, and the lessons' guards."""
    from ..pipeline.doctor import run as run_doctor
    from ..core.config import find_project_root

    out.set_json(json_out)
    proj = None
    if project is not None or find_project_root() is not None:
        proj = _open(project)
    result = run_doctor(proj)
    out.emit(result)
    raise typer.Exit(1 if result.failures else 0)


# -------------------------------------------------------------------- login
@app.command()
def login(
    provider: Annotated[str, typer.Option(help="claude | codex | all")] = "all",
    project: ProjectOpt = None,
    json_out: JsonOpt = False,
):
    """Report whether your own agent CLIs are signed in.

    The harness never handles credentials: it spawns the binary you installed
    and signed into. If one is not logged in, this prints the vendor's own
    login command for you to run.
    """
    from ..adapters.provider import get_provider

    out.set_json(json_out)
    proj = _open(project)
    names = ["claude", "codex"] if provider == "all" else [provider]
    rows = []
    any_missing = False
    for name in names:
        try:
            health = get_provider(proj, name).health()
        except Exception as exc:
            rows.append(f"{name}\terror\t{exc}")
            any_missing = True
            continue
        rows.append(health.brief())
        if not health.logged_in:
            any_missing = True
    out.emit("\n".join(rows))
    raise typer.Exit(1 if any_missing else 0)


# ---------------------------------------------------------------------- llm
@llm_app.command("ping")
def llm_ping(
    provider: Annotated[str, typer.Option(help="Provider id")] = "",
    tier: Annotated[str, typer.Option(help="small | mid | strong")] = "small",
    project: ProjectOpt = None,
    json_out: JsonOpt = False,
):
    """One tiny structured call: proves the provider works and calibrates the
    token estimator."""
    from ..adapters.provider import LLMRequest, get_provider
    from ..llm import ledger

    out.set_json(json_out)
    proj = _open(project)
    prov = get_provider(proj, provider or None)

    schema = {
        "type": "object",
        "properties": {
            "ok": {"type": "boolean"},
            "arch": {"type": "string", "description": "the architecture named in the prompt"},
        },
        "required": ["ok", "arch"],
    }
    req = LLMRequest(
        prompt=(
            "Reply with JSON only. Set ok=true and arch to the architecture named "
            "here: PowerPC big-endian Xenon."
        ),
        prefix="You are a reverse-engineering assistant. Answer with JSON matching the schema.",
        schema=schema,
        tier=tier,
        max_turns=1,
        purpose="ping",
        cwd=proj.sub("work", "_ping"),
        timeout_s=180,
    )
    result = prov.call(req)
    ledger.record(proj, prov.id, req, result, packet_tokens_est=len(req.prompt) // 3)
    out.emit(f"{prov.id}\t{result.brief()}\t{json.dumps(result.structured)[:120]}")
    raise typer.Exit(0 if result.ok else 1)


@app.command()
def cost(
    by: Annotated[str, typer.Option(help="Group by: model | purpose | provider")] = "",
    baseline_from: Annotated[
        list[str], typer.Option("--baseline-from", help="Project path whose Claude Code "
                                "transcripts form the manual baseline (repeatable)")
    ] = [],
    baseline_verified: Annotated[
        int, typer.Option(help="Functions the baseline sessions verified")
    ] = 0,
    since: Annotated[str, typer.Option(help="Baseline start date YYYY-MM-DD")] = "",
    until: Annotated[str, typer.Option(help="Baseline end date YYYY-MM-DD")] = "",
    project: ProjectOpt = None,
    json_out: JsonOpt = False,
):
    """Tokens per verified function, cache hit rate, and the manual baseline."""
    from datetime import date as _date

    from ..llm import baseline as baseline_mod
    from ..llm import ledger

    out.set_json(json_out)
    proj = _open(project)
    rep = ledger.report(proj, group_by=by)

    text = rep.brief()
    if baseline_from:
        since_d = _date.fromisoformat(since) if since else None
        until_d = _date.fromisoformat(until) if until else None
        base = baseline_mod.build(
            list(baseline_from), verified=baseline_verified,
            since=since_d, until=until_d,
        )
        rep.baseline_per_verified = base.per_verified
        text = rep.brief() + "\n\n" + base.brief()
    out.emit(rep if json_out else text)


# ------------------------------------------------------------------ lessons
@lesson_app.command("list")
def lesson_list(
    stage: Annotated[str, typer.Option(help="Only lessons guarding this stage")] = "",
    project: ProjectOpt = None,
    json_out: JsonOpt = False,
):
    """Show recorded traps."""
    from ..core import lessons as lessons_mod

    out.set_json(json_out)
    proj = _open(project)
    rows = lessons_mod.for_stage(proj, stage) if stage else lessons_mod.all_lessons(proj)
    if json_out:
        out.emit(rows)
        return
    out.emit("\n".join(
        f"{r['key']}\t{r['trigger'] or '-'}\t{r['severity']}\t{r['title']}" for r in rows
    ))


@lesson_app.command("add")
def lesson_add(
    key: str,
    title: str,
    body: Annotated[str, typer.Option(help="One or two sentences on what and why")] = "",
    trigger: Annotated[str, typer.Option(help="Stage this guards")] = "",
    severity: Annotated[str, typer.Option(help="warn | error")] = "warn",
    project: ProjectOpt = None,
    json_out: JsonOpt = False,
):
    """Record a trap so it is never re-derived."""
    from ..core.stages import now_iso

    out.set_json(json_out)
    proj = _open(project)
    proj.db.upsert(
        "lesson",
        {
            "key": key, "title": title, "body": body, "trigger": trigger,
            "check_kind": "none", "severity": severity, "source": "user",
            "created_at": now_iso(),
        },
        "key",
    )
    out.emit(f"lesson\t{key}\trecorded")


@lesson_app.command("check")
def lesson_check(
    stage: Annotated[str, typer.Option(help="Only this stage's checks")] = "",
    project: ProjectOpt = None,
    json_out: JsonOpt = False,
):
    """Run the lessons' executable checks."""
    from ..core import lessons as lessons_mod

    out.set_json(json_out)
    proj = _open(project)
    results = lessons_mod.run_checks(proj, stage)
    out.emit("\n".join(
        f"{'ok  ' if ok else 'FAIL'}\t{key}\t{msg}" for key, ok, msg in results
    ) or "no executable checks")
    raise typer.Exit(1 if any(not ok for _, ok, _ in results) else 0)


# ------------------------------------------------------------------- status
@app.command()
def status(project: ProjectOpt = None, json_out: JsonOpt = False):
    """Queue counts, last build and session, ledger totals."""
    from ..pipeline.status import run as run_status

    out.set_json(json_out)
    out.emit(run_status(_open(project)))


# -------------------------------------------------------------------- import
ForceOpt = Annotated[bool, typer.Option("--force", help="Rerun even if inputs are unchanged")]


@import_app.command("image")
def import_image_cmd(
    path: Annotated[Path, typer.Argument(help="Decrypted image or executable")],
    base: Annotated[str, typer.Option(help="Load address, e.g. 0x82000000")] = "",
    name: Annotated[str, typer.Option(help="Target name")] = "",
    project: ProjectOpt = None, json_out: JsonOpt = False, force: ForceOpt = False,
):
    """Register the target image."""
    from ..pipeline.importer import import_image

    out.set_json(json_out)
    proj = _open(project)
    base_val = int(base, 0) if base else None
    out.emit(import_image(proj, path=path, base=base_val, name=name, force=force))


@import_app.command("lifted")
def import_lifted_cmd(
    path: Annotated[Path, typer.Argument(help="Directory of lifted C++ sources")],
    pattern: Annotated[str, typer.Option(help="Source glob")] = "*_recomp.*.cpp",
    project: ProjectOpt = None, json_out: JsonOpt = False, force: ForceOpt = False,
):
    """Index a static recompiler's output: functions, names, boundaries."""
    from ..pipeline.importer import import_lifted

    out.set_json(json_out)
    out.emit(import_lifted(_open(project), path=path, pattern=pattern, force=force))


@import_app.command("xrefs")
def import_xrefs_cmd(
    scope: Annotated[str, typer.Option(help="corpus | all")] = "corpus",
    project: ProjectOpt = None, json_out: JsonOpt = False, force: ForceOpt = False,
):
    """Record call edges and folded constants for functions in scope."""
    from ..pipeline.importer import import_xrefs

    out.set_json(json_out)
    out.emit(import_xrefs(_open(project), scope=scope, force=force))


@import_app.command("names")
def import_names_cmd(
    path: Annotated[Path, typer.Argument(help="CSV addr,name or TOML table")],
    kind: Annotated[str, typer.Option(help="Evidence kind")] = "ingest",
    confidence: Annotated[float, typer.Option(help="0-1")] = 0.8,
    project: ProjectOpt = None, json_out: JsonOpt = False, force: ForceOpt = False,
):
    """Import recovered symbol names as evidence."""
    from ..pipeline.importer import import_names

    out.set_json(json_out)
    out.emit(import_names(_open(project), path=path, kind=kind,
                          confidence=confidence, force=force))


@import_app.command("structs")
def import_structs_cmd(
    path: Annotated[Path, typer.Argument(help="Recovered-layout C header")],
    project: ProjectOpt = None, json_out: JsonOpt = False, force: ForceOpt = False,
):
    """Import struct layouts with their offset citations."""
    from ..pipeline.importer import import_structs

    out.set_json(json_out)
    out.emit(import_structs(_open(project), path=path, force=force))


@import_app.command("trace")
def import_trace_cmd(
    path: Annotated[Path, typer.Argument(help="Guest execution trace")],
    profile: Annotated[str, typer.Option(help="boot | play | map")] = "play",
    project: ProjectOpt = None, json_out: JsonOpt = False, force: ForceOpt = False,
):
    """Import an execution trace: call counts and thread attribution."""
    from ..pipeline.importer import import_trace

    out.set_json(json_out)
    out.emit(import_trace(_open(project), path=path, profile=profile, force=force))


@import_app.command("queue")
def import_queue_cmd(
    path: Annotated[Path, typer.Argument(help="Previous queue.json")],
    project: ProjectOpt = None, json_out: JsonOpt = False, force: ForceOpt = False,
):
    """Import prior statuses, gates and verdicts."""
    from ..pipeline.importer import import_queue

    out.set_json(json_out)
    out.emit(import_queue(_open(project), path=path, force=force))


@import_app.command("notes")
def import_notes_cmd(
    path: Annotated[Path, typer.Argument(help="Directory of sub_*.md notes")],
    project: ProjectOpt = None, json_out: JsonOpt = False, force: ForceOpt = False,
):
    """Import per-function notes, trimmed to packet size."""
    from ..pipeline.importer import import_notes

    out.set_json(json_out)
    out.emit(import_notes(_open(project), path=path, force=force))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
