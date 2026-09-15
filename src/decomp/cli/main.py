"""decomp — mechanical harness for AI-driven reverse engineering.

Commands are thin wrappers: they parse arguments, call a pipeline stage, and
print its brief(). All logic lives in decomp.pipeline / decomp.core.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

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
corpus_app = typer.Typer(help="Bound the work by call-graph closure.", no_args_is_help=True)
queue_app = typer.Typer(help="What to work on next, and why.", no_args_is_help=True)
llm_app = typer.Typer(help="Provider smoke tests and the token ledger.", no_args_is_help=True)
lesson_app = typer.Typer(help="Traps recorded as checks.", no_args_is_help=True)
app.add_typer(import_app, name="import")
app.add_typer(corpus_app, name="corpus")
app.add_typer(queue_app, name="queue")
app.add_typer(llm_app, name="llm")
app.add_typer(lesson_app, name="lesson")

ProjectOpt = Annotated[Path | None, typer.Option("--project", "-C", help="Project directory")]
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
    from ..core.config import find_project_root
    from ..pipeline.doctor import run as run_doctor

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
        list[str] | None, typer.Option("--baseline-from", help="Project path whose "
                                          "Claude Code transcripts form the manual "
                                          "baseline (repeatable)")
    ] = None,
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


@import_app.command("decomp")
def import_decomp_cmd(
    path: Annotated[Path, typer.Argument(help="Directory of sub_*.c decompiler output")],
    pattern: Annotated[str, typer.Option(help="File glob")] = "sub_*.c",
    project: ProjectOpt = None, json_out: JsonOpt = False, force: ForceOpt = False,
):
    """Register existing decompiler output as each function's C view."""
    from ..pipeline.importer import import_decompiled

    out.set_json(json_out)
    out.emit(import_decompiled(_open(project), path=path, pattern=pattern, force=force))


# -------------------------------------------------------------------- corpus
@corpus_app.command("grow")
def corpus_grow(
    seeds: Annotated[list[str], typer.Argument(help="Seed addresses")] = None,
    seed_file: Annotated[Path | None, typer.Option("--seed-file", help="File of addresses")] = None,
    subsystem: Annotated[str, typer.Option(help="Name this corpus")] = "",
    max_depth: Annotated[int, typer.Option(help="0 = unbounded")] = 0,
    follow_helpers: Annotated[bool, typer.Option(help="Walk into runtime helpers too")] = False,
    project: ProjectOpt = None, json_out: JsonOpt = False, force: ForceOpt = False,
):
    """Grow the corpus from seeds by following resolved guest calls."""
    from ..pipeline.corpus import DEFAULT_STOP_KINDS, grow

    out.set_json(json_out)
    stop = () if follow_helpers else DEFAULT_STOP_KINDS
    out.emit(grow(_open(project), seeds=list(seeds or []), seed_file=seed_file,
                  subsystem=subsystem, max_depth=max_depth, stop_kinds=stop, force=force))


# -------------------------------------------------------------------- screen
@app.command()
def screen(
    subsystem: Annotated[str, typer.Option(help="Restrict to one subsystem")] = "",
    scope: Annotated[str, typer.Option(help="corpus | all")] = "corpus",
    limit: Annotated[int, typer.Option(help="Screen only the hottest N")] = 0,
    project: ProjectOpt = None, json_out: JsonOpt = False, force: ForceOpt = False,
):
    """Decide statically which functions an oracle can bracket. Costs no tokens."""
    from ..pipeline.screen import screen as run_screen

    out.set_json(json_out)
    out.emit(run_screen(_open(project), subsystem=subsystem, scope=scope,
                        limit=limit, force=force))


# --------------------------------------------------------------------- queue
@queue_app.command("build")
def queue_build(
    subsystem: Annotated[str, typer.Option(help="Restrict to one subsystem")] = "",
    no_cluster: Annotated[bool, typer.Option("--no-cluster", help="Skip family clustering")] = False,
    project: ProjectOpt = None, json_out: JsonOpt = False, force: ForceOpt = False,
):
    """Assign tiers, difficulty and families across the corpus."""
    from ..pipeline.queue import build

    out.set_json(json_out)
    out.emit(build(_open(project), subsystem=subsystem, cluster=not no_cluster, force=force))


@queue_app.command("next")
def queue_next(
    n: Annotated[int, typer.Option("-n", help="How many")] = 16,
    tier: Annotated[str, typer.Option(help="A B C D E F L U")] = "",
    subsystem: Annotated[str, typer.Option(help="Restrict to one subsystem")] = "",
    status: Annotated[str, typer.Option(help="Only this status")] = "",
    include_gated: Annotated[bool, typer.Option(help="Include gated functions")] = False,
    project: ProjectOpt = None, json_out: JsonOpt = False,
):
    """The next functions worth a model's attention."""
    from ..pipeline.queue import next_items

    out.set_json(json_out)
    out.emit(next_items(_open(project), tier=tier, limit=n, subsystem=subsystem,
                        status=status, include_gated=include_gated))


@queue_app.command("report")
def queue_report(
    subsystem: Annotated[str, typer.Option(help="Restrict to one subsystem")] = "",
    project: ProjectOpt = None, json_out: JsonOpt = False,
):
    """Tier and status cross-tab."""
    from ..pipeline.queue import report

    out.set_json(json_out)
    out.emit(report(_open(project), subsystem=subsystem))


@queue_app.command("set")
def queue_set(
    addr: Annotated[str, typer.Argument(help="Function address")],
    status: Annotated[str, typer.Option(help="New status")] = "",
    note: Annotated[str, typer.Option(help="Short note")] = "",
    tier: Annotated[str, typer.Option(help="New tier")] = "",
    project: ProjectOpt = None, json_out: JsonOpt = False,
):
    """Override one function's queue record."""
    from ..core.db import addr_str, parse_addr
    from ..pipeline.queue import set_status

    out.set_json(json_out)
    proj = _open(project)
    a = parse_addr(addr)
    try:
        row = set_status(proj, a, status=status or None, note=note or None, tier=tier or None)
    except ValueError as exc:
        out.fail(str(exc))
    out.emit(f"{addr_str(a)}\t{row.get('tier')}\t{row.get('status')}")


# ---------------------------------------------------------------------- port
@app.command()
def packet(
    addr: Annotated[str, typer.Argument(help="Function address")],
    form: Annotated[str, typer.Option(help="c | asm | both")] = "",
    show: Annotated[bool, typer.Option(help="Print the packet itself")] = False,
    project: ProjectOpt = None, json_out: JsonOpt = False,
):
    """Build one packet and report what it costs."""
    from ..core.db import parse_addr
    from ..views.packet import build as build_packet

    out.set_json(json_out)
    pk = build_packet(_open(project), parse_addr(addr), form=form)
    out.emit(pk.text if show and not json_out else pk)


@app.command()
def port(
    addrs: Annotated[list[str] | None, typer.Argument(help="Addresses to port")] = None,
    next_n: Annotated[int, typer.Option("--next", help="Take the next N from the queue")] = 0,
    tier: Annotated[str, typer.Option(help="Restrict the queue pick to a tier")] = "",
    subsystem: Annotated[str, typer.Option(help="Restrict to one subsystem")] = "",
    provider: Annotated[str, typer.Option(help="claude | codex | replay")] = "",
    model: Annotated[str, typer.Option(help="Explicit model override")] = "",
    model_tier: Annotated[str, typer.Option("--tier-override", help="small | mid | strong")] = "",
    out_dir: Annotated[Path | None, typer.Option("--out", help="Where to write ports")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Build packets, make no calls")] = False,
    project: ProjectOpt = None, json_out: JsonOpt = False,
):
    """Ask a model for ports, check them, and record what happened.

    This is the only command that spends tokens.
    """
    from ..core.db import parse_addr
    from ..pipeline.port import port_many
    from ..pipeline.queue import next_items

    out.set_json(json_out)
    proj = _open(project)

    targets: list[int] = [parse_addr(a) for a in (addrs or [])]
    if next_n:
        picks = next_items(proj, tier=tier, limit=next_n, subsystem=subsystem)
        targets.extend(i.addr for i in picks.items)
    if not targets:
        out.fail("nothing to port: pass addresses or --next N")

    out.emit(port_many(proj, targets, provider_name=provider or None, model=model,
                       tier=model_tier, out_dir=out_dir, dry_run=dry_run))


@app.command()
def brief(
    show: Annotated[bool, typer.Option(help="Print the prefix itself")] = False,
    project: ProjectOpt = None, json_out: JsonOpt = False,
):
    """The stable prefix every call rides on."""
    from ..llm.prefix import build as build_prefix

    out.set_json(json_out)
    proj = _open(project)
    pf = build_prefix(proj)
    path = proj.state / "brief.md"
    path.write_text(pf.text)
    out.emit(pf.text if show and not json_out else pf)


# ------------------------------------------------------- build / verify loop
@app.command()
def build(
    host: Annotated[str, typer.Option(help="Host from decomp.toml, or local")] = "",
    target: Annotated[list[str] | None, typer.Option("--target", help="Build targets")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show what would run")] = False,
    project: ProjectOpt = None, json_out: JsonOpt = False,
):
    """Compile the written ports and prove the binary actually changed."""
    from ..pipeline.build import run as run_build

    out.set_json(json_out)
    result = run_build(_open(project), host=host, targets=list(target or []),
                       dry_run=dry_run)
    out.emit(result)
    raise typer.Exit(0 if result.ok else 1)


@app.command()
def session(
    label: Annotated[str, typer.Option(help="Name for this run")] = "",
    profile: Annotated[str, typer.Option(help="boot | play | map")] = "play",
    host: Annotated[str, typer.Option(help="Host from decomp.toml")] = "",
    duration: Annotated[int, typer.Option(help="Seconds to run")] = 120,
    controls: Annotated[int, typer.Option(help="Deliberately wrong ports to arm")] = 2,
    allow_stale: Annotated[bool, typer.Option("--allow-stale",
                           help="Run even if the armed set is not in the binary")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    project: ProjectOpt = None, json_out: JsonOpt = False,
):
    """Run the program with the candidate ports armed, plus controls."""
    from ..pipeline.session import run as run_session

    out.set_json(json_out)
    result = run_session(_open(project), label=label, profile=profile, host=host,
                         duration_s=duration, controls=controls,
                         allow_stale=allow_stale, dry_run=dry_run)
    out.emit(result)
    raise typer.Exit(0 if result.ok else 1)


@app.command()
def verify(
    session_id: Annotated[int, typer.Option("--session", help="Session id")] = 0,
    log: Annotated[Path | None, typer.Option(help="Read a log file directly")] = None,
    no_controls: Annotated[bool, typer.Option("--no-controls",
                           help="Record verdicts without a passing control")] = False,
    project: ProjectOpt = None, json_out: JsonOpt = False,
):
    """Turn a session log into verdicts, if the session could have failed."""
    from ..pipeline.verify import run as run_verify

    out.set_json(json_out)
    result = run_verify(_open(project), session_id=session_id or None,
                        log_path=str(log) if log else "",
                        require_controls=not no_controls)
    out.emit(result)
    raise typer.Exit(0 if result.trusted else 1)


@app.command()
def promote(
    min_calls: Annotated[int, typer.Option(help="Override the call threshold")] = 0,
    min_ratio: Annotated[float, typer.Option(help="Override calls per line")] = 0.0,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Decide without writing")] = False,
    project: ProjectOpt = None, json_out: JsonOpt = False,
):
    """Decide which verified ports have enough evidence to run for real."""
    from ..pipeline.promote import run as run_promote

    out.set_json(json_out)
    out.emit(run_promote(_open(project), min_calls=min_calls, min_ratio=min_ratio,
                         dry_run=dry_run))


@app.command()
def hosts(
    add: Annotated[str, typer.Option(help="Name for a new host")] = "",
    ssh: Annotated[str, typer.Option(help="user@host")] = "",
    workdir: Annotated[str, typer.Option(help="Remote working directory")] = "",
    check: Annotated[bool, typer.Option(help="Test each configured host")] = False,
    project: ProjectOpt = None, json_out: JsonOpt = False,
):
    """Configure or test the machines stages can run on."""
    from ..core.remote import transport_for

    out.set_json(json_out)
    proj = _open(project)

    if add:
        lines = [f'\n[hosts.{add}]', f'ssh = "{ssh}"']
        if workdir:
            lines.append(f'workdir = "{workdir}"')
        with open(proj.root / "decomp.toml", "a") as f:
            f.write("\n".join(lines) + "\n")
        out.emit(f"host\t{add}\t{ssh}\tadded to decomp.toml")
        return

    rows = []
    names = list(proj.get("hosts", {}) or {}) or ["local"]
    for name in names:
        transport = transport_for(proj, name if name != "local" else "")
        if check:
            result = transport.check()
            rows.append(f"{name}\t{'reachable' if result.ok else 'unreachable'}"
                        f"\t{transport.host.ssh or 'local'}")
        else:
            rows.append(f"{name}\t{transport.host.ssh or 'local'}"
                        f"\t{transport.host.workdir}")
    out.emit("\n".join(rows))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
