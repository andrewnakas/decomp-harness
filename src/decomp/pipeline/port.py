"""`decomp port`: the one step that spends tokens.

Everything before this was mechanical. Here the harness hands a model a packet
and asks for judgment, then refuses to believe the answer until it has been
checked. The order matters: lint before build, build before session, session
before a verdict is recorded.

Retries send only what changed. A model that has already seen the packet does
not need it again; it needs to know what was wrong.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..core.db import addr_str
from ..core.stages import now_iso
from ..llm import ledger
from ..llm.schemas import PortAnswer, json_schema, parse_port_answer
from ..port import emit, lint

if TYPE_CHECKING:
    from ..core.config import Project

MAX_ATTEMPTS = 3
# Structured output is delivered as a tool call, which costs a turn of its own.
# A budget of 1 starves it and the call ends as error_max_turns having produced
# nothing but thinking.
PORT_MAX_TURNS = 4

# How long to wait for one answer, by tier. A cheap call that has not answered
# in three minutes is not about to: one real run lost fifteen minutes to a
# single hung call before giving up on it.
TIMEOUT_BY_TIER = {"small": 240, "mid": 420, "strong": 900}


@dataclass
class PortOutcome:
    addr: int
    ok: bool
    status: str
    attempts: int = 0
    tokens: int = 0
    cost_usd: float = 0.0
    path: Path | None = None
    error: str = ""
    blocked: str = ""
    note: str = ""
    model: str = ""

    def brief(self) -> str:
        head = addr_str(self.addr)
        if self.ok:
            how = "translated" if self.model == "mechanical" else self.status
            tail = f"{how}\t{self.path.name if self.path else ''}"
        elif self.blocked:
            tail = f"{self.blocked}\t{self.note[:60]}"
        else:
            tail = f"FAILED\t{self.error[:80]}"
        return f"{head}\t{tail}\t{self.attempts} attempt(s)\t{self.tokens} tok"


@dataclass
class PortRunResult:
    outcomes: list[PortOutcome] = field(default_factory=list)

    @property
    def written(self) -> int:
        return sum(1 for o in self.outcomes if o.ok)

    @property
    def blocked(self) -> int:
        return sum(1 for o in self.outcomes if o.blocked)

    @property
    def failed(self) -> int:
        return sum(1 for o in self.outcomes if not o.ok and not o.blocked)

    @property
    def tokens(self) -> int:
        return sum(o.tokens for o in self.outcomes)

    @property
    def cost(self) -> float:
        return sum(o.cost_usd for o in self.outcomes)

    @property
    def mechanical(self) -> int:
        return sum(1 for o in self.outcomes if o.ok and o.model == "mechanical")

    def brief(self) -> str:
        lines = [o.brief() for o in self.outcomes]
        summary = (
            f"--\twritten={self.written} blocked={self.blocked} failed={self.failed}"
            f"\t{self.tokens} tokens\t${self.cost:.4f}"
        )
        lines.append(summary)
        if self.mechanical:
            # Otherwise a run where every function translated mechanically looks
            # like the provider was asked and said nothing.
            lines.append(
                f"note\t{self.mechanical} of {self.written} translated without a "
                f"model; --no-draft asks one anyway"
            )
        if self.written:
            lines.append(
                f"per written port\t{self.tokens // max(1, self.written)} tokens"
            )
        return "\n".join(lines)


def try_draft(project: Project, addr: int, fn: dict,
              out_dir: Path) -> PortOutcome | None:
    """Translate mechanically if the function is simple enough.

    The cheapest token is the one never spent. Roughly one ungated function in
    eight is a thunk, getter or setter whose translation needs no judgment. The
    drafter refuses rather than guesses, so declining costs nothing.
    """
    from ..adapters.draft.lifted_to_native import LiftedToNative
    from ..adapters.groundtruth.lifted_rexglue import from_project as truth_from_project
    from ..llm.schemas import PortAnswer

    try:
        gt = truth_from_project(project)
    except KeyError:
        return None

    result = LiftedToNative().draft(
        addr, gt.body(addr),
        {"gate": fn.get("gate"), "has_vmx": bool(fn.get("vmx128"))},
    )
    if not hasattr(result, "code"):
        return None

    answer = PortAnswer(
        addr=f"{addr:08X}", code=result.code, windows=result.windows,
        result_registers=result.result_registers, note=result.note,
        confidence=result.confidence,
    )
    report = lint.check(
        answer, expected_addr=addr,
        budget_bytes=project.get("oracle.window_budget_bytes", 32768),
        budget_spans=project.get("oracle.window_budget_spans", 32),
    )
    if not report.ok:
        # A mechanical draft that fails its own lint is a bug in the drafter,
        # not a reason to ship it and let a session find out.
        return None

    artifact = emit.write(
        answer, addr, out_dir,
        macro=project.get("oracle.port_macro", "SKATE3_PORT"),
        status="written", provenance="mechanical translation, no model call",
    )
    _record(project, addr, answer, status="written", path=artifact.path, attempts=0)
    project.db.execute("UPDATE port SET source='mechanical' WHERE addr=?", (addr,))
    return PortOutcome(
        addr=addr, ok=True, status="written", attempts=0, tokens=0, cost_usd=0.0,
        path=artifact.path, note=result.note, model="mechanical",
    )


def port_one(project: Project, addr: int, provider_name: str = "",
             model: str = "", tier: str = "", out_dir: Path | None = None,
             max_attempts: int = MAX_ATTEMPTS, dry_run: bool = False,
             allow_draft: bool = True) -> PortOutcome:
    """Ask for one port, check it, and record what happened.

    A mechanical translation is tried first: if the function needs no judgment,
    no model is called and the port costs nothing.
    """
    from ..adapters.provider import LLMRequest, get_provider
    from ..llm import prefix as prefix_mod
    from ..queue import difficulty as difficulty_mod
    from ..views import packet as packet_mod

    fn = project.db.one("SELECT * FROM function WHERE addr=?", (addr,))
    if not fn:
        raise KeyError(f"{addr_str(addr)} is not in this project")

    provider = get_provider(project, provider_name or None)
    prefix = prefix_mod.build(project)
    schema = json_schema(PortAnswer)
    work_dir = project.work_dir / addr_str(addr)
    out_dir = Path(out_dir) if out_dir else project.sub("ports")

    if allow_draft and not dry_run:
        existing = project.db.one(
            "SELECT status FROM port WHERE addr=? AND source='mechanical'", (addr,)
        )
        if existing is None:
            drafted = try_draft(project, addr, fn, out_dir)
            if drafted is not None:
                return drafted

    resolved_tier = tier or difficulty_mod.tier_for(
        fn.get("difficulty") or 0.5, bool(fn.get("vmx128")), fn.get("attempts") or 0
    )

    outcome = PortOutcome(addr=addr, ok=False, status="pending")
    session_ref = ""
    feedback = ""
    divergence = ""

    for attempt in range(1, max_attempts + 1):
        outcome.attempts = attempt
        pkt = packet_mod.build(project, addr, divergence=divergence, attempt=attempt)

        if feedback:
            # A retry sends the correction only. The model has the packet in its
            # own context already, and resending it pays for it twice.
            prompt = (
                "Your previous answer for this function did not pass validation.\n"
                f"{feedback}\n\nReturn a corrected answer in the same schema."
            )
        else:
            prompt = pkt.text

        if dry_run:
            outcome.error = "dry run: no call made"
            outcome.tokens = pkt.tokens
            return outcome

        req = LLMRequest(
            prompt=prompt,
            prefix="" if session_ref else prefix.text,
            schema=schema,
            tier=resolved_tier,
            effort=difficulty_mod.effort_for(resolved_tier, retrying=bool(feedback)),
            model=model,
            max_turns=PORT_MAX_TURNS,
            cwd=work_dir,
            resume_session=session_ref,
            purpose="retry" if feedback else "port",
            addrs=[addr],
            cache_ttl=project.get("providers.claude.cache_ttl", "1h"),
            timeout_s=TIMEOUT_BY_TIER.get(resolved_tier, 420),
        )
        result = provider.call(req)
        ledger.record(project, provider.id, req, result, attempt=attempt,
                      packet_tokens_est=pkt.tokens)

        outcome.tokens += result.usage.input_tokens + result.usage.output_tokens
        outcome.cost_usd += result.cost_usd or 0.0
        outcome.model = result.model or resolved_tier
        session_ref = result.session_ref or session_ref

        if not result.ok:
            outcome.error = result.error or "provider call failed"
            feedback = ""
            continue

        try:
            answer = parse_port_answer(result.structured)
        except ValueError as exc:
            feedback = str(exc)
            outcome.error = feedback
            continue

        if answer.blocked:
            outcome.blocked = answer.blocked
            outcome.note = answer.note
            outcome.status = answer.blocked
            _record(project, addr, answer, status=answer.blocked, path=None,
                    attempts=attempt)
            return outcome

        report = lint.check(
            answer, expected_addr=addr,
            budget_bytes=project.get("oracle.window_budget_bytes", 32768),
            budget_spans=project.get("oracle.window_budget_spans", 32),
        )
        if not report.ok:
            feedback = report.feedback()
            outcome.error = feedback
            continue

        artifact = emit.write(
            answer, addr, out_dir,
            macro=project.get("oracle.port_macro", "SKATE3_PORT"),
            status="written",
            provenance=f"{provider.id} {outcome.model}, attempt {attempt}",
        )
        _record(project, addr, answer, status="written", path=artifact.path,
                attempts=attempt)
        outcome.ok = True
        outcome.status = "written"
        outcome.path = artifact.path
        outcome.note = answer.note
        outcome.error = ""
        return outcome

    _record(project, addr, None, status="needs_human", path=None,
            attempts=outcome.attempts, error=outcome.error)
    outcome.status = "needs_human"
    return outcome


def _record(project: Project, addr: int, answer: PortAnswer | None, status: str,
            path: Path | None, attempts: int, error: str = "") -> None:
    """Write what we learned, whether or not the port succeeded."""
    update: dict[str, Any] = {
        "addr": addr, "status": status, "attempts": attempts, "updated_at": now_iso(),
    }
    if answer:
        if answer.note:
            update["note"] = answer.note[:300]
        if answer.signature:
            update["signature"] = answer.signature[:200]
        if answer.blocked:
            update["gate"] = answer.blocked
            update["gate_reason"] = (answer.note or "")[:200]
    elif error:
        update["note"] = error[:300]
    project.db.upsert("function", update, "addr")

    if answer and path:
        project.db.upsert(
            "port",
            {
                "addr": addr, "path": str(path), "status": status,
                "result_mask": ",".join(answer.result_registers),
                "windows_json": json.dumps([w.model_dump() for w in answer.windows]),
                "lint_ok": 1, "source": "llm", "updated_at": now_iso(),
            },
            "addr",
        )

    if not answer:
        return

    # Findings are proposals until something confirms them, and they are stored
    # as such: an LLM-sourced name never displaces one resolved from the binary.
    for finding in answer.names:
        try:
            from ..core.db import parse_addr

            target = parse_addr(finding.addr)
        except ValueError:
            continue
        project.db.execute(
            "INSERT INTO symbol_evidence (addr, name, kind, source, confidence, "
            "created_at) VALUES (?,?,?,?,?,?)",
            (target, finding.name, "llm", f"port:{addr_str(addr)}",
             min(finding.confidence, 0.6), now_iso()),
        )

    for f in answer.fields:
        project.db.upsert("struct", {"name": f.struct, "origin": "llm"}, "name")
        struct_id = project.db.scalar("SELECT id FROM struct WHERE name=?", (f.struct,))
        existing = project.db.one(
            "SELECT * FROM struct_field WHERE struct_id=? AND offset=?",
            (struct_id, f.offset),
        )
        if existing and existing["status"] in ("established", "confirmed"):
            continue      # never overwrite a cited fact with a proposal
        project.db.upsert(
            "struct_field",
            {
                "struct_id": struct_id, "offset": f.offset, "size": f.size,
                "ctype": f.ctype, "name": f.name, "status": "proposed",
                "confidence": 0.5,
            },
            ("struct_id", "offset"),
        )


def port_batch(project: Project, addrs: list[int], provider_name: str = "",
               model: str = "", tier: str = "", out_dir: Path | None = None
               ) -> list[PortOutcome] | None:
    """Ask for several small functions in one call.

    The prefix is the same for every function in a run, and a provider that
    caches it well makes this barely matter. Codex opens a fresh session per
    invocation and cached only 54% of its input across a real run, so the fixed
    cost is paid again on every call; sharing it across a batch is where that
    goes back.

    Returns None when the batch cannot be used, so the caller falls back to
    asking one at a time rather than losing the work.
    """
    from ..adapters.provider import LLMRequest, get_provider
    from ..llm import prefix as prefix_mod
    from ..llm.schemas import BatchAnswer, json_schema, parse_batch_answer
    from ..queue import difficulty as difficulty_mod
    from ..views import packet as packet_mod

    if len(addrs) < 2:
        return None

    provider = get_provider(project, provider_name or None)
    prefix = prefix_mod.build(project)
    out_dir = Path(out_dir) if out_dir else project.sub("ports")
    work_dir = project.work_dir / f"batch_{addrs[0]:08X}"

    packets = []
    total_tokens = 0
    for addr in addrs:
        pkt = packet_mod.build(project, addr)
        packets.append(pkt.text)
        total_tokens += pkt.tokens
    if total_tokens > project.get("budget.packet_tokens_max", 6000):
        return None

    prompt = (
        f"{len(addrs)} functions follow. Answer all of them, as an object with a "
        f"`ports` array holding one entry per function in the order given.\n\n"
        + "\n\n".join(packets)
    )

    req = LLMRequest(
        prompt=prompt, prefix=prefix.text, schema=json_schema(BatchAnswer),
        tier=tier or "small", model=model, max_turns=PORT_MAX_TURNS,
        cwd=work_dir, purpose="batch", addrs=list(addrs),
        cache_ttl=project.get("providers.claude.cache_ttl", "1h"),
        effort=difficulty_mod.effort_for(tier or "small"),
        # A batch is several functions, so it earns more time than one.
        timeout_s=TIMEOUT_BY_TIER.get(tier or "small", 420) * 2,
    )
    result = provider.call(req)
    ledger.record(project, provider.id, req, result, packet_tokens_est=total_tokens)

    if not result.ok:
        return None
    try:
        answers = parse_batch_answer(result.structured)
    except ValueError:
        return None
    if len(answers) != len(addrs):
        # A short answer would silently drop functions from the round.
        return None

    # Cost is shared across the batch, so each port carries its own share.
    spent = result.usage.input_tokens + result.usage.output_tokens
    share_tokens = spent // len(addrs)
    share_cost = (result.cost_usd or 0.0) / len(addrs)

    outcomes: list[PortOutcome] = []
    for addr, answer in zip(addrs, answers, strict=True):
        outcome = PortOutcome(addr=addr, ok=False, status="pending", attempts=1,
                              tokens=share_tokens, cost_usd=share_cost,
                              model=result.model or "batch")
        if answer.blocked:
            outcome.blocked = answer.blocked
            outcome.status = answer.blocked
            outcome.note = answer.note
            _record(project, addr, answer, status=answer.blocked, path=None,
                    attempts=1)
            outcomes.append(outcome)
            continue

        report = lint.check(
            answer, expected_addr=addr,
            budget_bytes=project.get("oracle.window_budget_bytes", 32768),
            budget_spans=project.get("oracle.window_budget_spans", 32),
        )
        if not report.ok:
            # One bad answer does not spoil the batch: it is retried alone,
            # where a correction can be sent without re-sending the others.
            outcome.error = report.feedback()
            outcomes.append(outcome)
            continue

        artifact = emit.write(
            answer, addr, out_dir,
            macro=project.get("oracle.port_macro", "SKATE3_PORT"),
            status="written",
            provenance=f"{provider.id} {outcome.model}, batch of {len(addrs)}",
        )
        _record(project, addr, answer, status="written", path=artifact.path,
                attempts=1)
        outcome.ok = True
        outcome.status = "written"
        outcome.path = artifact.path
        outcome.note = answer.note
        outcomes.append(outcome)

    return outcomes


def port_many(project: Project, addrs: list[int], batch_size: int = 0,
              **kw: Any) -> PortRunResult:
    """Port a set of functions, batching the small ones where it pays."""
    from ..queue import difficulty as difficulty_mod

    batch_size = batch_size or project.get("budget.batch_size", 6)
    outcomes: list[PortOutcome] = []
    pending: list[int] = []

    def flush() -> None:
        """Send the accumulated batch, falling back to one at a time."""
        nonlocal pending
        if not pending:
            return
        group, pending = pending, []
        batched = None
        if len(group) > 1 and not kw.get("dry_run"):
            batched = port_batch(
                project, group,
                provider_name=kw.get("provider_name") or "",
                model=kw.get("model", ""), tier=kw.get("tier", ""),
                out_dir=kw.get("out_dir"),
            )
        if batched is None:
            for addr in group:
                outcomes.append(_one(addr))
            return
        for outcome in batched:
            # Anything the batch could not settle is asked again on its own.
            outcomes.append(outcome if outcome.ok or outcome.blocked
                            else _one(outcome.addr))

    def _one(addr: int) -> PortOutcome:
        try:
            return port_one(project, addr, **kw)
        except KeyError as exc:
            return PortOutcome(addr=addr, ok=False, status="error", error=str(exc))

    for addr in addrs:
        fn = project.db.one("SELECT * FROM function WHERE addr=?", (addr,)) or {}
        score = fn.get("difficulty") or 0.0

        # A function the translator can handle costs nothing, so it never goes
        # into a batch that would be paid for.
        if kw.get("allow_draft", True) and not kw.get("dry_run"):
            drafted = try_draft(project, addr, fn,
                                Path(kw.get("out_dir") or project.sub("ports")))
            if drafted is not None:
                outcomes.append(drafted)
                continue

        if difficulty_mod.batchable(fn, score,
                                    project.get("budget.batch_max_lines", 40)):
            pending.append(addr)
            if len(pending) >= batch_size:
                flush()
            continue

        flush()
        outcomes.append(_one(addr))

    flush()
    return PortRunResult(outcomes=outcomes)
