"""Token ledger: every model call is recorded, so efficiency is measured.

The harness's whole claim is "fewer tokens per verified function". That number
comes from here, not from an estimate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..adapters.provider.base import LLMRequest, LLMResult
from ..core.hashing import sha256_text
from ..core.stages import now_iso
from ..core.tokens import calibrate

if TYPE_CHECKING:
    from ..core.config import Project


def record(project: Project, provider_id: str, req: LLMRequest, result: LLMResult,
           *, run_id: int | None = None, attempt: int = 1,
           packet_tokens_est: int = 0) -> int:
    """Write one llm_call row and refine the token estimator. Returns its id."""
    cur = project.db.execute(
        "INSERT INTO llm_call (ts, run_id, provider, model, purpose, addrs_json, "
        "packet_hash, packet_tokens_est, prefix_hash, input_tokens, cache_read_tokens, "
        "cache_write_tokens, output_tokens, cost_usd, session_ref, resumed, attempt, "
        "duration_ms, schema_ok, outcome, error, answer_path) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            now_iso(),
            run_id,
            provider_id,
            result.model or req.model or req.tier,
            req.purpose,
            json.dumps(req.addrs),
            sha256_text(req.prompt)[:16],
            packet_tokens_est,
            sha256_text(req.prefix)[:16] if req.prefix else "",
            result.usage.input_tokens,
            result.usage.cache_read_tokens,
            result.usage.cache_write_tokens,
            result.usage.output_tokens,
            result.cost_usd,
            result.session_ref,
            1 if req.resume_session else 0,
            attempt,
            result.duration_ms,
            1 if result.structured is not None else 0,
            "ok" if result.ok else "error",
            result.error[:500] if result.error else None,
            str(result.raw_path) if result.raw_path else None,
        ),
    )
    # `input_tokens` already excludes cache reads for both providers, so it is
    # the fresh count that corresponds to the packet we sent. Use it to refine
    # chars-per-token; skip resumed calls, where the ratio is meaningless.
    fresh = result.usage.input_tokens
    if not req.resume_session and fresh > 50 and req.prompt:
        calibrate(project, len(req.prompt), fresh)
    return int(cur.lastrowid)


@dataclass
class CostReport:
    calls: int
    input_tokens: int
    cache_read: int
    cache_write: int
    output_tokens: int
    cost_usd: float
    verified: int
    promoted: int
    mechanical: int
    baseline_per_verified: float | None = None
    rows: list[tuple] | None = None
    group_by: str = ""

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def per_verified(self) -> float | None:
        if not self.verified:
            return None
        return round(self.total_tokens / self.verified, 1)

    @property
    def cache_hit_rate(self) -> float:
        billed = self.input_tokens + self.cache_read
        return round(self.cache_read / billed, 3) if billed else 0.0

    def brief(self) -> str:
        lines = [
            f"calls\t{self.calls}",
            f"tokens\tin={self.input_tokens} cache_r={self.cache_read} "
            f"cache_w={self.cache_write} out={self.output_tokens}",
            f"cost\t${self.cost_usd:.4f}",
            f"cache_hit\t{self.cache_hit_rate:.1%}",
            f"verified\t{self.verified}\tpromoted\t{self.promoted}"
            f"\tzero_token\t{self.mechanical}",
        ]
        if self.per_verified is not None:
            lines.append(f"tokens/verified\t{self.per_verified:.0f}")
        if self.baseline_per_verified:
            lines.append(f"baseline/verified\t{self.baseline_per_verified:.0f}")
            if self.per_verified:
                ratio = self.baseline_per_verified / self.per_verified
                lines.append(f"improvement\t{ratio:.1f}x")
        if self.rows:
            lines.append("")
            lines.append(f"{self.group_by}\tcalls\tin\tcache_r\tout\tcost")
            for r in self.rows:
                lines.append("\t".join(str(c) for c in r))
        return "\n".join(lines)


def report(project: Project, group_by: str = "") -> CostReport:
    totals = project.db.one(
        "SELECT COUNT(*) AS calls, "
        "COALESCE(SUM(input_tokens),0) AS input_tokens, "
        "COALESCE(SUM(cache_read_tokens),0) AS cache_read, "
        "COALESCE(SUM(cache_write_tokens),0) AS cache_write, "
        "COALESCE(SUM(output_tokens),0) AS output_tokens, "
        "COALESCE(SUM(cost_usd),0) AS cost_usd FROM llm_call"
    ) or {}
    verified = project.db.scalar(
        "SELECT COUNT(*) FROM function WHERE status IN ('verified','promoted','thin')", (), 0
    )
    promoted = project.db.scalar(
        "SELECT COUNT(*) FROM function WHERE status='promoted'", (), 0
    )
    mechanical = project.db.scalar(
        "SELECT COUNT(*) FROM port WHERE source='mechanical'", (), 0
    )

    rows = None
    if group_by:
        column = {"model": "model", "purpose": "purpose", "provider": "provider"}.get(
            group_by, "model"
        )
        rows = [
            (
                r[column],
                r["calls"],
                r["input_tokens"],
                r["cache_read"],
                r["output_tokens"],
                f"{r['cost_usd']:.4f}",
            )
            for r in project.db.query(
                f"SELECT {column}, COUNT(*) AS calls, "
                "COALESCE(SUM(input_tokens),0) AS input_tokens, "
                "COALESCE(SUM(cache_read_tokens),0) AS cache_read, "
                "COALESCE(SUM(output_tokens),0) AS output_tokens, "
                "COALESCE(SUM(cost_usd),0) AS cost_usd "
                f"FROM llm_call GROUP BY {column} ORDER BY cost_usd DESC"
            )
        ]

    return CostReport(
        calls=int(totals.get("calls", 0)),
        input_tokens=int(totals.get("input_tokens", 0)),
        cache_read=int(totals.get("cache_read", 0)),
        cache_write=int(totals.get("cache_write", 0)),
        output_tokens=int(totals.get("output_tokens", 0)),
        cost_usd=float(totals.get("cost_usd", 0.0) or 0.0),
        verified=int(verified or 0),
        promoted=int(promoted or 0),
        mechanical=int(mechanical or 0),
        rows=rows,
        group_by=group_by,
    )
