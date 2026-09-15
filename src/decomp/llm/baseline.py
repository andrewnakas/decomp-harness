"""Reconstruct the manual baseline from Claude Code transcripts.

To claim the harness is cheaper we need the number it is cheaper than. Claude
Code writes one JSONL per session under ~/.claude/projects/<slugged-path>/;
every assistant message carries a usage block. Summing those over the sessions
that did the work gives tokens spent, which divided by functions verified gives
the baseline this harness is measured against.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

PROJECTS_DIR = Path.home() / ".claude" / "projects"

# Relative price of each token kind, against fresh input at 1.0. A cached read
# costs a small fraction of a fresh one, and output costs several times more, so
# summing the four kinds and calling the result "tokens" overstates a
# cache-heavy session by a wide margin. These are the published ratios rounded
# to something defensible across the current model line.
PRICE_WEIGHTS = {
    "input": 1.0,
    "cache_read": 0.1,
    "cache_write": 1.25,
    "output": 5.0,
}


def weighted(input_tokens: int, cache_read: int, cache_write: int,
             output: int) -> int:
    """Tokens expressed as their equivalent in fresh input tokens.

    This is the number worth comparing between two ways of doing the same work.
    A raw sum would say a session that read 479 million cached tokens cost
    eighty times what it did.
    """
    return round(
        input_tokens * PRICE_WEIGHTS["input"]
        + cache_read * PRICE_WEIGHTS["cache_read"]
        + cache_write * PRICE_WEIGHTS["cache_write"]
        + output * PRICE_WEIGHTS["output"]
    )


def slug_for(path: Path | str) -> str:
    """Claude Code's directory naming: absolute path with separators as dashes."""
    return str(Path(path).resolve()).replace("/", "-")


@dataclass
class SessionUsage:
    session: str
    path: Path
    messages: int = 0
    input_tokens: int = 0
    cache_read: int = 0
    cache_write: int = 0
    output_tokens: int = 0
    models: dict[str, int] = field(default_factory=dict)
    first_ts: str = ""
    last_ts: str = ""

    @property
    def total(self) -> int:
        """Raw sum of every token kind. Use `cost_weighted` for comparisons."""
        return self.input_tokens + self.cache_read + self.cache_write + self.output_tokens

    @property
    def cost_weighted(self) -> int:
        return weighted(self.input_tokens, self.cache_read, self.cache_write,
                        self.output_tokens)


@dataclass
class BaselineReport:
    sessions: list[SessionUsage]
    verified: int = 0
    label: str = ""

    @property
    def input_tokens(self) -> int:
        return sum(s.input_tokens for s in self.sessions)

    @property
    def cache_read(self) -> int:
        return sum(s.cache_read for s in self.sessions)

    @property
    def cache_write(self) -> int:
        return sum(s.cache_write for s in self.sessions)

    @property
    def output_tokens(self) -> int:
        return sum(s.output_tokens for s in self.sessions)

    @property
    def total(self) -> int:
        return sum(s.total for s in self.sessions)

    @property
    def cost_weighted(self) -> int:
        return weighted(self.input_tokens, self.cache_read, self.cache_write,
                        self.output_tokens)

    @property
    def per_verified(self) -> float | None:
        """Cost-weighted tokens per verified function, which is the comparable
        figure. The raw total is reported alongside but is not what anyone
        pays."""
        if not self.verified:
            return None
        return round(self.cost_weighted / self.verified, 1)

    def brief(self) -> str:
        lines = [
            f"baseline\t{self.label}",
            f"sessions\t{len(self.sessions)}",
            f"messages\t{sum(s.messages for s in self.sessions)}",
            f"tokens\tin={self.input_tokens} cache_r={self.cache_read} "
            f"cache_w={self.cache_write} out={self.output_tokens}",
            f"raw total\t{self.total}",
            f"cost-weighted\t{self.cost_weighted}\t(cache reads at a tenth, "
            f"output at five times)",
        ]
        if self.verified:
            lines.append(f"verified\t{self.verified}")
            lines.append(f"weighted/verified\t{self.per_verified:.0f}")
            lines.append(
                "caveat\tthis counts everything those sessions did, not only "
                "the work being compared. Narrow it with --since and --until, "
                "or by scanning fewer project directories, before quoting it."
            )
        return "\n".join(lines)


def _ts_date(ts: str) -> date | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def scan_session(path: Path, since: date | None = None,
                 until: date | None = None) -> SessionUsage | None:
    """Sum usage across one transcript, optionally restricted to a date range."""
    usage = SessionUsage(session=path.stem, path=path)
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("type") != "assistant":
                continue
            ts = rec.get("timestamp", "") or ""
            day = _ts_date(ts)
            if since and day and day < since:
                continue
            if until and day and day > until:
                continue
            msg = rec.get("message") or {}
            u = msg.get("usage") or {}
            if not u:
                continue
            usage.messages += 1
            usage.input_tokens += int(u.get("input_tokens", 0) or 0)
            usage.cache_read += int(u.get("cache_read_input_tokens", 0) or 0)
            usage.cache_write += int(u.get("cache_creation_input_tokens", 0) or 0)
            usage.output_tokens += int(u.get("output_tokens", 0) or 0)
            model = msg.get("model") or "unknown"
            usage.models[model] = usage.models.get(model, 0) + 1
            if ts:
                usage.first_ts = usage.first_ts or ts
                usage.last_ts = ts
    return usage if usage.messages else None


def scan_projects(paths: list[Path | str], since: date | None = None,
                  until: date | None = None,
                  projects_dir: Path = PROJECTS_DIR) -> list[SessionUsage]:
    """Scan transcripts for the given project directories (real paths, not slugs)."""
    sessions: list[SessionUsage] = []
    for p in paths:
        # Accept either a real project path or an already-slugged directory name.
        candidate = projects_dir / slug_for(p)
        if not candidate.is_dir():
            direct = projects_dir / str(p)
            candidate = direct if direct.is_dir() else candidate
        if not candidate.is_dir():
            continue
        for jsonl in sorted(candidate.glob("*.jsonl")):
            su = scan_session(jsonl, since=since, until=until)
            if su:
                sessions.append(su)
    return sessions


def build(paths: list[Path | str], verified: int = 0, since: date | None = None,
          until: date | None = None, label: str = "") -> BaselineReport:
    sessions = scan_projects(paths, since=since, until=until)
    return BaselineReport(
        sessions=sessions,
        verified=verified,
        label=label or ", ".join(str(p) for p in paths),
    )
