"""decomp.toml loading and the Project handle every stage receives."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .db import Db

CONFIG_NAME = "decomp.toml"
STATE_DIR = ".decomp"

DEFAULT_CONFIG: dict[str, Any] = {
    "project": {"name": "untitled", "target_adapter": "rawimage"},
    "target": {
        "platform": "generic",
        "arch": "ppc64",
        "endian": "big",
        "ptr_size": 4,
        "base_addr": 0,
        "ghidra_lang": "PowerPC:BE:64:A2ALT-32addr",
    },
    "providers": {
        "default": "claude",
        "claude": {"bin": "claude", "cache_ttl": "1h"},
        "codex": {"bin": "codex"},
    },
    # Model tiers are aliases, never hard-coded ids: the CLI resolves them.
    "routing": {
        "small": "haiku",
        "mid": "sonnet",
        "strong": "opus",
        "port_mid_max_lines": 120,
        "escalate_after_attempts": 2,
    },
    "budget": {
        "packet_tokens_target": 1000,
        "packet_tokens_max": 6000,
        "batch_max_lines": 40,
        "batch_size": 6,
    },
    "oracle": {
        "adapter": "rexglue_shadow",
        "promote_min_calls": 100,
        "promote_min_calls_per_line": 1.0,
        "window_budget_bytes": 32768,
        "window_budget_spans": 32,
    },
    "hosts": {},
}


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


@dataclass
class Host:
    """A machine a stage can run on. `ssh` empty means local."""

    name: str
    ssh: str = ""           # user@host
    workdir: str = ""       # remote path to the consumer repo
    build_dir: str = ""
    env: dict[str, str] = field(default_factory=dict)

    @property
    def is_local(self) -> bool:
        return not self.ssh


@dataclass
class Project:
    """Everything a pipeline stage needs: config, DB, paths."""

    root: Path
    config: dict[str, Any]
    db: Db

    # ------------------------------------------------------------------ paths
    @property
    def state(self) -> Path:
        p = self.root / STATE_DIR
        p.mkdir(parents=True, exist_ok=True)
        return p

    def sub(self, *parts: str) -> Path:
        p = self.state.joinpath(*parts)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def views_dir(self) -> Path:
        return self.sub("views")

    @property
    def packets_dir(self) -> Path:
        return self.sub("packets")

    @property
    def answers_dir(self) -> Path:
        return self.sub("answers")

    @property
    def runs_dir(self) -> Path:
        return self.sub("runs")

    @property
    def work_dir(self) -> Path:
        return self.sub("work")

    @property
    def prefix_dir(self) -> Path:
        return self.sub("prefix")

    # ----------------------------------------------------------------- config
    def get(self, path: str, default: Any = None) -> Any:
        """Dotted lookup: project.get('routing.small')."""
        cur: Any = self.config
        for part in path.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def host(self, name: str | None) -> Host:
        if not name or name == "local":
            return Host(name="local")
        h = self.get(f"hosts.{name}")
        if not h:
            raise KeyError(f"host '{name}' not in {CONFIG_NAME}; add it with `decomp hosts add`")
        return Host(
            name=name,
            ssh=h.get("ssh", ""),
            workdir=h.get("workdir", ""),
            build_dir=h.get("build_dir", ""),
            env=h.get("env", {}),
        )

    def target_row(self) -> dict[str, Any] | None:
        return self.db.one("SELECT * FROM target ORDER BY id LIMIT 1")


def find_project_root(start: Path | None = None) -> Path | None:
    """Walk up from `start` looking for decomp.toml."""
    cur = (start or Path(os.getcwd())).resolve()
    for candidate in [cur, *cur.parents]:
        if (candidate / CONFIG_NAME).is_file():
            return candidate
    return None


def load_config(root: Path) -> dict[str, Any]:
    cfg_path = root / CONFIG_NAME
    user = tomllib.loads(cfg_path.read_text()) if cfg_path.is_file() else {}
    return _deep_merge(DEFAULT_CONFIG, user)


def open_project(root: Path | str | None = None) -> Project:
    """Open the project rooted at `root` (or found by walking up from cwd)."""
    if root is None:
        found = find_project_root()
        if found is None:
            raise FileNotFoundError(
                f"no {CONFIG_NAME} found here or in any parent; run `decomp init` first"
            )
        root = found
    root = Path(root).resolve()
    config = load_config(root)
    db = Db(root / STATE_DIR / "db.sqlite")
    return Project(root=root, config=config, db=db)
