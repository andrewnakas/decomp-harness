"""`decomp init`: create decomp.toml, the DB, and the state directory."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..core import lessons
from ..core.config import CONFIG_NAME, STATE_DIR, open_project

TEMPLATE = """# DecompHarness project
[project]
name = "{name}"
target_adapter = "{adapter}"

[target]
platform = "{platform}"
arch = "{arch}"
endian = "{endian}"
base_addr = {base}
ghidra_lang = "{lang}"
# image = "path/to/image.bin"
# recomp_path = "{recomp}"

[providers]
default = "claude"

[routing]
small = "haiku"
mid = "sonnet"
strong = "opus"

[budget]
packet_tokens_target = 1000
packet_tokens_max = 6000

[oracle]
adapter = "{oracle}"
promote_min_calls = 100
promote_min_calls_per_line = 1.0

# [hosts.linux]
# ssh = "user@host"
# workdir = "/home/user/Documents/skate3/skate3recomp-dev"
# build_dir = "out/build/linux-release-jammy"
"""

PRESETS = {
    "xex": {
        "platform": "xbox360",
        "arch": "ppc64",
        "endian": "big",
        "base": "0x82000000",
        "lang": "PowerPC:BE:64:A2ALT-32addr",
        "oracle": "rexglue_shadow",
    },
    "elf": {
        "platform": "generic",
        "arch": "x86_64",
        "endian": "little",
        "base": "0",
        "lang": "x86:LE:64:default",
        "oracle": "objdiff",
    },
    "rawimage": {
        "platform": "generic",
        "arch": "ppc64",
        "endian": "big",
        "base": "0",
        "lang": "PowerPC:BE:64:A2ALT-32addr",
        "oracle": "rexglue_shadow",
    },
}


@dataclass
class InitResult:
    root: Path
    created: bool
    lessons_seeded: int

    def brief(self) -> str:
        state = "created" if self.created else "already present"
        return (
            f"project\t{self.root}\t{state}\n"
            f"lessons\t{self.lessons_seeded} seeded\n"
            f"next\tdecomp doctor"
        )


def init(root: Path | str = ".", target: str = "rawimage", name: str = "",
         recomp: str = "", force: bool = False) -> InitResult:
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    cfg_path = root / CONFIG_NAME
    created = False
    if not cfg_path.is_file() or force:
        preset = PRESETS.get(target, PRESETS["rawimage"])
        cfg_path.write_text(
            TEMPLATE.format(
                name=name or root.name,
                adapter=target,
                recomp=recomp or "path/to/recomp",
                **preset,
            )
        )
        created = True
    (root / STATE_DIR).mkdir(exist_ok=True)
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text(
            "# decomp state and generated analysis\n"
            f"{STATE_DIR}/\n"
            "ghidra/\n"
            "out/\n"
        )
    project = open_project(root)
    seeded = lessons.seed(project)
    return InitResult(root=root, created=created, lessons_seeded=seeded)
