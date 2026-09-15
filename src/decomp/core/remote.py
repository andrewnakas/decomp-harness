"""Running a stage somewhere else.

Analysis happens on the machine with the corpus; builds and play sessions happen
on the machine with the toolchain and the game. The harness should not care
which is which, so a Host is either local or an ssh target and every stage takes
one.

Uses the system ssh and rsync rather than a library, so the user's own ssh
config, keys and agent apply without the harness knowing anything about them.
"""

from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Host

SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    host: str = "local"

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def tail(self, lines: int = 20, stream: str = "both") -> str:
        """The last few lines, which is where a build failure lives."""
        text = ""
        if stream in ("both", "stderr"):
            text += self.stderr
        if stream in ("both", "stdout"):
            text += self.stdout
        return "\n".join(text.splitlines()[-lines:])

    def brief(self) -> str:
        state = "ok" if self.ok else f"exit {self.returncode}"
        return f"{self.host}\t{state}\t{self.duration_s:.1f}s"


@dataclass
class Transport:
    """Runs commands and moves files, locally or over ssh."""

    host: Host
    dry_run: bool = False
    env: dict[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.host.name

    @property
    def is_local(self) -> bool:
        return self.host.is_local

    def workdir(self) -> str:
        return self.host.workdir or "."

    # ------------------------------------------------------------------ run
    def run(self, command: str | list[str], cwd: str = "", timeout: int = 1800,
            check: bool = False) -> CommandResult:
        """Run a shell command on this host.

        The exit status is returned, never asserted away. A build script that
        pipes through grep after `|| true` once reported success while the
        binary had not been rebuilt, and the next session silently ran the old
        one, so nothing here hides a status.
        """
        if isinstance(command, list):
            command = " ".join(shlex.quote(part) for part in command)
        directory = cwd or self.workdir()

        if self.is_local:
            argv = ["/bin/sh", "-c", command]
            run_cwd = directory if directory and Path(directory).is_dir() else None
        else:
            remote = f"cd {shlex.quote(directory)} && {command}" if directory else command
            argv = ["ssh", *SSH_OPTS, self.host.ssh, remote]
            run_cwd = None

        if self.dry_run:
            return CommandResult(argv=argv, returncode=0, stdout="(dry run)",
                                 host=self.name)

        started = time.time()
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout, cwd=run_cwd,
                env={**_environ(), **self.env} if self.env else None,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(argv=argv, returncode=124,
                                 stderr=f"timed out after {timeout}s",
                                 duration_s=timeout, host=self.name)
        result = CommandResult(
            argv=argv, returncode=proc.returncode, stdout=proc.stdout or "",
            stderr=proc.stderr or "", duration_s=round(time.time() - started, 2),
            host=self.name,
        )
        if check and not result.ok:
            raise RuntimeError(f"{self.name}: command failed: {result.tail(10)}")
        return result

    # ----------------------------------------------------------------- files
    def push(self, local: Path | str, remote: str, delete: bool = False) -> CommandResult:
        """Copy files to the host. A trailing slash on a directory copies its
        contents, as rsync means it."""
        local = str(local)
        if self.is_local:
            return self._local_copy(local, remote, delete)
        argv = ["rsync", "-a", "--mkpath"]
        if delete:
            argv.append("--delete")
        argv += ["-e", " ".join(["ssh", *SSH_OPTS]), local, f"{self.host.ssh}:{remote}"]
        return self._rsync(argv)

    def pull(self, remote: str, local: Path | str) -> CommandResult:
        local = str(local)
        Path(local).parent.mkdir(parents=True, exist_ok=True)
        if self.is_local:
            return self._local_copy(remote, local, delete=False)
        argv = [
            "rsync", "-a", "--mkpath", "-e", " ".join(["ssh", *SSH_OPTS]),
            f"{self.host.ssh}:{remote}", local,
        ]
        return self._rsync(argv)

    def _rsync(self, argv: list[str]) -> CommandResult:
        if self.dry_run:
            return CommandResult(argv=argv, returncode=0, stdout="(dry run)",
                                 host=self.name)
        started = time.time()
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=600)
        return CommandResult(
            argv=argv, returncode=proc.returncode, stdout=proc.stdout or "",
            stderr=proc.stderr or "", duration_s=round(time.time() - started, 2),
            host=self.name,
        )

    def _local_copy(self, src: str, dst: str, delete: bool) -> CommandResult:
        argv = ["rsync", "-a"]
        if delete:
            argv.append("--delete")
        argv += [src, dst]
        return self._rsync(argv)

    # ----------------------------------------------------------------- facts
    def exists(self, path: str) -> bool:
        return self.run(f"test -e {shlex.quote(path)}", timeout=60).ok

    def mtime(self, path: str) -> float | None:
        """Modification time, as a float. Used to prove a binary is not stale."""
        result = self.run(
            f"stat -c %Y {shlex.quote(path)} 2>/dev/null || "
            f"stat -f %m {shlex.quote(path)}",
            timeout=60,
        )
        if not result.ok:
            return None
        try:
            return float(result.stdout.strip().splitlines()[0])
        except (ValueError, IndexError):
            return None

    def symbols(self, binary: str, pattern: str = "") -> set[str]:
        """Defined text symbols in a binary, optionally filtered.

        An exit status says a build ran; this says what it actually produced.
        """
        cmd = f"nm -g --defined-only {shlex.quote(binary)} 2>/dev/null || nm {shlex.quote(binary)}"
        if pattern:
            cmd += f" | grep {shlex.quote(pattern)}"
        result = self.run(cmd, timeout=300)
        if not result.ok:
            return set()
        found = set()
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[-2].upper() in ("T", "W", "D", "B", "R"):
                found.add(parts[-1])
            elif len(parts) == 2 and parts[0].upper() in ("T", "W"):
                found.add(parts[1])
        return found

    def check(self) -> CommandResult:
        return self.run("true", timeout=20)


def _environ() -> dict[str, str]:
    import os

    return dict(os.environ)


def transport_for(project, host_name: str = "", dry_run: bool = False) -> Transport:
    return Transport(host=project.host(host_name or None), dry_run=dry_run)
