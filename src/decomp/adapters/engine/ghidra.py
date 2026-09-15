"""Ghidra through PyGhidra, in this process.

Three things the audio project established, kept here because each one cost a
session to learn:

  * Import with analysis off. Auto-analysis over an 18 MB image with 47,652
    functions is expensive and pointless when the entry points are already known
    from the recompiler's output.
  * Fix the register-save stubs before decompiling anything. Xenon prologues
    call __savegprlr_* helpers with a non-standard convention; Ghidra models them
    as ordinary functions, so the first argument in r3 is replaced by a fake
    return value. Without the fix most functions get wrong parameters, and every
    struct offset read from them is silently wrong.
  * Apply recovered names before decompiling, so call sites read as names rather
    than addresses.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .base import AnalysisEngine, DecompResult, EngineInfo

if TYPE_CHECKING:
    from ...core.config import Project

# Stubs that save and restore callee-saved registers. Modelling them as ordinary
# functions is what corrupts parameter recovery across a whole corpus.
DEFAULT_HELPER_PREFIXES = (
    "__savegprlr_", "__restgprlr_",
    "__savefpr_", "__restfpr_",
    "__savevmx_", "__restvmx_",
)


class GhidraEngine(AnalysisEngine):
    id = "ghidra"

    def __init__(self, install_dir: str = "", java_home: str = ""):
        # Discover rather than demand. Requiring an environment variable for an
        # install in a standard place is a setup step that earns nothing.
        self.install_dir = install_dir or os.environ.get("GHIDRA_INSTALL_DIR", "") \
            or _discover_ghidra()
        self.java_home = java_home or os.environ.get("JAVA_HOME", "") \
            or _discover_jdk()
        self._started = False
        self._program: Any = None
        self._project: Any = None
        self._flat: Any = None
        self._decompiler: Any = None
        self._monitor: Any = None

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        if self._started:
            return
        if not self.install_dir:
            raise RuntimeError(
                "no Ghidra install found: set GHIDRA_INSTALL_DIR, or "
                "engine.ghidra_dir in decomp.toml"
            )
        os.environ["GHIDRA_INSTALL_DIR"] = self.install_dir
        if self.java_home:
            os.environ["JAVA_HOME"] = self.java_home
        import pyghidra

        pyghidra.start(verbose=False)
        self._started = True

    def open(self, image: str, base: int, language: str, project_dir: str,
             analyze: bool = False) -> EngineInfo:
        """Open (or create) a project and load the image at its base address."""
        self.start()
        import pyghidra

        project_path = Path(project_dir)
        project_path.mkdir(parents=True, exist_ok=True)

        self._context = pyghidra.open_program(
            image,
            project_location=str(project_path),
            project_name="decomp",
            language=language or None,
            loader="ghidra.app.util.opinion.BinaryLoader",
            analyze=analyze,
        )
        self._flat = self._context.__enter__()
        self._program = self._flat.getCurrentProgram()

        # The loader has no base-address option through this API, so the image
        # is rebased after loading. Guest addresses in every other table are
        # absolute, and a program based at zero would make all of them wrong.
        if base:
            self._rebase(base)

        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        self._monitor = ConsoleTaskMonitor()
        self._decompiler = DecompInterface()
        self._decompiler.openProgram(self._program)

        return EngineInfo(
            id=self.id,
            version=str(self._program.getDomainFile().getName()),
            program=str(self._program.getName()),
            language=str(self._program.getLanguageID()),
            functions=int(self._program.getFunctionManager().getFunctionCount()),
            analysis=analyze,
        )

    def _rebase(self, base: int) -> None:
        current = int(self._program.getImageBase().getOffset())
        if current == base:
            return
        transaction = self._program.startTransaction("set image base")
        try:
            self._program.setImageBase(self._addr_in(base), True)
        finally:
            self._program.endTransaction(transaction, True)

    def _addr_in(self, value: int):
        """An address in the program's default space, usable before rebasing."""
        return self._program.getAddressFactory().getDefaultAddressSpace() \
            .getAddress(value)

    def close(self) -> None:
        if self._decompiler is not None:
            self._decompiler.dispose()
            self._decompiler = None
        if getattr(self, "_context", None) is not None:
            try:
                self._context.__exit__(None, None, None)
            except Exception:
                pass
            self._context = None
        self._program = None

    # ------------------------------------------------------------- mutation
    def _addr(self, value: int):
        return self._program.getAddressFactory().getDefaultAddressSpace() \
            .getAddress(value)

    def define_functions(self, addrs: list[int]) -> int:
        """Disassemble at each known entry point and create a function there.

        Cheaper and more accurate than asking Ghidra to find them: the
        recompiler already resolved every boundary. The disassembly step is not
        optional - a function cannot be created over bytes that are still data,
        which is the quiet way this returns zero.
        """
        manager = self._program.getFunctionManager()
        created = 0
        transaction = self._program.startTransaction("define functions")
        try:
            for value in addrs:
                address = self._addr(value)
                if manager.getFunctionAt(address) is not None:
                    continue
                if self._program.getListing().getInstructionAt(address) is None:
                    try:
                        self._flat.disassemble(address)
                    except Exception:
                        continue
                try:
                    if self._flat.createFunction(address, f"sub_{value:08X}") is not None:
                        created += 1
                except Exception:
                    continue
        finally:
            self._program.endTransaction(transaction, True)
        return created

    def apply_names(self, names: dict[int, str]) -> int:
        from ghidra.program.model.symbol import SourceType

        manager = self._program.getFunctionManager()
        applied = 0
        transaction = self._program.startTransaction("apply names")
        try:
            for value, name in names.items():
                function = manager.getFunctionAt(self._addr(value))
                if function is None:
                    continue
                try:
                    function.setName(name, SourceType.USER_DEFINED)
                    applied += 1
                except Exception:
                    continue
        finally:
            self._program.endTransaction(transaction, True)
        return applied

    def fix_helpers(self, prefixes: list[str] | None = None) -> int:
        """Mark register-save stubs as void, parameterless and inline.

        Without this, `bl __savegprlr_26` decompiles as an assignment from a
        function call, the real first argument in r3 is lost, and parameter
        recovery is wrong for most of the corpus.
        """
        from ghidra.program.model.symbol import SourceType

        prefixes = tuple(prefixes or DEFAULT_HELPER_PREFIXES)
        manager = self._program.getFunctionManager()
        fixed = 0
        transaction = self._program.startTransaction("fix helpers")
        try:
            for function in manager.getFunctions(True):
                name = str(function.getName())
                if not name.startswith(prefixes):
                    continue
                try:
                    function.setReturnType(
                        self._program.getDataTypeManager().getDataType("/void"),
                        SourceType.USER_DEFINED,
                    )
                except Exception:
                    pass
                try:
                    function.replaceParameters(
                        [], function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True, SourceType.USER_DEFINED,
                    )
                except Exception:
                    pass
                try:
                    function.setInline(True)
                    function.setNoReturn(False)
                except Exception:
                    pass
                fixed += 1
        finally:
            self._program.endTransaction(transaction, True)
        return fixed

    # ----------------------------------------------------------- decompiling
    def decompile(self, addr: int, timeout_s: int = 60) -> DecompResult:
        started = time.time()
        function = self._program.getFunctionManager().getFunctionAt(self._addr(addr))
        if function is None:
            return DecompResult(addr=addr, ok=False, error="no function at address")

        results = self._decompiler.decompileFunction(function, timeout_s, self._monitor)
        duration = int((time.time() - started) * 1000)
        if not results.decompileCompleted():
            return DecompResult(
                addr=addr, ok=False, duration_ms=duration,
                error=str(results.getErrorMessage() or "decompilation did not complete"),
            )

        decompiled = results.getDecompiledFunction()
        callees = []
        try:
            for callee in function.getCalledFunctions(self._monitor):
                callees.append(int(callee.getEntryPoint().getOffset()))
        except Exception:
            pass

        return DecompResult(
            addr=addr, ok=True, c=str(decompiled.getC()),
            signature=str(decompiled.getSignature()), callees=callees,
            duration_ms=duration,
        )


def _discover_ghidra() -> str:
    from ...pipeline.doctor import find_ghidra

    found = find_ghidra()
    return str(found) if found else ""


def _discover_jdk() -> str:
    from ...pipeline.doctor import find_jdk

    found = find_jdk()
    return str(found[0]) if found else ""


def from_project(project: Project) -> GhidraEngine:
    return GhidraEngine(
        install_dir=project.get("engine.ghidra_dir", ""),
        java_home=project.get("engine.java_home", ""),
    )
