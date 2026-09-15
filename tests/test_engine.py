from __future__ import annotations

import pytest

# The engine needs a JVM and a Ghidra install, so these are opt-in: they run
# when the tooling is present and skip cleanly when it is not.
pytest.importorskip("pyghidra")

from decomp.pipeline.doctor import find_ghidra, find_jdk  # noqa: E402

pytestmark = pytest.mark.skipif(
    find_ghidra() is None or find_jdk() is None,
    reason="needs a Ghidra install and a JDK 21+",
)

FUNCTIONS = {
    0x82000000: "get_count",
    0x82000008: "set_flags",
    0x82000018: "sum_chain",
    0x82000048: "caller",
    0x82000074: "classify",
}


@pytest.fixture(scope="module")
def engine(tmp_path_factory, request):
    from decomp.adapters.engine.ghidra import GhidraEngine

    image = request.config.rootpath / "tests/fixtures/mini_ppc/mini.bin"
    project_dir = tmp_path_factory.mktemp("ghidra")
    eng = GhidraEngine()
    eng.open(str(image), 0x82000000, "PowerPC:BE:32:default", str(project_dir),
             analyze=False)
    yield eng
    eng.close()


def test_image_loads_at_the_requested_base(engine):
    """A program based at zero would make every recorded guest address wrong."""
    assert int(engine._program.getImageBase().getOffset()) == 0x82000000


def test_known_entry_points_become_functions(engine):
    """Disassembly first: a function cannot be created over bytes that are still
    data, which is the quiet way this returns zero."""
    created = engine.define_functions(list(FUNCTIONS))
    assert created == len(FUNCTIONS)
    # Idempotent: asking again creates nothing.
    assert engine.define_functions(list(FUNCTIONS)) == 0


def test_field_offsets_survive_decompilation(engine):
    engine.define_functions(list(FUNCTIONS))
    result = engine.decompile(0x82000000)
    assert result.ok
    # get_count reads the second field of a three-field struct.
    assert "+ 4" in result.c
    assert result.signature


def test_control_flow_is_recovered(engine):
    engine.define_functions(list(FUNCTIONS))
    loop = engine.decompile(0x82000018)
    assert loop.ok and ("while" in loop.c or "do" in loop.c or "for" in loop.c)

    switch = engine.decompile(0x82000074)
    assert switch.ok and "return" in switch.c


def test_names_are_applied_before_decompiling(engine):
    engine.define_functions(list(FUNCTIONS))
    assert engine.apply_names(FUNCTIONS) == len(FUNCTIONS)
    # The fixture is unrelocated, so call sites inside it point at zero and
    # cannot show a callee's name. What the rename must change is the
    # function's own signature.
    result = engine.decompile(0x82000048)
    assert result.ok
    assert "caller" in result.signature


def test_missing_function_is_reported_not_raised(engine):
    result = engine.decompile(0x8FFFFFFF)
    assert not result.ok
    assert "no function" in result.error


def test_helper_fix_is_recorded_so_the_guard_can_check_it(engine):
    """Without the fix most functions get wrong parameters and every struct
    offset read from them is silently wrong, so a lesson guards it."""
    # No save/restore stubs in this fixture, so the count is zero; what matters
    # is that the call is safe and reports honestly.
    assert engine.fix_helpers() == 0


def test_analyze_stage_end_to_end(project, request, tmp_path, engine):
    """Import an image, decompile it, and build a packet from the result.

    The engine is passed in: a JVM holds one program at a time, so a second
    open in the same process is both slow and an error.
    """
    from decomp.pipeline.analyze import run as run_analyze
    from decomp.pipeline.importer import import_image
    from decomp.views.packet import build as build_packet

    image = request.config.rootpath / "tests/fixtures/mini_ppc/mini.bin"
    project.config["target"]["ghidra_lang"] = "PowerPC:BE:32:default"
    import_image(project, path=image, base=0x82000000, name="mini")

    for addr in FUNCTIONS:
        project.db.upsert("function", {"addr": addr, "in_corpus": 1}, "addr")

    result = run_analyze(project, engine=engine)
    assert result.decompiled == len(FUNCTIONS), result.brief()
    assert result.failed == 0

    cached = project.db.query("SELECT * FROM view_cache WHERE kind='ghidra_c'")
    assert len(cached) == len(FUNCTIONS)
    assert all(row["tokens"] > 0 for row in cached)

    # A packet built from a freshly decompiled function, with no lifted corpus
    # to fall back on, still carries its C body.
    project.db.meta_set("truth.lifted_dir", str(tmp_path))
    packet = build_packet(project, 0x82000000)
    assert packet.tokens > 0
    assert "get_count" in packet.text or "param_1" in packet.text


def test_the_engine_project_is_not_under_a_dot_directory(project):
    """Ghidra refuses any path element starting with a dot, so the engine's
    project cannot live under .decomp. This failed only when analyze was first
    run against a real image."""
    path = project.ghidra_dir
    assert path.is_dir()
    assert not any(part.startswith(".") for part in path.parts[1:]), path
    assert ".decomp" not in str(path)


def test_init_ignores_the_generated_directories(tmp_path):
    from decomp.pipeline.init_project import init

    init(tmp_path, target="xex")
    ignored = (tmp_path / ".gitignore").read_text()
    for entry in (".decomp/", "ghidra/", "out/"):
        assert entry in ignored
