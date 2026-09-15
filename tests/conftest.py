from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def project(tmp_path):
    """A fresh initialized project in a temp dir."""
    from decomp.pipeline.init_project import init

    init(tmp_path, target="xex", name="testproj")
    from decomp.core.config import open_project

    return open_project(tmp_path)


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES
