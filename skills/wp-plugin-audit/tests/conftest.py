from __future__ import annotations

import re
from pathlib import Path

import pytest
from _php import Index, build_index, tree_sitter_available

FIXTURES = Path(__file__).parent / "fixtures"
BACKENDS = ["regex"] + (["treesitter"] if tree_sitter_available() else [])


@pytest.fixture(params=BACKENDS)
def backend(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.fixture
def index_of(backend: str):
    def _index(name: str) -> Index:
        return build_index(FIXTURES / name, backend)

    return _index


def marker_lines(name: str, marker: str) -> list[int]:
    """1-based lines of the fixture's PHP file that carry ``// <marker>``."""
    text = (FIXTURES / name / f"{name}.php").read_text().splitlines()
    return [i + 1 for i, line in enumerate(text) if re.search(rf"//\s*{marker}\b", line)]
