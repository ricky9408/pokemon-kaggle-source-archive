from __future__ import annotations

import tarfile
from pathlib import Path

from evaluation_v2.package import build_archive, inspect_archive, materialize_archive


def test_build_archive_is_deterministic_and_cache_free(tmp_path: Path) -> None:
    agent = tmp_path / "agent"
    (agent / "cg" / "__pycache__").mkdir(parents=True)
    (agent / "main.py").write_text("def agent(obs): return []\n")
    (agent / "deck.csv").write_text("\n".join(str(index) for index in range(60)))
    (agent / "cg" / "api.py").write_text("# api\n")
    (agent / "cg" / "libcg.so").write_bytes(b"native")
    (agent / "cg" / "__pycache__" / "api.pyc").write_bytes(b"cache")
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    assert build_archive(agent, first) == build_archive(agent, second)
    assert inspect_archive(first) == []
    with tarfile.open(first) as archive:
        assert "cg/__pycache__/api.pyc" not in archive.getnames()
    extracted = tmp_path / "extracted"
    materialize_archive(first, extracted)
    assert (extracted / "main.py").exists()
