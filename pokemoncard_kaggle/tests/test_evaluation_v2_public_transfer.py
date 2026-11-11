import gzip
from pathlib import Path
import tarfile

from evaluation_v2.cohort import deck_sha256
from evaluation_v2.public_transfer import (
    archive_policy_identity,
    filter_panel_by_label,
    materialize_historical_archive,
    replay_started_at,
)


def _archive(path: Path, *, model: bytes = b"model") -> None:
    files = {
        "./main.py": b"def agent(obs): return [0]\n",
        "./deck.csv": "".join(f"{card}\n" for card in range(1, 61)).encode(),
        "./model.bin": model,
        "./cg/libcg.so": b"engine",
    }
    with gzip.open(path, "wb") as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, fileobj=__import__("io").BytesIO(data))


def test_archive_policy_identity_excludes_engine_and_hashes_full_policy(tmp_path: Path) -> None:
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    _archive(first, model=b"one")
    _archive(second, model=b"two")

    first_identity = archive_policy_identity(first)
    second_identity = archive_policy_identity(second)

    assert first_identity.deck_sha256 == deck_sha256(range(1, 61))
    assert first_identity.main_sha256 == second_identity.main_sha256
    assert first_identity.policy_content_sha256 != second_identity.policy_content_sha256


def test_replay_uuid_timestamp_is_utc() -> None:
    timestamp = replay_started_at("b5a78bee-76fa-11f1-8d68-0242ac130202")

    assert timestamp.isoformat().startswith("2026-07-03T")
    assert timestamp.utcoffset().total_seconds() == 0


def test_materialize_historical_archive_normalizes_dot_roots(tmp_path: Path) -> None:
    archive = tmp_path / "agent.tar.gz"
    _archive(archive)
    destination = tmp_path / "agent"

    materialize_historical_archive(archive, destination)

    assert (destination / "main.py").is_file()
    assert (destination / "deck.csv").is_file()
    assert (destination / "cg" / "libcg.so").is_file()


def test_filter_panel_records_parent_and_explicit_exclusion() -> None:
    panel = {
        "schema": "public_transfer_panel_v1",
        "panel_id": "parent",
        "games": [
            {"agent_label": "keep", "outcome": 0.0},
            {"agent_label": "drop", "outcome": 1.0},
        ],
    }
    child = filter_panel_by_label(
        panel,
        excluded_labels=["drop"],
        exclusion_reason="runtime timeout fixed before transfer scoring",
    )
    assert child["parent_panel_id"] == "parent"
    assert child["excluded_labels"] == ["drop"]
    assert [game["agent_label"] for game in child["games"]] == ["keep"]
