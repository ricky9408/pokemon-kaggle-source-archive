from datetime import datetime, timezone

import pytest


@pytest.fixture(autouse=True)
def freeze_v4_1_authorization_wall_clock(request, monkeypatch):
    """Keep historical authorization fixtures deterministic after their expiry date."""

    if request.path.name.startswith("test_evaluation_v4_1_"):
        def frozen():
            return datetime(2026, 7, 11, 23, 0, tzinfo=timezone.utc)

        monkeypatch.setattr("evaluation_v4_1.authorization._wall_now", frozen)
        monkeypatch.setattr("evaluation_v4_1.executor._wall_now", frozen)
