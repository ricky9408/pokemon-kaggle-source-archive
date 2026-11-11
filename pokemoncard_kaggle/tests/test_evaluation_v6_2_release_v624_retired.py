from __future__ import annotations

import pytest

from evaluation_v6_2 import release_v624


def test_v624_route_is_permanently_fail_closed() -> None:
    assert release_v624.RECRUITMENT_RELEASE_ROOT_ALLOWLIST == frozenset()
    with pytest.raises(release_v624.ReleaseV624Error, match="retired"):
        release_v624.validate_release_root({})
    with pytest.raises(release_v624.ReleaseV624Error, match="retired"):
        release_v624.verify_population_release_files()

    verdict = release_v624.assess_population_release_files()
    assert verdict["state"] == "POPULATION_INFEASIBLE"
    assert verdict["calibration_upload_authorized"] is False
    assert verdict["production_upload_authorized"] is False
    assert verdict["unit_upload_permits"] == []
    assert verdict["sealed_holdout_accessed"] is False
