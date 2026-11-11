"""Regression tests for the convergence-aware finalize (bug: ref 54268328 was
finalized 'measured' at 845.4 mid-drift on 2026-07-02; true convergence ~817)."""
import os
import sys
import tempfile
from datetime import UTC, datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from outcome_ledger import Ledger, family_from_archive  # noqa: E402

TRAJ = [600, 718, 815.6, 789, 676.2, 722.8, 694.1, 760.9, 779.4, 804.5, 808.5,
        829.4, 845.4, 827.7, 845.3, 863.6, 876.6, 863.8, 885.6, 895.9, 884.9,
        881.7, 901.6, 909.0, 888.2, 897.1, 904.9, 897.6, 889.9, 895.1]
SLIDE = [894.2, 870.6, 870.1, 852.7, 840.4, 836.9, 832.6, 828.6, 823.0, 817.4]


def make_ledger():
    db = os.path.join(tempfile.mkdtemp(), "t.sqlite")
    ledger = Ledger(db)
    t0 = datetime(2026, 7, 2, 14, 36, tzinfo=UTC)
    ledger.record_submission("r149", "submission-x-v149.tar.gz", t0)
    return ledger, t0


def fin(ledger, t0, minute):
    return ledger.try_finalize("r149", t0 + timedelta(minutes=minute),
                               3600, 4, 100.0, refresh_finalized=True)


def add_until(ledger, t0, minute):
    for i, s in enumerate(TRAJ):
        t = 5 * (i + 1)
        if t <= minute:
            ledger.add_tick("r149", t0 + timedelta(minutes=t), s)


def test_no_premature_finalize_mid_climb():
    ledger, t0 = make_ledger()
    add_until(ledger, t0, 67)
    assert fin(ledger, t0, 67) is None
    assert ledger.submission("r149")["state"] == "WATCHING"


def test_staircase_not_finalized():
    ledger, t0 = make_ledger()
    add_until(ledger, t0, 90)
    assert fin(ledger, t0, 90) is None
    add_until(ledger, t0, 150)
    assert fin(ledger, t0, 150) is None


def test_converged_tail_is_label_and_self_corrects():
    ledger, t0 = make_ledger()
    add_until(ledger, t0, 150)
    for i, s in enumerate(SLIDE):
        ledger.add_tick("r149", t0 + timedelta(minutes=160 + 30 * i), s)
    r4 = fin(ledger, t0, 460)
    if r4 is not None:
        assert r4["median"] <= 845  # never a stale-high label
    for i in range(10):
        ledger.add_tick("r149", t0 + timedelta(minutes=470 + 30 * i), 815 + (i % 2))
    r5 = fin(ledger, t0, 760)
    assert r5 is not None and r5["verdict"] == "measured"
    assert abs(r5["median"] - 815.5) < 5


def test_never_converging_gets_terminal_drift():
    ledger, t0 = make_ledger()
    ledger.record_submission("r134", "submission-x-v134.tar.gz", t0)
    for i in range(100):
        ledger.add_tick("r134", t0 + timedelta(minutes=30 * i),
                        990 + 120 * ((i % 7) - 3) / 3.0)
    r = ledger.try_finalize("r134", t0 + timedelta(hours=50),
                            3600, 4, 100.0, refresh_finalized=True)
    assert r is not None and r["verdict"] == "drift"


def test_nightmine_calibration_archive_has_specific_family():
    assert family_from_archive("submission-codex-nightmine-shaymin-v160.tar.gz") == (
        "alakazam_nighttime_mine"
    )


if __name__ == "__main__":
    test_no_premature_finalize_mid_climb()
    test_staircase_not_finalized()
    test_converged_tail_is_label_and_self_corrects()
    test_never_converging_gets_terminal_drift()
    print("all ledger convergence tests pass")
