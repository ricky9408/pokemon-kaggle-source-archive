from evaluation_v2.seeded_arena import anchor_outcome, summarize_matched_deltas


def _row(anchor: str, control: str, seed: int, left: int, outcome: float) -> dict:
    if outcome == 0.5:
        winner = 2
    elif outcome == 1.0:
        winner = 0 if left else 1
    else:
        winner = 1 if left else 0
    return {
        "anchor": anchor,
        "control": control,
        "seed": seed,
        "anchor_left": left,
        "left": anchor if left else control,
        "right": control if left else anchor,
        "winner": winner,
    }


def test_anchor_outcome_handles_both_seats() -> None:
    assert anchor_outcome(_row("a", "c", 1, 1, 1.0), "a") == 1.0
    assert anchor_outcome(_row("a", "c", 1, 0, 1.0), "a") == 1.0
    assert anchor_outcome(_row("a", "c", 1, 1, 0.0), "a") == 0.0


def test_matched_delta_summary_pairs_baseline_cells() -> None:
    rows = [
        _row("base", "control", 1, 1, 0.0),
        _row("base", "control", 1, 0, 0.0),
        _row("candidate", "control", 1, 1, 1.0),
        _row("candidate", "control", 1, 0, 0.0),
    ]

    feature = summarize_matched_deltas(rows, baseline_label="base")["candidate"]

    assert feature["matched_cells"] == 2
    assert feature["paired_mean_delta"] == 0.5
    assert feature["paired_cvar20_delta"] == 0.0
