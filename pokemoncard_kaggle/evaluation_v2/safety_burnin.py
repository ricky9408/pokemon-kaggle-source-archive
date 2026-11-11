"""Hard legality, determinism, and runtime burn-in for an exact policy."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import statistics
import time
from typing import Any, Callable, Iterable


@dataclass(frozen=True)
class SafetyLimits:
    min_calls: int = 50_000
    min_repeat_checks: int = 2_000
    max_illegal: int = 0
    max_exceptions: int = 0
    max_nondeterministic: int = 0
    max_p99_seconds: float = 6.5
    max_action_seconds: float = 9.0
    max_fallback_fraction: float = 0.005


def valid_action(action: Any, observation: dict[str, Any]) -> bool:
    select = observation.get("select") or {}
    options = select.get("option") or []
    minimum = int(select.get("minCount", 0))
    maximum = int(select.get("maxCount", len(options)))
    return (
        isinstance(action, list)
        and minimum <= len(action) <= maximum
        and len(action) == len(set(action))
        and all(isinstance(index, int) and 0 <= index < len(options) for index in action)
    )


def load_observation_corpus(
    paths: Iterable[Path],
    *,
    deck_hash: str | None = None,
) -> list[str]:
    observations: dict[str, str] = {}
    for path in paths:
        with path.open() as handle:
            for line in handle:
                row = json.loads(line)
                if deck_hash and str(row.get("deck_hash")) != deck_hash:
                    continue
                observation = row.get("observation")
                if not isinstance(observation, dict) or not (observation.get("select") or {}).get("option"):
                    continue
                encoded = json.dumps(observation, sort_keys=True, separators=(",", ":"))
                observations.setdefault(hashlib.sha256(encoded.encode()).hexdigest(), encoded)
    return [observations[key] for key in sorted(observations)]


def _percentile(values: list[float], probability: float) -> float:
    if not values:
        return float("inf")
    ordered = sorted(values)
    index = min(len(ordered) - 1, int((len(ordered) - 1) * probability + 0.999999))
    return ordered[index]


def run_burnin(
    agent: Callable[[dict[str, Any]], list[int]],
    observations: list[str],
    *,
    calls: int,
    repeat_checks: int,
    fallback_count: Callable[[], int] | None = None,
    limits: SafetyLimits = SafetyLimits(),
) -> dict[str, Any]:
    if not observations:
        raise ValueError("observation corpus is empty")
    runtimes: list[float] = []
    illegal = 0
    exceptions = 0
    fallback_before = fallback_count() if fallback_count else 0
    for index in range(calls):
        observation = json.loads(observations[index % len(observations)])
        started = time.perf_counter()
        try:
            action = agent(observation)
            illegal += int(not valid_action(action, observation))
        except Exception:
            exceptions += 1
        runtimes.append(time.perf_counter() - started)
    fallback_after = fallback_count() if fallback_count else 0
    actual_repeats = min(repeat_checks, len(observations))
    nondeterministic = 0
    repeat_exceptions = 0
    for encoded in observations[:actual_repeats]:
        try:
            first = agent(json.loads(encoded))
            second = agent(json.loads(encoded))
            nondeterministic += first != second
        except Exception:
            repeat_exceptions += 1
    fallbacks = max(0, fallback_after - fallback_before)
    fallback_fraction = fallbacks / calls if calls else 1.0
    p99 = _percentile(runtimes, 0.99)
    maximum = max(runtimes, default=float("inf"))
    checks = [
        {"name": "calls", "passed": calls >= limits.min_calls, "value": calls, "threshold": f">={limits.min_calls}"},
        {"name": "unique_observations", "passed": len(observations) > 0, "value": len(observations), "threshold": ">0"},
        {"name": "repeat_checks", "passed": actual_repeats >= limits.min_repeat_checks, "value": actual_repeats, "threshold": f">={limits.min_repeat_checks}"},
        {"name": "illegal", "passed": illegal <= limits.max_illegal, "value": illegal, "threshold": f"<={limits.max_illegal}"},
        {"name": "exceptions", "passed": exceptions <= limits.max_exceptions, "value": exceptions, "threshold": f"<={limits.max_exceptions}"},
        {"name": "repeat_exceptions", "passed": repeat_exceptions == 0, "value": repeat_exceptions, "threshold": "==0"},
        {"name": "nondeterministic", "passed": nondeterministic <= limits.max_nondeterministic, "value": nondeterministic, "threshold": f"<={limits.max_nondeterministic}"},
        {"name": "p99_seconds", "passed": p99 <= limits.max_p99_seconds, "value": p99, "threshold": f"<={limits.max_p99_seconds}"},
        {"name": "max_seconds", "passed": maximum <= limits.max_action_seconds, "value": maximum, "threshold": f"<={limits.max_action_seconds}"},
        {"name": "fallback_instrumented", "passed": fallback_count is not None, "value": fallback_count is not None, "threshold": "true"},
        {"name": "fallback_fraction", "passed": fallback_count is not None and fallback_fraction <= limits.max_fallback_fraction, "value": fallback_fraction, "threshold": f"<={limits.max_fallback_fraction}"},
    ]
    return {
        "schema": "candidate_safety_burnin_v1",
        "limits": asdict(limits),
        "checks": checks,
        "passed": all(bool(check["passed"]) for check in checks),
        "calls": calls,
        "unique_observations": len(observations),
        "repeat_checks": actual_repeats,
        "illegal": illegal,
        "exceptions": exceptions,
        "nondeterministic": nondeterministic,
        "repeat_exceptions": repeat_exceptions,
        "p50_seconds": statistics.median(runtimes) if runtimes else float("inf"),
        "p99_seconds": p99,
        "max_seconds": maximum,
        "fallbacks": fallbacks,
        "fallback_fraction": fallback_fraction,
        "fallback_instrumented": fallback_count is not None,
    }


__all__ = [
    "SafetyLimits",
    "load_observation_corpus",
    "run_burnin",
    "valid_action",
]
