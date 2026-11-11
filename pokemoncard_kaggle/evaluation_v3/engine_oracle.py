"""Fail-closed native Search parity probe primitives.

This module deliberately has no evaluator or promotion integration.  It is a
small, reproducible *reference* experiment over a frozen pre-cutoff replay.
It uses only the released Search ABI; evaluator-only seeded/patched exports
are forbidden.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import ctypes
from itertools import combinations
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
from typing import Any, Callable, Mapping, Sequence


SCHEMA = "engine_oracle_parity_v1"
VERDICT_UNSUPPORTED = "UNSUPPORTED"
VERDICT_REFERENCE_ONLY = "REFERENCE_PARITY_ONLY"
FORBIDDEN_NATIVE_EXPORTS = ("AgentSetSeed", "BattleStartSeeded", "SearchBeginSeeded")
REQUIRED_NATIVE_EXPORTS = (
    "GameInitialize",
    "AgentStart",
    "BattleFinish",
    "SearchBegin",
    "SearchStep",
    "SearchEnd",
)
TRANSPORT_FIELDS = frozenset({"remainingOverageTime", "search_begin_input"})


class ProbeFailure(RuntimeError):
    """An expected fail-closed probe condition."""


def canonical_bytes(value: Any) -> bytes:
    """Return the stable JSON encoding used for all report/transcript hashes."""

    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_hash(value: Any) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def canonical_state(value: Any) -> Any:
    """Remove only transport-only fields before hashing a native state."""

    if isinstance(value, Mapping):
        return {
            str(key): canonical_state(item)
            for key, item in value.items()
            if str(key) not in TRANSPORT_FIELDS
        }
    if isinstance(value, (list, tuple)):
        return [canonical_state(item) for item in value]
    return value


def canonical_state_hash(observation: Mapping[str, Any]) -> str:
    return canonical_hash(canonical_state(observation))


def canonical_action_hash(select: Mapping[str, Any], action: Sequence[int]) -> str:
    """Hash action indices together with the exact legal-option meaning."""

    options = select.get("option")
    if not isinstance(options, list):
        raise ProbeFailure("select.option is missing")
    minimum = select.get("minCount")
    maximum = select.get("maxCount")
    if not isinstance(minimum, int) or not isinstance(maximum, int):
        raise ProbeFailure("select bounds are missing")
    if not all(isinstance(index, int) and not isinstance(index, bool) for index in action):
        raise ProbeFailure("action must be an integer selection")
    if not minimum <= len(action) <= maximum:
        raise ProbeFailure("action does not satisfy selection bounds")
    if len(set(action)) != len(action) or any(index < 0 or index >= len(options) for index in action):
        raise ProbeFailure("action is not a distinct in-range selection")
    return canonical_hash({"action": list(action), "options": [options[index] for index in action]})


def sha256_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def tree_sha256(root: Path) -> str:
    """Hash file names and contents, excluding no files implicitly."""

    digest = sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def write_create_once_json(path: Path, value: Mapping[str, Any]) -> None:
    """Create a report exactly once; never silently replace evidence."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True))
        handle.write("\n")


def available_file_identity(path: Path) -> dict[str, Any]:
    """Return only identity facts that can be read without weakening a failure."""

    identity: dict[str, Any] = {"path": str(path), "exists": path.is_file()}
    if path.is_file():
        try:
            identity["sha256"] = sha256_file(path)
        except OSError as exc:
            identity["identity_error"] = f"{type(exc).__name__}: {exc}"
    return identity


def unsupported_receipt(
    *,
    reason: str,
    stage: str,
    replay_path: Path | None = None,
    native_roots_path: Path | None = None,
    sample_library: Path | None = None,
    github_library: Path | None = None,
    source_dir: Path | None = None,
    zig: Path | None = None,
    docker_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a compact, create-once-safe receipt for an expected failure."""

    identities: dict[str, Any] = {}
    for label, path in (
        ("replay", replay_path),
        ("native_roots", native_roots_path),
        ("kaggle_sample_library", sample_library),
        ("github_cabt_library", github_library),
        ("zig", zig),
    ):
        if path is not None:
            identities[label] = available_file_identity(path)
    if source_dir is not None:
        source_identity: dict[str, Any] = {"path": str(source_dir), "exists": source_dir.is_dir()}
        if source_dir.is_dir():
            try:
                source_identity["tree_sha256"] = tree_sha256(source_dir)
            except OSError as exc:
                source_identity["identity_error"] = f"{type(exc).__name__}: {exc}"
        identities["source_dir"] = source_identity
    return {
        "schema": SCHEMA,
        "scope": "pre-cutoff reference parity only; not hosted-public equivalence",
        "verdict": VERDICT_UNSUPPORTED,
        "failure_stage": stage,
        "disagreement_reasons": [reason],
        "identities_available": identities,
        "execution": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "docker": dict(docker_identity or {}),
        },
        "wrapper_sha256": sha256_file(Path(__file__)),
    }


def load_native_root(path: Path, *, episode_id: str, root_id: str | None = None) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if str(row.get("episode_id")) == episode_id and (root_id is None or row.get("native_root_id") == root_id):
            matches.append(row)
    if len(matches) != 1:
        raise ProbeFailure(f"expected exactly one native root, found {len(matches)}")
    root = matches[0]
    observation = root.get("observation")
    if not isinstance(observation, dict) or not isinstance(observation.get("search_begin_input"), str):
        raise ProbeFailure("native root lacks actor observation/search_begin_input")
    return root


def _visible_matches(actor_value: Any, omniscient_value: Any) -> bool:
    """Actor-side ``None`` is an intentional hidden-zone wildcard."""

    if actor_value is None:
        return True
    if isinstance(actor_value, Mapping):
        return isinstance(omniscient_value, Mapping) and all(
            key in omniscient_value and _visible_matches(value, omniscient_value[key])
            for key, value in actor_value.items()
        )
    if isinstance(actor_value, list):
        return isinstance(omniscient_value, list) and len(actor_value) == len(omniscient_value) and all(
            _visible_matches(value, other) for value, other in zip(actor_value, omniscient_value)
        )
    return actor_value == omniscient_value


def locate_omniscient_visualize_state(replay: Mapping[str, Any], root: Mapping[str, Any]) -> dict[str, Any]:
    """Require the visualizer state at the root's exact frozen step mapping."""

    observation = root["observation"]
    actor_current = observation.get("current")
    if not isinstance(actor_current, Mapping):
        raise ProbeFailure("native root current state is missing")
    visualize = (((replay.get("steps") or [[{}]])[0][0]).get("visualize") or [])
    if not isinstance(visualize, list):
        raise ProbeFailure("replay has no omniscient visualize list")
    index = int(root.get("step_index", -1)) - 1
    if not 0 <= index < len(visualize):
        raise ProbeFailure("frozen native-root step has no corresponding visualize state")
    entry = visualize[index]
    current = entry.get("current") if isinstance(entry, Mapping) else None
    if not isinstance(current, Mapping) or not _visible_matches(actor_current, current):
        raise ProbeFailure("frozen native-root step does not match its exact visualize state")
    return {"visualize_index": index, "current": current}


def _zone_ids(player: Mapping[str, Any], zone: str) -> list[int]:
    cards = player.get(zone)
    if not isinstance(cards, list) or any(not isinstance(card, Mapping) or not isinstance(card.get("id"), int) for card in cards):
        raise ProbeFailure(f"omniscient {zone} is incomplete")
    return [int(card["id"]) for card in cards]


def hidden_zone_arguments(actor_observation: Mapping[str, Any], omniscient_current: Mapping[str, Any]) -> dict[str, list[int]]:
    """Extract exact hidden-zone IDs from a visualizer state, never guesses."""

    actor_current = actor_observation.get("current")
    if not isinstance(actor_current, Mapping):
        raise ProbeFailure("actor observation has no current state")
    actor = actor_current.get("yourIndex")
    players = omniscient_current.get("players")
    if actor not in (0, 1) or not isinstance(players, list) or len(players) != 2 or not all(isinstance(player, Mapping) for player in players):
        raise ProbeFailure("invalid player layout")
    other = 1 - actor
    result = {
        "your_deck": _zone_ids(players[actor], "deck"),
        "your_prize": _zone_ids(players[actor], "prize"),
        "opponent_deck": _zone_ids(players[other], "deck"),
        "opponent_prize": _zone_ids(players[other], "prize"),
        "opponent_hand": _zone_ids(players[other], "hand"),
        "opponent_active": [],
    }
    actor_players = actor_current.get("players")
    if not isinstance(actor_players, list) or len(actor_players) != 2:
        raise ProbeFailure("actor observation has invalid players")
    public_active = actor_players[other].get("active") if isinstance(actor_players[other], Mapping) else None
    if isinstance(public_active, list) and any(card is None for card in public_active):
        active = _zone_ids(players[other], "active")
        if not active:
            raise ProbeFailure("hidden opponent active is empty")
        result["opponent_active"] = active
    for player_index, key, count_key in (
        (actor, "your_deck", "deckCount"),
        (other, "opponent_deck", "deckCount"),
        (other, "opponent_hand", "handCount"),
    ):
        expected = actor_players[player_index].get(count_key) if isinstance(actor_players[player_index], Mapping) else None
        if not isinstance(expected, int) or len(result[key]) != expected:
            raise ProbeFailure(f"omniscient {key} count does not match actor observation")
    return result


def legal_actions(select: Mapping[str, Any]) -> tuple[tuple[int, ...], ...]:
    options = select.get("option")
    minimum = select.get("minCount")
    maximum = select.get("maxCount")
    if not isinstance(options, list) or not isinstance(minimum, int) or not isinstance(maximum, int):
        raise ProbeFailure("invalid select")
    if minimum < 0 or maximum < minimum or maximum > len(options):
        raise ProbeFailure("invalid selection bounds")
    action_count = sum(
        # ``combinations`` is only materialized after this small fail-closed cap.
        _binomial(len(options), count)
        for count in range(minimum, maximum + 1)
    )
    if action_count > 256:
        raise ProbeFailure("legal action set is too large for a reproducible probe")
    return tuple(
        selection
        for count in range(minimum, maximum + 1)
        for selection in combinations(range(len(options)), count)
    )


def _binomial(size: int, count: int) -> int:
    if count < 0 or count > size:
        return 0
    numerator = denominator = 1
    for index in range(1, min(count, size - count) + 1):
        numerator *= size - (index - 1)
        denominator *= index
    return numerator // denominator


def choose_branches(observation: Mapping[str, Any], recorded: Sequence[int]) -> dict[str, list[int]]:
    select = observation.get("select")
    if not isinstance(select, Mapping):
        raise ProbeFailure("actor observation has no selection")
    actions = legal_actions(select)
    recorded_tuple = tuple(recorded)
    if recorded_tuple not in actions:
        raise ProbeFailure("recorded action is not legal at the frozen root")
    alternative = next((action for action in actions if action != recorded_tuple), None)
    if alternative is None:
        raise ProbeFailure("frozen root has no distinct legal counterfactual")
    return {"recorded": list(recorded_tuple), "alternative": list(alternative)}


@dataclass
class NativeSearchSession:
    """Direct released-ABI session.  No Python engine wrapper is imported."""

    library_path: Path

    def __post_init__(self) -> None:
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
            raise ProbeFailure("native probe requires Linux/amd64")
        if not self.library_path.is_file():
            raise ProbeFailure(f"missing native binary: {self.library_path}")
        self.lib = ctypes.CDLL(str(self.library_path))
        forbidden = [name for name in FORBIDDEN_NATIVE_EXPORTS if hasattr(self.lib, name)]
        if forbidden:
            raise ProbeFailure(f"forbidden evaluator-only native export: {', '.join(forbidden)}")
        missing = [name for name in REQUIRED_NATIVE_EXPORTS if not hasattr(self.lib, name)]
        if missing:
            raise ProbeFailure(f"native wrapper ABI mismatch: missing {', '.join(missing)}")
        self.lib.GameInitialize()
        self.lib.AgentStart.restype = ctypes.c_void_p
        self.lib.BattleFinish.argtypes = [ctypes.c_void_p]
        self.lib.SearchBegin.restype = ctypes.c_char_p
        self.lib.SearchBegin.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int] + [ctypes.POINTER(ctypes.c_int)] * 6 + [ctypes.c_int]
        self.lib.SearchStep.restype = ctypes.c_char_p
        self.lib.SearchStep.argtypes = [ctypes.c_void_p, ctypes.c_int64, ctypes.POINTER(ctypes.c_int), ctypes.c_int]
        self.lib.SearchEnd.argtypes = [ctypes.c_void_p]
        self.pointer: int | None = None

    def __enter__(self) -> "NativeSearchSession":
        self.pointer = self.lib.AgentStart()
        if not self.pointer:
            raise ProbeFailure("AgentStart failed")
        return self

    def _array(self, values: Sequence[int]) -> Any:
        if not all(isinstance(value, int) and not isinstance(value, bool) for value in values):
            raise ProbeFailure("hidden-zone values must be integers")
        return (ctypes.c_int * len(values))(*values)

    def _parse(self, raw: bytes | None, operation: str) -> dict[str, Any]:
        if not raw:
            raise ProbeFailure(f"{operation} returned null")
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ProbeFailure(f"{operation} returned invalid JSON: {type(exc).__name__}") from exc
        if not isinstance(data, dict) or data.get("error", 0) != 0:
            raise ProbeFailure(f"{operation} returned error {data.get('error') if isinstance(data, dict) else 'invalid'}")
        state = data.get("state")
        if not isinstance(state, dict) or not isinstance(state.get("observation"), dict) or not isinstance(state.get("searchId"), int):
            raise ProbeFailure(f"{operation} returned an incompatible state wrapper")
        return state

    def begin(self, observation: Mapping[str, Any], zones: Mapping[str, Sequence[int]]) -> dict[str, Any]:
        if self.pointer is None:
            raise ProbeFailure("native session is closed")
        serialized = observation.get("search_begin_input")
        if not isinstance(serialized, str):
            raise ProbeFailure("actor observation lacks search_begin_input")
        required = ("your_deck", "your_prize", "opponent_deck", "opponent_prize", "opponent_hand", "opponent_active")
        if any(key not in zones for key in required):
            raise ProbeFailure("hidden-zone arguments are incomplete")
        arrays = [self._array(zones[key]) for key in required]
        # manualCoin=1 removes coin outcomes from this counterfactual; no seed
        # control is installed or consulted.
        raw = self.lib.SearchBegin(self.pointer, serialized.encode("ascii"), len(serialized), *arrays, 1)
        return self._parse(raw, "SearchBegin")

    def step(self, state: Mapping[str, Any], action: Sequence[int]) -> dict[str, Any]:
        if self.pointer is None:
            raise ProbeFailure("native session is closed")
        array = self._array(action)
        raw = self.lib.SearchStep(self.pointer, int(state["searchId"]), array, len(action))
        return self._parse(raw, "SearchStep")

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.pointer is not None:
            try:
                self.lib.SearchEnd(self.pointer)
            finally:
                self.lib.BattleFinish(self.pointer)
                self.pointer = None


def _continuation_action(observation: Mapping[str, Any]) -> list[int]:
    select = observation.get("select")
    if not isinstance(select, Mapping):
        raise ProbeFailure("transition has no legal selection")
    actions = legal_actions(select)
    if not actions:
        raise ProbeFailure("transition has no legal action")
    return list(actions[0])


def run_branch(
    library: Path,
    observation: Mapping[str, Any],
    zones: Mapping[str, Sequence[int]],
    first_action: Sequence[int],
    *,
    max_steps: int = 3,
) -> dict[str, Any]:
    """Run one fresh root branch and record every state/action hash."""

    transitions: list[dict[str, Any]] = []
    with NativeSearchSession(library) as session:
        state = session.begin(observation, zones)
        action = list(first_action)
        for index in range(max_steps):
            before = state["observation"]
            next_state = session.step(state, action)
            after = next_state["observation"]
            transitions.append(
                {
                    "transition": index + 1,
                    "action": action,
                    "action_sha256": canonical_action_hash(before["select"], action),
                    "before_state_sha256": canonical_state_hash(before),
                    "after_state_sha256": canonical_state_hash(after),
                }
            )
            current = after.get("current")
            if isinstance(current, Mapping) and current.get("result") not in (None, -1):
                break
            state = next_state
            action = _continuation_action(after)
    return {"transitions": transitions, "transcript_sha256": canonical_hash(transitions)}


def run_branch_isolated(
    library: Path,
    observation: Mapping[str, Any],
    zones: Mapping[str, Sequence[int]],
    first_action: Sequence[int],
    *,
    max_steps: int = 3,
    timeout_seconds: float = 20.0,
    worker_script: Path | None = None,
) -> dict[str, Any]:
    """Run one native branch in a disposable process with a hard timeout."""

    if timeout_seconds <= 0:
        raise ProbeFailure("native branch timeout must be positive")
    worker = worker_script or Path(__file__).resolve().parents[1] / "tools" / "engine_oracle_branch_worker.py"
    if not worker.is_file():
        raise ProbeFailure(f"native branch worker is missing: {worker}")
    with tempfile.TemporaryDirectory(prefix="engine-oracle-branch-") as temporary:
        directory = Path(temporary)
        request = directory / "request.json"
        response = directory / "response.json"
        request.write_bytes(
            canonical_bytes(
                {
                    "schema": "engine_oracle_branch_request_v1",
                    "library": str(library),
                    "observation": observation,
                    "zones": zones,
                    "first_action": list(first_action),
                    "max_steps": max_steps,
                }
            )
        )
        command = [sys.executable, str(worker), "--input", str(request), "--output", str(response)]
        try:
            completed = subprocess.run(
                command,
                check=False,
                text=True,
                capture_output=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise ProbeFailure(f"native branch timed out after {timeout_seconds:g}s") from exc
        if completed.returncode != 0:
            stderr = completed.stderr.strip().replace("\n", " ")[-500:]
            raise ProbeFailure(
                f"native branch worker exited {completed.returncode}"
                + (f": {stderr}" if stderr else "")
            )
        try:
            result = json.loads(response.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProbeFailure("native branch worker produced no valid response") from exc
        if not isinstance(result, dict) or not isinstance(result.get("transcript_sha256"), str):
            raise ProbeFailure("native branch worker returned an incompatible response")
        return result


def compare_engine_runs(engine_runs: Mapping[str, Mapping[str, Any]], *, hosted_binary_provenance: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Derive an intentionally conservative verdict from already-run engines."""

    reasons: list[str] = []
    transcripts: dict[str, Any] = {}
    for label, run in engine_runs.items():
        if run.get("status") != "ok":
            reasons.append(f"{label}: {run.get('reason') or 'engine failed'}")
            continue
        repeat = run.get("repeat_transcripts")
        branch = run.get("branch_transcripts")
        if not isinstance(repeat, Mapping) or not isinstance(branch, Mapping):
            reasons.append(f"{label}: missing transcript identity")
            continue
        if any(repeat.get(name) != branch.get(name) for name in ("recorded", "alternative")):
            reasons.append(f"{label}: RNG or nondeterministic transcript")
            continue
        transcripts[label] = branch
    if reasons:
        return {"verdict": VERDICT_UNSUPPORTED, "disagreement_reasons": reasons, "hosted_binary_provenance": hosted_binary_provenance}
    if len(transcripts) < 2:
        return {
            "verdict": VERDICT_UNSUPPORTED,
            "disagreement_reasons": ["fewer than two complete reference engines"],
            "hosted_binary_provenance": hosted_binary_provenance,
        }
    baseline_label, baseline = next(iter(transcripts.items()))
    for label, transcript in transcripts.items():
        if transcript != baseline:
            return {
                "verdict": VERDICT_UNSUPPORTED,
                "disagreement_reasons": [f"canonical transcript disagreement: {baseline_label} != {label}"],
                "hosted_binary_provenance": hosted_binary_provenance,
            }
    # The probe never possesses a hosted evaluator binary.  Local agreement is
    # useful reference parity only, never a hosted-public oracle claim.
    reason = "local reference binaries agree; hosted-public binary provenance is absent"
    if hosted_binary_provenance:
        reason = "local reference binaries agree; this probe does not establish hosted-public equivalence"
    return {
        "verdict": VERDICT_REFERENCE_ONLY,
        "disagreement_reasons": [],
        "hosted_binary_provenance": hosted_binary_provenance,
        "verdict_reason": reason,
    }


def compile_clean_engine(source_dir: Path, zig: Path) -> tuple[Path, dict[str, Any]]:
    """Build the exact unpatched released source into an ephemeral .so."""

    if not (source_dir / "Export.cpp").is_file() or not (source_dir / "Search.h").is_file():
        raise ProbeFailure("clean source identity is missing")
    source_text = (source_dir / "Search.h").read_text(encoding="utf-8-sig")
    if "AgentSetSeed" in source_text or "Game* game;" in source_text:
        raise ProbeFailure("source tree appears patched")
    if not zig.is_file():
        raise ProbeFailure("clean-build toolchain is missing")
    temporary = tempfile.mkdtemp(prefix="engine-oracle-clean-")
    output = Path(temporary) / "libcg.so"
    command = [str(zig), "c++", "-target", "x86_64-linux-gnu", "-std=c++20", "-O3", "-DNDEBUG", "-fPIC", "-shared", "-w", str(source_dir / "Export.cpp"), "-o", str(output)]
    try:
        completed = subprocess.run(command, check=False, text=True, capture_output=True, timeout=120.0)
    except subprocess.TimeoutExpired as exc:
        raise ProbeFailure("clean build timed out after 120s") from exc
    except OSError as exc:
        raise ProbeFailure(f"clean build could not start: {type(exc).__name__}: {exc}") from exc
    if completed.returncode != 0 or not output.is_file():
        raise ProbeFailure(f"clean build failed: {completed.stderr.strip()[-500:]}")
    return output, {
        "source_tree_sha256": tree_sha256(source_dir),
        "toolchain_binary_sha256": sha256_file(zig),
        "toolchain_tree_sha256": tree_sha256(zig.parent),
        "toolchain_version": subprocess.run([str(zig), "version"], check=True, text=True, capture_output=True).stdout.strip(),
        "compile_command": command,
        "binary_sha256": sha256_file(output),
    }


def run_reference_probe(
    *,
    replay_path: Path,
    native_roots_path: Path,
    sample_library: Path,
    github_library: Path | None,
    source_dir: Path,
    zig: Path,
    root_id: str | None = None,
    docker_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute the frozen replay experiment under all locally available references."""

    replay = json.loads(replay_path.read_text(encoding="utf-8"))
    root = load_native_root(native_roots_path, episode_id="85178405", root_id=root_id)
    visual = locate_omniscient_visualize_state(replay, root)
    observation = root["observation"]
    zones = hidden_zone_arguments(observation, visual["current"])
    branches = choose_branches(observation, root.get("recorded_selection") or [])
    clean_library, clean_identity = compile_clean_engine(source_dir, zig)
    engine_paths: dict[str, Path] = {"kaggle_sample": sample_library, "clean_unpatched_source": clean_library}
    if github_library is not None and github_library.is_file():
        engine_paths["github_cabt"] = github_library
    engine_runs: dict[str, dict[str, Any]] = {}
    for label, library in engine_paths.items():
        identity = {"path": str(library), "sha256": sha256_file(library)}
        try:
            first = {
                name: run_branch_isolated(library, observation, zones, action)
                for name, action in branches.items()
            }
            repeat = {
                name: run_branch_isolated(library, observation, zones, action)
                for name, action in branches.items()
            }
            engine_runs[label] = {
                "status": "ok",
                "identity": identity,
                "branch_transcripts": {name: item["transcript_sha256"] for name, item in first.items()},
                "repeat_transcripts": {name: item["transcript_sha256"] for name, item in repeat.items()},
                "branches": first,
            }
        except Exception as exc:
            engine_runs[label] = {"status": "failed", "identity": identity, "reason": f"{type(exc).__name__}: {exc}"}
    verdict = compare_engine_runs(engine_runs, hosted_binary_provenance=None)
    return {
        "schema": SCHEMA,
        "scope": "pre-cutoff reference parity only; not hosted-public equivalence",
        "replay": {"path": str(replay_path), "sha256": sha256_file(replay_path), "episode_id": "85178405"},
        "native_root": {
            "path": str(native_roots_path),
            "sha256": sha256_file(native_roots_path),
            "native_root_id": root["native_root_id"],
            "step_index": root["step_index"],
            "actor_observation_sha256": canonical_state_hash(observation),
            "omniscient_visualize_index": visual["visualize_index"],
        },
        "execution": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "manual_coin": 1,
            "max_search_steps": 3,
            "docker": dict(docker_identity or {}),
        },
        "source_build": clean_identity,
        "wrapper_sha256": sha256_file(Path(__file__)),
        "hidden_zone_sha256": canonical_hash(zones),
        "action_branches": branches,
        "engines": engine_runs,
        **verdict,
    }


__all__ = [
    "ProbeFailure",
    "SCHEMA",
    "VERDICT_REFERENCE_ONLY",
    "VERDICT_UNSUPPORTED",
    "canonical_action_hash",
    "canonical_hash",
    "canonical_state_hash",
    "choose_branches",
    "compare_engine_runs",
    "hidden_zone_arguments",
    "load_native_root",
    "run_reference_probe",
    "run_branch_isolated",
    "tree_sha256",
    "unsupported_receipt",
    "available_file_identity",
    "write_create_once_json",
]
