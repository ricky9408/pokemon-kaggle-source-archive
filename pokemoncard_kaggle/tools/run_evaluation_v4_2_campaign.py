#!/usr/bin/env python3
"""Exclusive parent executor for one frozen evaluation-v4.2 campaign.

This tool deliberately owns only orchestration.  The campaign plan, journal,
prepared-child contract, runtime verification, sandbox arm runner, and final
composer remain the authoritative implementations in ``evaluation_v4_2``.
It never accepts caller-selected container, deadline, scheduler, or retry
settings: those values are already sealed in the validated campaign plan.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import fcntl
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v4_2.campaign_composer import (
    _build_arm_terminal_evidence,
    build_campaign_terminal_manifest,
    build_prelaunch_veto_manifest,
    compose_campaign,
)
from evaluation_v4_2.campaign_journal import (
    BURN,
    FAILURE,
    NEVER_STARTED,
    POPEN_OBSERVED,
    START_DURABLE_POPEN_UNCERTAIN,
    SUCCESS,
    TERMINAL,
    VETO,
    CampaignJournal,
)
from evaluation_v4_2.witness_journal import (
    TERMINAL as CHILD_TERMINAL,
    canonical_json_bytes,
)
from evaluation_v4_2.campaign_preparation import (
    build_campaign_prepared_manifest,
    build_prepared_allocation,
)
from evaluation_v4_2.campaign_protocol import validate_campaign_plan
from evaluation_v4_2.campaign_runtime import verify_campaign_runtime
from evaluation_v4_2.parent_arm_claim import child_attempt_id, deterministic_parent_container_names
from tools.run_evaluation_v4_2_sandbox_arm import (
    _load_bundle_validator,
    build_parent_docker_command_templates,
    compose_witnessed_arm,
    execute_parent_bound_arm,
    predict_snapshot_manifest,
)


BUNDLE_DIR_MAP_SCHEMA = "evaluation_v4_2_campaign_bundle_dir_map_v1"


class CampaignExecutorError(RuntimeError):
    """The exclusive campaign executor cannot safely continue."""


class _Dependencies:
    """Class-only injection boundary used by the focused synthetic tests."""

    def __init__(
        self,
        *,
        plan_validator: Callable[[object], dict[str, Any]] = validate_campaign_plan,
        bundle_validator: Callable[[], Callable[[Path], Mapping[str, Any]]] = _load_bundle_validator,
        snapshot_manifest_predictor: Callable[..., Mapping[str, Any]] = predict_snapshot_manifest,
        template_builder: Callable[..., dict[str, list[str]]] = build_parent_docker_command_templates,
        prepared_allocation_builder: Callable[..., dict[str, Any]] = build_prepared_allocation,
        prepared_manifest_builder: Callable[..., dict[str, Any]] = build_campaign_prepared_manifest,
        runtime_verifier: Callable[..., dict[str, Any]] = verify_campaign_runtime,
        arm_executor: Callable[..., Mapping[str, Any]] = execute_parent_bound_arm,
        arm_composer: Callable[..., dict[str, Any]] = compose_witnessed_arm,
        arm_terminal_builder: Callable[..., dict[str, Any]] = _build_arm_terminal_evidence,
        campaign_terminal_builder: Callable[..., dict[str, Any]] = build_campaign_terminal_manifest,
        campaign_composer: Callable[..., dict[str, Any]] = compose_campaign,
    ) -> None:
        self.plan_validator = plan_validator
        self.bundle_validator = bundle_validator
        self.snapshot_manifest_predictor = snapshot_manifest_predictor
        self.template_builder = template_builder
        self.prepared_allocation_builder = prepared_allocation_builder
        self.prepared_manifest_builder = prepared_manifest_builder
        self.runtime_verifier = runtime_verifier
        self.arm_executor = arm_executor
        self.arm_composer = arm_composer
        self.arm_terminal_builder = arm_terminal_builder
        self.campaign_terminal_builder = campaign_terminal_builder
        self.campaign_composer = campaign_composer


class CampaignExecutor:
    """Run or conservatively close exactly one campaign under ``execution.lock``.

    Dependencies are injectable only here, to make the journal state-machine
    tests small.  The command-line entry point always creates this class with
    the frozen production dependencies above.
    """

    def __init__(
        self, *, repository_root: Path = ROOT, dependencies: _Dependencies | None = None) -> None:
        self._repository_root = repository_root.resolve()
        self._deps = dependencies or _Dependencies()

    @contextmanager
    def _execution_lock(self, journal: CampaignJournal) -> Iterator[None]:
        lock_path = journal.root / "execution.lock"
        with lock_path.open("a+b") as handle:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise CampaignExecutorError(
                    f"another process already owns {lock_path}"
                ) from exc
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _require_digest(value: object, *, label: str) -> str:
        if not isinstance(value, str) or len(value) != 64 or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise CampaignExecutorError(f"{label} must be a lowercase SHA-256 digest")
        return value

    def _exact_bundle_dirs(
        self,
        plan: Mapping[str, Any],
        value: Mapping[str, object],
    ) -> dict[str, Path]:
        """Require a total allocation-id map, optionally plan-hash enveloped."""

        raw: object = value
        if set(value) == {"schema", "plan_sha256", "bundle_dirs"}:
            if value["schema"] != BUNDLE_DIR_MAP_SCHEMA:
                raise CampaignExecutorError("bundle-dir map schema is invalid")
            if value["plan_sha256"] != plan.get("content_sha256"):
                raise CampaignExecutorError("bundle-dir map plan_sha256 differs from the exact plan")
            raw = value["bundle_dirs"]
        if not isinstance(raw, Mapping):
            raise CampaignExecutorError("allocation-to-bundle-dir map must be an object")
        allocations = plan.get("allocations")
        if not isinstance(allocations, list):
            raise CampaignExecutorError("validated campaign plan lacks allocations")
        expected_ids = [item.get("allocation_id") for item in allocations if isinstance(item, Mapping)]
        if len(expected_ids) != len(allocations) or not all(isinstance(item, str) for item in expected_ids):
            raise CampaignExecutorError("validated campaign plan has invalid allocation ids")
        if set(raw) != set(expected_ids):
            raise CampaignExecutorError("bundle-dir map must cover exactly the campaign allocations")
        result: dict[str, Path] = {}
        for allocation_id in expected_ids:
            path_value = raw[allocation_id]
            if not isinstance(path_value, (str, Path)):
                raise CampaignExecutorError(f"bundle-dir map entry {allocation_id!r} is not a path")
            try:
                path = Path(path_value).expanduser().resolve(strict=True)
            except OSError as exc:
                raise CampaignExecutorError(
                    f"bundle-dir map entry {allocation_id!r} cannot be resolved"
                ) from exc
            if not path.is_dir():
                raise CampaignExecutorError(f"bundle-dir map entry {allocation_id!r} is not a directory")
            result[allocation_id] = path
        return result

    @staticmethod
    def _runner_values(plan: Mapping[str, Any]) -> tuple[str, int, int, int, int]:
        binding = plan.get("runner_binding")
        if not isinstance(binding, Mapping):
            raise CampaignExecutorError("campaign plan lacks a frozen runner binding")
        resources = binding.get("resource_caps")
        image = binding.get("oci_image")
        if not isinstance(resources, Mapping) or not isinstance(image, str):
            raise CampaignExecutorError("campaign runner binding is incomplete")
        try:
            cpu = int(resources["cpu_limit_millicores"])
            memory = int(resources["memory_limit_bytes"])
            pids = int(resources["pids_limit"])
            tmpfs = int(resources["tmpfs_size_bytes"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CampaignExecutorError("campaign runner binding has invalid resources") from exc
        if min(cpu, memory, pids, tmpfs) <= 0:
            raise CampaignExecutorError("campaign runner binding has non-positive resources")
        return image, cpu, memory, pids, tmpfs

    def _runtime_receipt(
        self,
        plan: Mapping[str, Any],
        campaign_id: str,
        *,
        phase: str,
        wave: int | None = None,
        allocation_id: str | None = None,
    ) -> dict[str, Any]:
        return self._deps.runtime_verifier(
            plan["runner_binding"],
            repository_root=self._repository_root,
            phase=phase,
            campaign_id=campaign_id,
            plan_sha256=plan["content_sha256"],
            wave=wave,
            allocation_id=allocation_id,
        )

    def _prepared_manifest(
        self,
        journal: CampaignJournal,
        campaign_id: str,
        plan: Mapping[str, Any],
        bundle_dirs: Mapping[str, Path],
        campaign_dir: Path,
    ) -> dict[str, Any]:
        state = journal.state(campaign_id)
        validator = self._deps.bundle_validator()
        image, cpu, memory, pids, tmpfs = self._runner_values(plan)
        prepared: list[Mapping[str, Any]] = []
        allocations = plan["allocations"]
        for allocation in allocations:
            if not isinstance(allocation, Mapping):
                raise CampaignExecutorError("campaign allocation is invalid")
            allocation_id = allocation["allocation_id"]
            if not isinstance(allocation_id, str):
                raise CampaignExecutorError("campaign allocation id is invalid")
            bundle_dir = bundle_dirs[allocation_id]
            manifest = validator(bundle_dir)
            if not isinstance(manifest, Mapping):
                raise CampaignExecutorError("bundle validator did not return a manifest")
            if manifest.get("content_sha256") != allocation.get("bundle_manifest_sha256"):
                raise CampaignExecutorError(f"bundle manifest differs for allocation {allocation_id}")
            if manifest.get("task") != allocation.get("task"):
                raise CampaignExecutorError(f"bundle task differs for allocation {allocation_id}")
            snapshot_manifest = self._deps.snapshot_manifest_predictor(bundle_dir, manifest)
            if not isinstance(snapshot_manifest, Mapping):
                raise CampaignExecutorError("snapshot manifest predictor did not return a manifest")
            snapshot_manifest_sha256 = journal.evidence.put(dict(snapshot_manifest))
            snapshot_tree_sha256 = snapshot_manifest.get("tree_sha256")
            self._require_digest(snapshot_manifest_sha256, label="snapshot_manifest_sha256")
            self._require_digest(snapshot_tree_sha256, label="snapshot_tree_sha256")
            task = allocation.get("task")
            if not isinstance(task, Mapping):
                raise CampaignExecutorError(f"allocation {allocation_id} lacks an exact task")
            templates = self._deps.template_builder(
                campaign_dir / "arm-snapshots" / allocation_id / "snapshot",
                task,
                image=image,
                names=deterministic_parent_container_names(campaign_id, allocation_id),
                cpu_millicores=cpu,
                memory_bytes=memory,
                pids_limit=pids,
                tmpfs_bytes=tmpfs,
            )
            prepared.append(
                self._deps.prepared_allocation_builder(
                    plan,
                    state,
                    allocation,
                    snapshot_manifest_sha256=snapshot_manifest_sha256,
                    snapshot_tree_sha256=snapshot_tree_sha256,
                    normalized_command_templates=templates,
                )
            )
        return self._deps.prepared_manifest_builder(plan, state, prepared)

    @staticmethod
    def _child_journal_state(
        journal: CampaignJournal,
        campaign_id: str,
        allocation_id: str,
    ) -> Mapping[str, Any] | None:
        """Return the campaign-derived child state without inventing launch evidence."""

        arm_journal = getattr(journal, "_arm_journal", None)
        state_reader = getattr(arm_journal, "state", None)
        if not callable(state_reader):
            return None
        try:
            state = state_reader(child_attempt_id(campaign_id, allocation_id))
        except Exception:
            return None
        return state if isinstance(state, Mapping) else None

    @classmethod
    def _ambiguous_child_launch_state(
        cls,
        journal: CampaignJournal,
        campaign_id: str,
        allocation_id: str,
    ) -> str:
        """Classify only a durable child START as launch-ambiguous.

        ARM_BOUND precedes child PREPARE/START, so ARM_BOUND alone is not
        evidence that a process launch was attempted.  A terminal child is also
        conservatively ambiguous here because this path is used only after the
        exact result/composition path failed.
        """

        child = cls._child_journal_state(journal, campaign_id, allocation_id)
        if child is not None and child.get("state") in {"STARTED", CHILD_TERMINAL}:
            return START_DURABLE_POPEN_UNCERTAIN
        return NEVER_STARTED

    @staticmethod
    def _verified_child_terminal_disposition(
        journal: CampaignJournal,
        campaign_id: str,
        allocation_id: str,
        result: Mapping[str, Any],
    ) -> tuple[str, str]:
        """Bind a returned non-success disposition to the sealed child terminal."""

        child_id = child_attempt_id(campaign_id, allocation_id)
        if result.get("child_attempt_id") != child_id:
            raise CampaignExecutorError("parent-bound arm returned the wrong child attempt")
        terminal_status = result.get("terminal_status")
        launch_state = result.get("launch_state")
        if terminal_status not in {SUCCESS, FAILURE, BURN}:
            raise CampaignExecutorError("parent-bound arm returned an invalid terminal status")
        if terminal_status in {SUCCESS, FAILURE} and launch_state != POPEN_OBSERVED:
            raise CampaignExecutorError("successful/failed child lacks POPEN_OBSERVED")
        if terminal_status == BURN and launch_state not in {
            NEVER_STARTED,
            START_DURABLE_POPEN_UNCERTAIN,
        }:
            raise CampaignExecutorError("burned child has an invalid launch state")

        arm_journal = getattr(journal, "_arm_journal", None)
        state_reader = getattr(arm_journal, "state", None)
        evidence_reader = getattr(arm_journal, "read_terminal_evidence", None)
        if not callable(state_reader) or not callable(evidence_reader):
            raise CampaignExecutorError("campaign-owned child witness is unavailable")
        try:
            child_state = state_reader(child_id)
            payload = evidence_reader(child_id)
            child_evidence = json.loads(payload.decode("ascii"))
        except Exception as exc:
            raise CampaignExecutorError("parent-bound child terminal could not be reopened") from exc
        if (
            not isinstance(child_state, Mapping)
            or child_state.get("state") != CHILD_TERMINAL
            or child_state.get("terminal_status") != terminal_status
            or not isinstance(child_evidence, Mapping)
            or canonical_json_bytes(child_evidence) != payload
            or child_evidence.get("scope") != "parent_bound_campaign_arm"
            or child_evidence.get("terminal_status") != terminal_status
            or child_evidence.get("launch_state") != launch_state
        ):
            raise CampaignExecutorError("returned child disposition differs from sealed evidence")
        return terminal_status, launch_state

    def _seal_prelaunch_veto(
        self,
        journal: CampaignJournal,
        campaign_id: str,
    ) -> dict[str, Any]:
        state = journal.state(campaign_id)
        evidence = build_prelaunch_veto_manifest(
            state,
            campaign_root_id=journal.root_id,
        )
        journal.veto_prelaunch(campaign_id, evidence)
        return self._deps.campaign_composer(journal, campaign_id)

    def _burn(
        self,
        journal: CampaignJournal,
        campaign_id: str,
        allocation: Mapping[str, Any],
        *,
        launch_state: str,
    ) -> None:
        allocation_id = allocation["allocation_id"]
        state = journal.state(campaign_id)
        if allocation_id in state["dispositions"]:
            return
        evidence = self._deps.arm_terminal_builder(
            campaign_id=campaign_id,
            allocation_id=allocation_id,
            logical_attempt_id=allocation["logical_attempt_id"],
            terminal_status=BURN,
            launch_state=launch_state,
            sandbox_arm_claim_sha256=allocation["sandbox_arm_claim_sha256"],
        )
        journal.terminal_arm(campaign_id, allocation_id, BURN, launch_state, evidence)

    def _seal_terminal(self, journal: CampaignJournal, campaign_id: str) -> dict[str, Any]:
        state = journal.state(campaign_id)
        if state["state"] == TERMINAL:
            return state
        statuses = [item["terminal_status"] for item in state["dispositions"].values()]
        terminal_status = SUCCESS if statuses and all(item == SUCCESS for item in statuses) else VETO
        evidence = self._deps.campaign_terminal_builder(
            state,
            campaign_root_id=journal.root_id,
            terminal_status=terminal_status,
        )
        journal.terminal_campaign(campaign_id, terminal_status, evidence)
        return journal.state(campaign_id)

    def _burn_remainder(self, journal: CampaignJournal, campaign_id: str) -> None:
        """Close the active wave then all future allocations in canonical order."""

        plan = journal.read_campaign_plan(campaign_id)
        state = journal.state(campaign_id)
        current_wave = state.get("current_wave")
        if current_wave is None:
            raise CampaignExecutorError("cannot burn remainder without an active wave")
        for allocation in plan["allocations"]:
            allocation_id = allocation["allocation_id"]
            fresh = journal.state(campaign_id)
            if allocation_id in fresh["dispositions"]:
                continue
            launch_state = (
                self._ambiguous_child_launch_state(journal, campaign_id, allocation_id)
                if allocation["wave"] == current_wave
                else NEVER_STARTED
            )
            self._burn(
                journal,
                campaign_id,
                allocation,
                launch_state=launch_state,
            )

    def _recover_existing(self, journal: CampaignJournal, campaign_id: str) -> dict[str, Any]:
        """Never resume: burn all ambiguous work and finish as a zero-outcome VETO."""

        state = journal.state(campaign_id)
        if state["state"] == TERMINAL:
            # Read-only: composition itself reopens authenticated CAS only.
            return self._deps.campaign_composer(journal, campaign_id)
        journal.recover()
        state = journal.state(campaign_id)
        if state["state"] == TERMINAL:
            return self._deps.campaign_composer(journal, campaign_id)
        if state["state"] in {"CLAIMED", "PREPARED"} or (
            state["state"] == "STARTED" and not state["started_waves"]
        ):
            return self._seal_prelaunch_veto(journal, campaign_id)
        self._burn_remainder(journal, campaign_id)
        self._seal_terminal(journal, campaign_id)
        return self._deps.campaign_composer(journal, campaign_id)

    def _execute_allocation(
        self,
        journal: CampaignJournal,
        campaign_id: str,
        allocation: Mapping[str, Any],
        bundle_dir: Path,
        campaign_dir: Path,
    ) -> bool:
        """Run one child once and record its exact or conservative disposition."""

        allocation_id = allocation["allocation_id"]
        try:
            result = self._deps.arm_executor(
                bundle_dir,
                output_dir=campaign_dir / "arms" / allocation_id,
                campaign_journal=journal,
                campaign_id=campaign_id,
                allocation_id=allocation_id,
            )
            if not isinstance(result, Mapping):
                raise CampaignExecutorError("parent-bound arm did not return an authenticated result")
            terminal_status, launch_state = self._verified_child_terminal_disposition(
                journal,
                campaign_id,
                allocation_id,
                result,
            )
            child_id = child_attempt_id(campaign_id, allocation_id)
            if terminal_status != SUCCESS:
                evidence = self._deps.arm_terminal_builder(
                    campaign_id=campaign_id,
                    allocation_id=allocation_id,
                    logical_attempt_id=allocation["logical_attempt_id"],
                    terminal_status=terminal_status,
                    launch_state=launch_state,
                    sandbox_arm_claim_sha256=allocation["sandbox_arm_claim_sha256"],
                )
                journal.terminal_arm(
                    campaign_id,
                    allocation_id,
                    terminal_status,
                    launch_state,
                    evidence,
                )
                return False

            witnessed = self._deps.arm_composer(journal._arm_journal, child_id)
            binding = result.get("parent_binding")
            if not isinstance(binding, Mapping):
                raise CampaignExecutorError("successful parent-bound arm lacks parent binding")
            evidence = self._deps.arm_terminal_builder(
                campaign_id=campaign_id,
                allocation_id=allocation_id,
                logical_attempt_id=allocation["logical_attempt_id"],
                terminal_status=SUCCESS,
                launch_state=POPEN_OBSERVED,
                sandbox_arm_claim_sha256=allocation["sandbox_arm_claim_sha256"],
                child_attempt_id=child_id,
                parent_bound_child_claim_sha256=binding.get("parent_bound_child_claim_sha256"),
                child_claim_event_sha256=binding.get("child_claim_event_sha256"),
                child_start_event_sha256=binding.get("child_start_event_sha256"),
                witnessed_arm=witnessed,
            )
            journal.terminal_arm(campaign_id, allocation_id, SUCCESS, POPEN_OBSERVED, evidence)
            return True
        except BaseException:
            # An exception after child START is launch-ambiguous.  ARM_BOUND by
            # itself is not launch evidence because it precedes PREPARE/START.
            state = journal.state(campaign_id)
            if allocation_id not in state["dispositions"]:
                self._burn(
                    journal,
                    campaign_id,
                    allocation,
                    launch_state=self._ambiguous_child_launch_state(
                        journal,
                        campaign_id,
                        allocation_id,
                    ),
                )
            return False

    def run(
        self,
        *,
        journal: CampaignJournal,
        plan: object,
        allocation_bundle_dirs: Mapping[str, object],
        evaluation_epoch_sha256: str,
        output_root: Path,
    ) -> dict[str, Any]:
        """Claim once, fully prepare, run canonical waves, then compose or veto."""

        if not isinstance(journal, CampaignJournal):
            raise CampaignExecutorError("journal must be a CampaignJournal")
        checked_plan = self._deps.plan_validator(plan)
        if not isinstance(checked_plan, Mapping):
            raise CampaignExecutorError("campaign plan validator did not return an object")
        checked_plan = dict(checked_plan)
        self._require_digest(checked_plan.get("content_sha256"), label="plan.content_sha256")
        self._require_digest(evaluation_epoch_sha256, label="evaluation_epoch_sha256")
        bundle_dirs = self._exact_bundle_dirs(checked_plan, allocation_bundle_dirs)
        output_root = output_root.resolve()

        with self._execution_lock(journal):
            campaign_id = journal.campaign_id_for_plan(checked_plan, evaluation_epoch_sha256)
            try:
                existing = journal.state(campaign_id)
            except Exception:
                # A crashed writer can leave an authenticated event ahead of
                # its signed head.  Recover that journal condition only when
                # the direct read did not establish a terminal read-only run.
                journal.recover()
                try:
                    existing = journal.state(campaign_id)
                except Exception:
                    existing = None
            if existing is not None:
                if existing["state"] == TERMINAL:
                    return self._deps.campaign_composer(journal, campaign_id)
                return self._recover_existing(journal, campaign_id)

            claim = journal.claim_campaign(checked_plan, evaluation_epoch_sha256)
            campaign_id = claim["payload"]["campaign_id"]
            campaign_dir = output_root / campaign_id
            try:
                if campaign_dir.exists():
                    raise CampaignExecutorError(f"campaign artifact path already exists: {campaign_dir}")
                campaign_dir.mkdir(parents=True, mode=0o700)
                prepared = self._prepared_manifest(
                    journal, campaign_id, checked_plan, bundle_dirs, campaign_dir
                )
                journal.prepare_campaign(campaign_id, prepared)
                start_runtime = self._runtime_receipt(
                    checked_plan, campaign_id, phase="campaign_start"
                )
                journal.start_campaign(campaign_id, start_runtime)
            except BaseException:
                # Before WAVE_START no arm can have been called.  Consume the
                # one-shot claim rather than offering a fresh preparation try.
                state = journal.state(campaign_id)
                if state["state"] != TERMINAL:
                    return self._seal_prelaunch_veto(journal, campaign_id)
                return self._deps.campaign_composer(journal, campaign_id)

            failed = False
            scheduler_width = int(checked_plan["runner_binding"]["scheduler_width"])
            for wave in sorted({item["wave"] for item in checked_plan["allocations"]}):
                wave_allocations = [
                    item for item in checked_plan["allocations"] if item["wave"] == wave
                ]
                try:
                    wave_runtime = self._runtime_receipt(
                        checked_plan, campaign_id, phase="wave_start", wave=wave
                    )
                    journal.start_wave(
                        campaign_id,
                        wave,
                        [item["allocation_id"] for item in wave_allocations],
                        runtime_verification=wave_runtime,
                    )
                except BaseException:
                    failed = True
                    state = journal.state(campaign_id)
                    if not state["started_waves"]:
                        return self._seal_prelaunch_veto(journal, campaign_id)
                    self._burn_remainder(journal, campaign_id)
                    break
                with ThreadPoolExecutor(
                    max_workers=min(scheduler_width, len(wave_allocations)),
                    thread_name_prefix=f"ev42-wave-{wave}",
                ) as pool:
                    futures = [
                        pool.submit(
                            self._execute_allocation,
                            journal,
                            campaign_id,
                            allocation,
                            bundle_dirs[allocation["allocation_id"]],
                            campaign_dir,
                        )
                        for allocation in wave_allocations
                    ]
                    # Iterate every future even after a failure: WAVE_START
                    # commits the complete allocation slice.
                    for future in futures:
                        try:
                            succeeded = future.result()
                        except BaseException:
                            succeeded = False
                        if not succeeded:
                            failed = True
                if failed:
                    # The whole started wave is executed exactly once before
                    # any future allocation is consumed as NEVER_STARTED.
                    self._burn_remainder(journal, campaign_id)
                    break

            self._seal_terminal(journal, campaign_id)
            return self._deps.campaign_composer(journal, campaign_id)


def _read_json(path: Path) -> object:
    try:
        with path.open("r", encoding="ascii") as handle:
            return json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CampaignExecutorError(f"cannot read JSON from {path}: {exc}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--bundle-map", type=Path, required=True)
    parser.add_argument("--evaluation-epoch-sha256", required=True)
    parser.add_argument("--journal-root", type=Path, required=True)
    parser.add_argument("--journal-key-file", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        key = args.journal_key_file.read_bytes()
        if not key:
            raise CampaignExecutorError("journal key file is empty")
        result = CampaignExecutor().run(
            journal=CampaignJournal(args.journal_root, key),
            plan=_read_json(args.plan),
            allocation_bundle_dirs=_read_json(args.bundle_map),
            evaluation_epoch_sha256=args.evaluation_epoch_sha256,
            output_root=args.output_root,
        )
    except CampaignExecutorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI wrapper.
    raise SystemExit(main())
