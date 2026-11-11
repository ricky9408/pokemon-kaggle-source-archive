#!/usr/bin/env python3
"""Freeze or verify the exact v4.2 exclusive campaign runner binding."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v4_2.campaign_protocol import validate_runner_binding  # noqa: E402
from evaluation_v4_2.campaign_runtime import (  # noqa: E402
    CampaignRuntimeError,
    build_current_runner_binding,
)
from tools.run_evaluation_v4_2_sandbox_arm import (  # noqa: E402
    DEFAULT_ARM_DEADLINE_SECONDS,
    DEFAULT_DOCKER_CALL_TIMEOUT_SECONDS,
    DEFAULT_IMAGE,
)


def _bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")


def _create_once(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise CampaignRuntimeError(f"runner binding already exists: {path}") from None
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("freeze", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--scheduler-width", type=int, default=16)
    parser.add_argument("--arm-deadline-seconds", type=float, default=DEFAULT_ARM_DEADLINE_SECONDS)
    parser.add_argument("--action-deadline-seconds", type=float, default=1.0)
    parser.add_argument(
        "--docker-call-timeout-seconds",
        type=float,
        default=DEFAULT_DOCKER_CALL_TIMEOUT_SECONDS,
    )
    args = parser.parse_args(argv)
    try:
        if args.mode == "freeze":
            binding = build_current_runner_binding(
                repository_root=ROOT,
                oci_image=args.image,
                scheduler_width=args.scheduler_width,
                arm_deadline_seconds=args.arm_deadline_seconds,
                action_deadline_seconds=args.action_deadline_seconds,
                docker_call_timeout_seconds=args.docker_call_timeout_seconds,
            )
            _create_once(args.output, _bytes(binding))
        else:
            value = json.loads(args.output.read_text(encoding="ascii"))
            binding = validate_runner_binding(value)
            # Re-freeze from live bytes and require byte-identical content.
            current = build_current_runner_binding(
                repository_root=ROOT,
                oci_image=binding["oci_image"],
                scheduler_width=binding["scheduler_width"],
                arm_deadline_seconds=binding["deadline_caps"]["arm_deadline_seconds"],
                action_deadline_seconds=binding["deadline_caps"]["action_deadline_seconds"],
                docker_call_timeout_seconds=binding["deadline_caps"]["docker_call_timeout_seconds"],
            )
            if current != binding:
                raise CampaignRuntimeError("runner binding differs from current exact runtime")
    except (CampaignRuntimeError, OSError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(1, f"v4.2 campaign runner binding failed: {exc}\n")
    print(json.dumps(binding, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
