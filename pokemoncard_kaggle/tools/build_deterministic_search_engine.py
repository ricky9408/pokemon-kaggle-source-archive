#!/usr/bin/env python3
"""Build the evaluator-only deterministic search engine on Linux/amd64."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v2.native_engine import (
    patch_engine_source,
    patch_game_wrapper,
    patch_sim_wrapper,
    tree_sha256,
)


PYTHON_WRAPPER_FILES = ("__init__.py", "api.py", "game.py", "sim.py", "utils.py")


def _sha256_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, capture_output=True)


def build(
    *,
    source_dir: Path,
    wrapper_dir: Path,
    output_dir: Path,
    compiler_image: str,
    zig_dir: Path,
) -> dict[str, object]:
    source_dir = source_dir.resolve()
    wrapper_dir = wrapper_dir.resolve()
    output_dir = output_dir.resolve()
    zig_dir = zig_dir.resolve()
    if not (zig_dir / "zig").is_file() or not (zig_dir / "lib").is_dir():
        raise ValueError("zig_dir must contain the Linux/amd64 zig toolchain")
    if output_dir.exists():
        raise FileExistsError(f"output already exists: {output_dir}")
    output_dir.mkdir(parents=True)

    patched_source = output_dir / "source"
    patch_manifest = patch_engine_source(source_dir, patched_source)
    cg_dir = output_dir / "cg"
    cg_dir.mkdir()
    wrapper_hashes: dict[str, str] = {}
    for name in PYTHON_WRAPPER_FILES:
        source = wrapper_dir / name
        if not source.is_file():
            raise FileNotFoundError(source)
        destination = cg_dir / name
        shutil.copy2(source, destination)
        if name == "sim.py":
            destination.write_text(
                patch_sim_wrapper(destination.read_text(encoding="utf-8-sig")),
                encoding="utf-8",
            )
        elif name == "game.py":
            destination.write_text(
                patch_game_wrapper(destination.read_text(encoding="utf-8-sig")),
                encoding="utf-8",
            )
        wrapper_hashes[name] = _sha256_file(destination)

    compile_command = [
        "docker",
        "run",
        "--rm",
        "--platform",
        "linux/amd64",
        "-v",
        f"{patched_source}:/src:ro",
        "-v",
        f"{cg_dir}:/out",
        "-v",
        f"{zig_dir}:/zig:ro",
        compiler_image,
        "/zig/zig",
        "c++",
        "-target",
        "x86_64-linux-gnu",
        "-std=c++20",
        "-O3",
        "-DNDEBUG",
        "-fPIC",
        "-shared",
        "-w",
        "/src/Export.cpp",
        "-o",
        "/out/libcg.so",
    ]
    _run(compile_command)
    library = cg_dir / "libcg.so"
    if not library.is_file():
        raise RuntimeError("compiler did not create libcg.so")
    compiler = _run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "-v",
            f"{zig_dir}:/zig:ro",
            compiler_image,
            "/zig/zig",
            "version",
        ]
    ).stdout.strip()

    manifest = {
        "artifact_kind": "local_evaluator_only_do_not_submit",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "target_platform": "linux/amd64",
        "compiler_image": compiler_image,
        "compiler": f"zig {compiler}",
        "compiler_toolchain_sha256": tree_sha256(zig_dir),
        "compile_command": compile_command,
        "patch": patch_manifest.to_dict(),
        "wrapper_sha256": wrapper_hashes,
        "libcg_sha256": _sha256_file(library),
    }
    (output_dir / "build_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    (output_dir / "DO_NOT_SUBMIT").write_text(
        "This patched engine is only for deterministic local evaluation.\n"
        "Never include it in a Kaggle agent archive.\n"
    )
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=Path("references/ptcg_engine_20260701"))
    parser.add_argument(
        "--wrapper-dir",
        type=Path,
        default=Path("references/kaggle_sample_engine_20260701/cg"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("evaluation_artifacts/native_engine/deterministic_v4_linux_amd64"),
    )
    parser.add_argument("--compiler-image", default="python:3.11-slim")
    parser.add_argument(
        "--zig-dir",
        type=Path,
        default=Path("evaluation_artifacts/native_engine/ziglinux/ziglang"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    manifest = build(
        source_dir=args.source_dir,
        wrapper_dir=args.wrapper_dir,
        output_dir=args.output_dir,
        compiler_image=args.compiler_image,
        zig_dir=args.zig_dir,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
