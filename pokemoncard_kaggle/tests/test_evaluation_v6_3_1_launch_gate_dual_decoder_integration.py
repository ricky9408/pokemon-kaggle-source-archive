"""Pinned-image diagnostic agreement for both independent Stage-1 decoders."""

from __future__ import annotations

import subprocess
from hashlib import sha256
from pathlib import Path

import pytest

from evaluation_v6_3_1.launch_gate_decoder_manifest_v1 import (
    OUTPUT_BYTE_MISMATCH,
    compare_launch_gate_decoder_outputs_v1,
)


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "sha256:38634214ff91fc0007016cdf04d9f05d9289880fe8d30c4d66b0c284095460dd"
PAGE_SHA256 = "91fce3ca09e908b9e51d73e887f67a14ba7b5c250180cb613f871666f12277f5"
RAW_OBJECT_SHA256 = "c20ea3a183f40c61ca3396771fb92cb948cc603b81e966486996f48bab84a530"


def _image_available() -> bool:
    inspected = subprocess.run(
        ["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"],
        check=False,
        capture_output=True,
        text=True,
    )
    return inspected.returncode == 0 and inspected.stdout.strip() == IMAGE


@pytest.mark.docker_smoke
def test_real_decoders_emit_identical_strict_manifests_with_zero_authority(
    tmp_path: Path,
) -> None:
    if not _image_available():
        pytest.skip("immutable LLVM16 diagnostic image is unavailable")

    script = r"""
set -eu
install -d -m 0700 /work/stage1/gate-extract /work/stage1/decoder /work/stage1/tmp
install -d -m 0700 /work/evaluation_v6_3_1/native/capture_v2/tools
cp /repo/evaluation_v6_3_1/native/capture_v2/LaunchGateV1.S /work/evaluation_v6_3_1/native/capture_v2/LaunchGateV1.S
cp /repo/evaluation_v6_3_1/native/capture_v2/tools/launch_gate_llvm_mc_decoder_v1.cpp /work/evaluation_v6_3_1/native/capture_v2/tools/launch_gate_llvm_mc_decoder_v1.cpp

cd /work/stage1/gate-extract
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C LANG=C TZ=UTC SOURCE_DATE_EPOCH=0 HOME=/nonexistent DEBUGINFOD_URLS= \
  /usr/bin/clang-16 --target=x86_64-unknown-linux-gnu -c -x assembler -fintegrated-as -Wa,--noexecstack \
  -o LaunchGateV1.o /work/evaluation_v6_3_1/native/capture_v2/LaunchGateV1.S
chmod 0444 LaunchGateV1.o
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C LANG=C TZ=UTC SOURCE_DATE_EPOCH=0 HOME=/nonexistent DEBUGINFOD_URLS= \
  /usr/bin/objcopy --input-target=elf64-x86-64 --output-target=elf64-x86-64 --dump-section \
  .text.launch_gate_v1=LaunchGateV1.page.tmp LaunchGateV1.o LaunchGateV1.objcopy-discard.o
chmod 0444 LaunchGateV1.page.tmp
mv LaunchGateV1.page.tmp LaunchGateV1.page
rm LaunchGateV1.objcopy-discard.o
test "$(sha256sum LaunchGateV1.o | cut -d' ' -f1)" = "c20ea3a183f40c61ca3396771fb92cb948cc603b81e966486996f48bab84a530"
test "$(sha256sum LaunchGateV1.page | cut -d' ' -f1)" = "91fce3ca09e908b9e51d73e887f67a14ba7b5c250180cb613f871666f12277f5"

cd /work
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C LANG=C TZ=UTC SOURCE_DATE_EPOCH=0 HOME=/nonexistent DEBUGINFOD_URLS= TMPDIR=/work/stage1/tmp \
  /usr/bin/clang++-16 --target=x86_64-unknown-linux-gnu -std=c++20 -O2 -fPIE -fno-lto -fno-exceptions -fno-rtti \
  -fno-ident -fvisibility=hidden -ffile-prefix-map=/work=. -fmacro-prefix-map=/work=. -MD \
  -MF /work/stage1/decoder/launch_gate_llvm_mc_decoder_v1.d.raw -MT launch_gate_llvm_mc_decoder_v1.o \
  -I/opt/llvm-build/include -I/opt/llvm-src/llvm/include -c \
  /work/evaluation_v6_3_1/native/capture_v2/tools/launch_gate_llvm_mc_decoder_v1.cpp \
  -o /work/stage1/decoder/launch_gate_llvm_mc_decoder_v1.o
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C LANG=C TZ=UTC SOURCE_DATE_EPOCH=0 HOME=/nonexistent DEBUGINFOD_URLS= TMPDIR=/work/stage1/tmp \
  /usr/bin/clang++-16 --target=x86_64-unknown-linux-gnu --ld-path=/usr/bin/ld.bfd -pie -Wl,--build-id=none \
  -Wl,--fatal-warnings -Wl,--no-undefined -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,nodefaultlib \
  -Wl,--disable-new-dtags -Wl,-rpath,/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu \
  /work/stage1/decoder/launch_gate_llvm_mc_decoder_v1.o /usr/lib/x86_64-linux-gnu/libLLVM-16.so.1 \
  -o /work/stage1/decoder/launch_gate_llvm_mc_decoder_v1
/usr/bin/clang++-16 --target=x86_64-unknown-linux-gnu -std=c++20 -O2 -Wall -Wextra -Werror \
  /repo/evaluation_v6_3_1/native/capture_v2/tools/launch_gate_restricted_x86_decoder_v1.cpp \
  -o /work/stage1/decoder/launch_gate_restricted_x86_decoder_v1

cd /work/stage1/decoder
/usr/bin/env -i LC_ALL=C LANG=C TZ=UTC HOME=/nonexistent DEBUGINFOD_URLS= \
  /lib64/ld-linux-x86-64.so.2 --inhibit-cache /work/stage1/decoder/launch_gate_llvm_mc_decoder_v1 \
  /work/stage1/gate-extract/LaunchGateV1.page 874 /work/stage1/decoder/llvm.cbor
/usr/bin/env -i LC_ALL=C LANG=C TZ=UTC HOME=/nonexistent DEBUGINFOD_URLS= \
  /work/stage1/decoder/launch_gate_restricted_x86_decoder_v1 \
  /work/stage1/gate-extract/LaunchGateV1.page 874 /work/stage1/decoder/restricted.cbor
cp /work/stage1/gate-extract/LaunchGateV1.page /out/gate.page
cp /work/stage1/gate-extract/LaunchGateV1.o /out/gate.o
cp /work/stage1/decoder/llvm.cbor /out/llvm.cbor
cp /work/stage1/decoder/restricted.cbor /out/restricted.cbor
"""
    run = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/work:rw,exec,nosuid,nodev,size=256m",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=64m",
            "--mount",
            f"type=bind,src={ROOT},dst=/repo,readonly",
            "--mount",
            f"type=bind,src={tmp_path},dst=/out",
            IMAGE,
            "/bin/sh",
            "-c",
            script,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert run.returncode == 0, run.stderr

    page = (tmp_path / "gate.page").read_bytes()
    raw_object = (tmp_path / "gate.o").read_bytes()
    llvm_output = (tmp_path / "llvm.cbor").read_bytes()
    restricted_output = (tmp_path / "restricted.cbor").read_bytes()
    assert sha256(page).hexdigest() == PAGE_SHA256
    assert sha256(raw_object).hexdigest() == RAW_OBJECT_SHA256

    agreement = compare_launch_gate_decoder_outputs_v1(page, llvm_output, restricted_output)
    assert agreement.valid, agreement.issues
    assert llvm_output == restricted_output
    assert agreement.first is not None
    assert agreement.first.instruction_manifest_sha256 is not None
    assert agreement.first.cfg_manifest_sha256 is not None
    assert agreement.authority is False
    assert agreement.calibration_upload_authority is False
    assert agreement.production_upload_authority is False
    assert agreement.zero_authority is True

    changed = restricted_output[:-1] + bytes((restricted_output[-1] ^ 1,))
    disagreement = compare_launch_gate_decoder_outputs_v1(page, llvm_output, changed)
    assert not disagreement.valid
    assert disagreement.issues[0].code == OUTPUT_BYTE_MISMATCH
