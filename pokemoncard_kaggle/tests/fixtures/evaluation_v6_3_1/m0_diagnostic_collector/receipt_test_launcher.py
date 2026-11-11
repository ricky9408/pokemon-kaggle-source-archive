#!/usr/bin/env python3
"""Linux-only collector launcher for FD3 peer-binding and EOF tests."""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time


F_SETPIPE_SZ = getattr(fcntl, "F_SETPIPE_SZ", 1031)
F_GETPIPE_SZ = getattr(fcntl, "F_GETPIPE_SZ", 1032)


def _read_receipt_until_eof(descriptor: int, process: subprocess.Popen[bytes]) -> bytes:
    chunks: list[bytes] = []
    deadline = time.monotonic() + 20.0
    os.set_blocking(descriptor, False)
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait(timeout=5)
                raise RuntimeError("receipt descriptor did not reach EOF before timeout")
            if not poller.poll(max(1, int(remaining * 1000))):
                continue
            while True:
                try:
                    chunk = os.read(descriptor, 65536)
                except BlockingIOError:
                    break
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
    finally:
        os.close(descriptor)


def _drain_outputs_until_eof(
    stdout_descriptor: int,
    stderr_descriptor: int,
    process: subprocess.Popen[bytes],
) -> tuple[bytes, bytes]:
    descriptors = {stdout_descriptor: [], stderr_descriptor: []}
    poller = select.poll()
    for descriptor in descriptors:
        os.set_blocking(descriptor, False)
        poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
    deadline = time.monotonic() + 20.0
    active = set(descriptors)
    try:
        while active:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait(timeout=5)
                raise RuntimeError("collector output descriptors did not reach EOF")
            events = poller.poll(max(1, int(remaining * 1000)))
            if not events:
                continue
            for descriptor, _flags in events:
                if descriptor not in active:
                    continue
                while True:
                    try:
                        chunk = os.read(descriptor, 65536)
                    except BlockingIOError:
                        break
                    if not chunk:
                        poller.unregister(descriptor)
                        os.close(descriptor)
                        active.remove(descriptor)
                        break
                    descriptors[descriptor].append(chunk)
    finally:
        for descriptor in active:
            os.close(descriptor)
    return (
        b"".join(descriptors[stdout_descriptor]),
        b"".join(descriptors[stderr_descriptor]),
    )


def main() -> int:
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        raise SystemExit("usage: receipt_test_launcher.py OUTDIR -- COMMAND...")
    output_dir = Path(sys.argv[1])
    output_dir.mkdir(parents=True, exist_ok=True)
    command = sys.argv[3:]

    receipt_read_initial, receipt_write = os.pipe2(os.O_CLOEXEC)
    receipt_read = fcntl.fcntl(receipt_read_initial, fcntl.F_DUPFD_CLOEXEC, 10)
    os.close(receipt_read_initial)
    os.dup2(receipt_write, 3, inheritable=True)
    if receipt_write != 3:
        os.close(receipt_write)
    os.set_inheritable(3, True)
    stdout_read, stdout_write = os.pipe2(os.O_CLOEXEC)
    stderr_read, stderr_write = os.pipe2(os.O_CLOEXEC)
    pipe_size = fcntl.fcntl(stdout_read, F_SETPIPE_SZ, 4096)
    pipe_size = fcntl.fcntl(stdout_read, F_GETPIPE_SZ)
    peer_status = os.fstat(receipt_read)

    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=stdout_write,
        stderr=stderr_write,
        close_fds=True,
        pass_fds=(3,),
    )
    os.close(3)
    os.close(stdout_write)
    os.close(stderr_write)

    receipt = _read_receipt_until_eof(receipt_read, process)
    alive_at_receipt_eof = process.poll() is None
    stdout, stderr = _drain_outputs_until_eof(stdout_read, stderr_read, process)
    try:
        status = process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        process.kill()
        status = process.wait(timeout=5)
        raise RuntimeError("collector remained alive after all channels reached EOF")

    (output_dir / "receipt.bin").write_bytes(receipt)
    (output_dir / "stdout.bin").write_bytes(stdout)
    (output_dir / "stderr.bin").write_bytes(stderr)
    (output_dir / "status.txt").write_text(f"{status}\n", encoding="ascii")
    (output_dir / "peer.json").write_text(
        json.dumps(
            {
                "alive_at_receipt_eof": alive_at_receipt_eof,
                "pipe_size": pipe_size,
                "read_st_dev": peer_status.st_dev,
                "read_st_ino": peer_status.st_ino,
                "stdout_length": len(stdout),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
