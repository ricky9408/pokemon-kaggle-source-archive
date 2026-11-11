from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import os
import shutil
import subprocess
import textwrap
import time
import zlib

import pytest


ROOT = Path(__file__).resolve().parents[1]
HEADER_DIR = ROOT / "evaluation_v6_3_1" / "cpp"


DRIVER = textwrap.dedent(
    r'''
    #define V631302_DURABLE_TEST_HOOKS
    #include "V631302TraceEmitter.h"
    #include "V631302EngineSession.h"
    #include "V631302DurableJournal.h"

    #include <chrono>
    #include <atomic>
    #include <iostream>
    #include <string>
    #include <thread>
    #include <vector>

    using v631302::durable::Bytes;
    using v631302::durable::DurableJournal;
    using v631302::durable::DurableJournalError;
    using v631302::durable::IoTarget;

    Bytes bytes(const std::string& value) {
      return Bytes(value.begin(), value.end());
    }

    int main(int argc, char** argv) {
      if (argc < 3) {
        std::cerr << "usage" << std::endl;
        return 64;
      }
      const std::string command = argv[1];
      const std::string root = argv[2];
      try {
        DurableJournal journal(root);

        if (command == "append") {
          const auto result = journal.append_transaction(bytes(argc >= 4 ? argv[3] : "event"));
          std::cout << "append " << result.old_offset << " " << result.new_offset
                    << " " << result.transaction_sequence << std::endl;
        } else if (command == "concurrent") {
          std::atomic<unsigned int> failures{0U};
          std::vector<std::thread> workers;
          for (unsigned int index = 0U; index < 8U; ++index) {
            workers.emplace_back([&journal, &failures, index]() {
              try {
                (void)journal.append_transaction(Bytes{static_cast<std::uint8_t>('a' + index)});
              } catch (...) {
                failures.fetch_add(1U, std::memory_order_relaxed);
              }
            });
          }
          for (auto& worker : workers) worker.join();
          std::cout << "concurrent " << journal.committed_offset() << " "
                    << journal.committed_transaction_sequence() << " "
                    << failures.load() << std::endl;
        } else if (command == "short-success") {
          journal.test_set_max_write_bytes(IoTarget::Trace, 2U);
          const auto result = journal.append_transaction(bytes("short-write-success"));
          std::cout << "append " << result.new_offset << std::endl;
        } else if (command == "short-fail") {
          journal.test_set_max_write_bytes(IoTarget::Trace, 3U);
          journal.test_fail_write_call(IoTarget::Trace, 2U);
          (void)journal.append_transaction(bytes("partial-trace-event"));
        } else if (command == "fsync-fail") {
          journal.test_fail_fsync_call(IoTarget::Wal, 1U);
          (void)journal.append_transaction(bytes("fsync-failure-event"));
        } else if (command == "retry-after-failure") {
          journal.test_fail_write_call(IoTarget::Trace, 1U);
          try {
            (void)journal.append_transaction(bytes("failed-event"));
            return 65;
          } catch (const DurableJournalError&) {
          }
          try {
            (void)journal.append_transaction(bytes("forbidden-retry"));
            return 66;
          } catch (const DurableJournalError& error) {
            std::cout << "poisoned " << error.code() << std::endl;
          }
        } else if (command == "wal-sequence-overflow") {
          journal.test_set_wal_next_sequence(
            std::numeric_limits<std::uint64_t>::max() - 1U
          );
          (void)journal.append_transaction(bytes("must-not-append"));
        } else if (command == "wal-offset-overflow") {
          journal.test_set_wal_end(std::numeric_limits<std::uint64_t>::max() - 1U);
          (void)journal.append_transaction(bytes("must-not-append"));
        } else if (command == "crash") {
          if (argc < 4) return 64;
          const std::string point = argv[3];
          if (point == "prepare") journal.test_crash_at(v631302::durable::CrashPoint::AfterPrepareFsync);
          else if (point == "trace-write") journal.test_crash_at(v631302::durable::CrashPoint::AfterTraceWrite);
          else if (point == "trace-fsync") journal.test_crash_at(v631302::durable::CrashPoint::AfterTraceFsync);
          else if (point == "commit") journal.test_crash_at(v631302::durable::CrashPoint::AfterCommitFsync);
          else return 64;
          (void)journal.append_transaction(bytes("crashed-event"));
        } else if (command == "open") {
          std::cout << "open " << journal.committed_offset() << " "
                    << journal.committed_transaction_sequence() << std::endl;
        } else if (command == "hold") {
          std::cout << "ready" << std::endl;
          std::cout.flush();
          std::this_thread::sleep_for(std::chrono::seconds(10));
        } else {
          return 64;
        }
      } catch (const DurableJournalError& error) {
        std::cout << "error " << error.code() << std::endl;
        return 2;
      }
      return 0;
    }
    '''
)


PRODUCTION_INCLUDE_DRIVER = textwrap.dedent(
    r'''
    #include "V631302TraceEmitter.h"
    #include "V631302EngineSession.h"
    #include "V631302DurableJournal.h"

    static_assert(v631302::kCampaignAuthority == false);
    static_assert(v631302::kEngineIntegrated == false);
    static_assert(v631302::durable::kAuthority == false);
    static_assert(v631302::durable::kCampaignAuthority == false);
    static_assert(v631302::durable::kDurableProductionReady == false);
    static_assert(v631302::durable::kEngineIntegrated == false);
    static_assert(v631302::durable::kSemanticAuthenticationImplemented == false);
    static_assert(v631302::durable::kExternalAnchorImplemented == false);
    static_assert(v631302::durable::kPostPrepareFailurePoisoningImplemented == true);

    int main() { return 0; }
    '''
)


@pytest.fixture(scope="session")
def durable_driver(tmp_path_factory: pytest.TempPathFactory) -> Path:
    compiler = shutil.which("c++")
    if compiler is None:
        pytest.skip("a C++20 compiler is required")
    build_dir = tmp_path_factory.mktemp("native-631302-durable-driver")
    source = build_dir / "driver.cpp"
    executable = build_dir / "driver"
    source.write_text(DRIVER, encoding="ascii")
    subprocess.run(
        [
            compiler,
            "-std=c++20",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-pthread",
            "-I",
            str(HEADER_DIR),
            str(source),
            "-o",
            str(executable),
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    return executable


@pytest.fixture(scope="session")
def production_include_driver(tmp_path_factory: pytest.TempPathFactory) -> Path:
    compiler = shutil.which("c++")
    if compiler is None:
        pytest.skip("a C++20 compiler is required")
    build_dir = tmp_path_factory.mktemp("native-631302-durable-include-driver")
    source = build_dir / "include_driver.cpp"
    executable = build_dir / "include_driver"
    source.write_text(PRODUCTION_INCLUDE_DRIVER, encoding="ascii")
    subprocess.run(
        [
            compiler,
            "-std=c++20",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-pthread",
            "-I",
            str(HEADER_DIR),
            str(source),
            "-o",
            str(executable),
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    return executable


def run(driver: Path, command: str, root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(driver), command, str(root), *args],
        text=True,
        capture_output=True,
    )


def trace(root: Path) -> bytes:
    return (root / "trace.cbor").read_bytes()


def test_durable_header_includes_with_engine_headers(
    production_include_driver: Path,
) -> None:
    result = subprocess.run(
        [str(production_include_driver)],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr


def test_clean_append_is_exact_unframed_and_wal_has_no_event_bytes(
    durable_driver: Path, tmp_path: Path
) -> None:
    root = tmp_path / "clean"
    root.mkdir()
    first = b"private-event-one"
    second = b"private-event-two"

    assert run(durable_driver, "append", root, first.decode()).returncode == 0
    assert run(durable_driver, "append", root, second.decode()).returncode == 0
    assert trace(root) == first + second
    wal = (root / "durable.wal").read_bytes()
    assert first not in wal
    assert second not in wal
    assert (root / "trace.cbor").stat().st_mode & 0o777 == 0o600
    assert (root / "durable.wal").stat().st_mode & 0o777 == 0o600
    assert (root / "session.lock").stat().st_mode & 0o777 == 0o600
    assert run(durable_driver, "open", root).stdout == "open 34 2\n"


def test_same_object_concurrent_appends_are_serialized(
    durable_driver: Path, tmp_path: Path
) -> None:
    root = tmp_path / "same-object-concurrent"
    root.mkdir()
    result = run(durable_driver, "concurrent", root)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "concurrent 8 8 0\n"
    assert sorted(trace(root)) == list(range(ord("a"), ord("i")))
    assert run(durable_driver, "open", root).stdout == "open 8 8\n"


@pytest.mark.parametrize(
    ("point", "expected_trace"),
    [
        ("prepare", b"stable-prefix"),
        ("trace-write", b"stable-prefix"),
        ("trace-fsync", b"stable-prefix"),
        ("commit", b"stable-prefixcrashed-event"),
    ],
)
def test_crash_boundaries_recover_to_one_committed_state(
    durable_driver: Path, tmp_path: Path, point: str, expected_trace: bytes
) -> None:
    root = tmp_path / f"crash-{point}"
    root.mkdir()
    assert run(durable_driver, "append", root, "stable-prefix").returncode == 0
    crashed = run(durable_driver, "crash", root, point)
    assert crashed.returncode == 90 + {"prepare": 1, "trace-write": 2, "trace-fsync": 3, "commit": 4}[point]
    reopened = run(durable_driver, "open", root)
    assert reopened.returncode == 0
    assert trace(root) == expected_trace


def test_torn_wal_tail_rolls_back_only_the_pending_transaction(
    durable_driver: Path, tmp_path: Path
) -> None:
    root = tmp_path / "torn-wal"
    root.mkdir()
    assert run(durable_driver, "append", root, "base").returncode == 0
    assert run(durable_driver, "append", root, "pending").returncode == 0
    wal_path = root / "durable.wal"
    wal_path.write_bytes(wal_path.read_bytes()[:-5])

    reopened = run(durable_driver, "open", root)
    assert reopened.returncode == 0
    assert trace(root) == b"base"
    assert reopened.stdout == "open 4 1\n"


def test_partial_trace_and_io_failures_fail_then_recover(
    durable_driver: Path, tmp_path: Path
) -> None:
    partial_root = tmp_path / "partial-trace"
    partial_root.mkdir()
    assert run(durable_driver, "append", partial_root, "base").returncode == 0
    failed = run(durable_driver, "short-fail", partial_root)
    assert failed.returncode == 2
    assert "RNG_DURABLE_IO_FAILED" in failed.stdout
    reopened = run(durable_driver, "open", partial_root)
    assert reopened.returncode == 0
    assert trace(partial_root) == b"base"

    fsync_root = tmp_path / "fsync-failure"
    fsync_root.mkdir()
    failed = run(durable_driver, "fsync-fail", fsync_root)
    assert failed.returncode == 2
    assert "RNG_DURABLE_IO_FAILED" in failed.stdout
    assert run(durable_driver, "open", fsync_root).returncode == 0
    assert trace(fsync_root) == b""

    short_root = tmp_path / "short-success"
    short_root.mkdir()
    assert run(durable_driver, "short-success", short_root).returncode == 0
    assert trace(short_root) == b"short-write-success"


def test_failed_post_prepare_append_poisoned_until_reopen(
    durable_driver: Path, tmp_path: Path
) -> None:
    root = tmp_path / "poisoned-after-prepare"
    root.mkdir()
    failed = run(durable_driver, "retry-after-failure", root)
    assert failed.returncode == 0, failed.stderr
    assert failed.stdout == "poisoned RNG_TRANSACTION_PARTIAL_COMMIT\n"
    reopened = run(durable_driver, "open", root)
    assert reopened.returncode == 0, reopened.stderr
    assert reopened.stdout == "open 0 0\n"
    assert trace(root) == b""


def test_committed_trace_mismatch_and_wal_interior_corruption_fail_closed(
    durable_driver: Path, tmp_path: Path
) -> None:
    trace_root = tmp_path / "committed-trace-mismatch"
    trace_root.mkdir()
    assert run(durable_driver, "append", trace_root, "committed").returncode == 0
    trace_path = trace_root / "trace.cbor"
    corrupted_trace = bytearray(trace_path.read_bytes())
    corrupted_trace[0] ^= 0x01
    trace_path.write_bytes(corrupted_trace)
    rejected = run(durable_driver, "open", trace_root)
    assert rejected.returncode == 2
    assert "RNG_DURABLE_COMMITTED_MISMATCH" in rejected.stdout

    wal_root = tmp_path / "wal-interior-corruption"
    wal_root.mkdir()
    assert run(durable_driver, "append", wal_root, "one").returncode == 0
    assert run(durable_driver, "append", wal_root, "two").returncode == 0
    wal_path = wal_root / "durable.wal"
    corrupted_wal = bytearray(wal_path.read_bytes())
    corrupted_wal[100] ^= 0x01
    wal_path.write_bytes(corrupted_wal)
    rejected = run(durable_driver, "open", wal_root)
    assert rejected.returncode == 2
    assert "RNG_DURABLE_JOURNAL_INTERIOR_CORRUPTION" in rejected.stdout


def test_recovery_recomputes_prepare_transaction_identity(
    durable_driver: Path, tmp_path: Path
) -> None:
    root = tmp_path / "transaction-identity"
    root.mkdir()
    assert run(durable_driver, "append", root, "bound-event").returncode == 0
    wal_path = root / "durable.wal"
    wal = bytearray(wal_path.read_bytes())
    prepare_size = 96 + 160 + 36
    commit_size = 96 + 128 + 36
    assert len(wal) == prepare_size + commit_size
    forged_id = bytes([0xA5]) * 32

    def rewrite_frame(offset: int, payload_size: int, previous: bytes) -> bytes:
        wal[offset + 32 : offset + 64] = previous
        payload_start = offset + 96
        payload_end = payload_start + payload_size
        wal[payload_start : payload_start + 32] = forged_id
        wal[offset + 64 : offset + 96] = sha256(wal[payload_start:payload_end]).digest()
        record_hash = sha256(wal[offset:payload_end]).digest()
        wal[payload_end : payload_end + 32] = record_hash
        crc = zlib.crc32(wal[offset : payload_end + 32]) & 0xFFFFFFFF
        wal[payload_end + 32 : payload_end + 36] = crc.to_bytes(4, "big")
        return record_hash

    prepare_hash = rewrite_frame(0, 160, bytes(32))
    rewrite_frame(prepare_size, 128, prepare_hash)
    wal_path.write_bytes(wal)

    rejected = run(durable_driver, "open", root)
    assert rejected.returncode == 2
    assert "RNG_DURABLE_JOURNAL_INTERIOR_CORRUPTION" in rejected.stdout


@pytest.mark.parametrize("command", ["wal-sequence-overflow", "wal-offset-overflow"])
def test_wal_sequence_and_offset_exhaustion_fail_before_writing(
    durable_driver: Path, tmp_path: Path, command: str
) -> None:
    root = tmp_path / command
    root.mkdir()
    rejected = run(durable_driver, command, root)
    assert rejected.returncode == 2
    assert "RNG_TRANSACTION_PARTIAL_COMMIT" in rejected.stdout
    assert trace(root) == b""
    assert (root / "durable.wal").read_bytes() == b""


def test_concurrent_session_lock_is_rejected(
    durable_driver: Path, tmp_path: Path
) -> None:
    root = tmp_path / "lock"
    root.mkdir()
    holder = subprocess.Popen(
        [str(durable_driver), "hold", str(root)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "ready"
        rejected = run(durable_driver, "open", root)
        assert rejected.returncode == 2
        assert "RNG_CONCURRENT_AUTHORITATIVE_ACCESS" in rejected.stdout
    finally:
        holder.terminate()
        try:
            holder.wait(timeout=2)
        except subprocess.TimeoutExpired:
            holder.kill()
            holder.wait(timeout=2)
        time.sleep(0.01)


def test_unsafe_directory_symlink_and_hardlink_paths_are_rejected(
    durable_driver: Path, tmp_path: Path
) -> None:
    writable_root = tmp_path / "group-writable"
    writable_root.mkdir()
    writable_root.chmod(0o770)
    rejected = run(durable_driver, "open", writable_root)
    assert rejected.returncode == 2
    assert "RNG_DURABLE_PATH_UNSAFE" in rejected.stdout

    symlink_root = tmp_path / "private-symlink"
    symlink_root.mkdir()
    symlink_target = tmp_path / "symlink-target"
    symlink_target.write_bytes(b"must-not-change")
    (symlink_root / "trace.cbor").symlink_to(symlink_target)
    rejected = run(durable_driver, "open", symlink_root)
    assert rejected.returncode == 2
    assert "RNG_DURABLE_PATH_UNSAFE" in rejected.stdout
    assert symlink_target.read_bytes() == b"must-not-change"

    hardlink_root = tmp_path / "private-hardlink"
    hardlink_root.mkdir()
    hardlink_target = tmp_path / "hardlink-target"
    hardlink_target.write_bytes(b"must-also-not-change")
    os.link(hardlink_target, hardlink_root / "trace.cbor")
    rejected = run(durable_driver, "open", hardlink_root)
    assert rejected.returncode == 2
    assert "RNG_DURABLE_PATH_UNSAFE" in rejected.stdout
    assert hardlink_target.read_bytes() == b"must-also-not-change"
