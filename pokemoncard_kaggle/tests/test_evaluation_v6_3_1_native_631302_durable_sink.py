from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import shutil
import subprocess

import pytest

from evaluation_v6_3_1.unified_rng_events import decode_trace_events, verify_trace_bytes


ROOT = Path(__file__).resolve().parents[1]
HEADER_DIR = ROOT / "evaluation_v6_3_1" / "cpp"


def _root(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def _initializer(value: bytes) -> str:
    return ", ".join(f"0x{byte:02x}U" for byte in value)


@pytest.fixture(scope="module")
def durable_sink_driver(tmp_path_factory: pytest.TempPathFactory) -> Path:
    compiler = shutil.which("c++")
    if compiler is None:
        pytest.skip("a C++20 compiler is required")
    roots = {name: _root(f"durable-sink-{name}") for name in (
        "secret", "seed", "panel", "candidate", "control", "engine",
        "ruleset", "catalog", "candidate-deck", "control-deck", "manifest",
        "site", "object", "trace-manifest", "engine-state",
    )}
    source_text = f'''#define V631302_DURABLE_TEST_HOOKS
#include "V631302DurableTraceSink.h"
#include "V631302EngineSession.h"

#include <atomic>
#include <iomanip>
#include <iostream>
#include <string>
#include <thread>

template <typename Range> void hex(const Range& values) {{
  for (const auto value : values) {{
    std::cout << std::hex << std::setfill('0') << std::setw(2)
              << static_cast<unsigned int>(value);
  }}
}}

v631302::PublicRunDescriptor descriptor() {{
  v631302::PublicRunDescriptor value{{}};
  value.seed_commitment_root = v631302::Root{{{_initializer(roots["seed"])}}};
  value.panel_schedule_root = v631302::Root{{{_initializer(roots["panel"])}}};
  value.common_seed_id = 0xfedcba98U;
  value.candidate_archive_sha256 = v631302::Root{{{_initializer(roots["candidate"])}}};
  value.control_archive_sha256 = v631302::Root{{{_initializer(roots["control"])}}};
  value.candidate_seat = 1U;
  value.engine_binary_sha256 = v631302::Root{{{_initializer(roots["engine"])}}};
  value.ruleset_sha256 = v631302::Root{{{_initializer(roots["ruleset"])}}};
  value.card_catalog_sha256 = v631302::Root{{{_initializer(roots["catalog"])}}};
  value.candidate_deck_root = v631302::Root{{{_initializer(roots["candidate-deck"])}}};
  value.control_deck_root = v631302::Root{{{_initializer(roots["control-deck"])}}};
  value.run_manifest_root = v631302::Root{{{_initializer(roots["manifest"])}}};
  return value;
}}

int main(int argc, char** argv) {{
  static_assert(v631302::kAtomicTransactionSinkImplemented);
  static_assert(v631302::kEngineSessionTransactionSinkWiringImplemented);
  static_assert(v631302::durable::kDurableTraceSinkImplemented);
  static_assert(v631302::durable::kDurableTraceSinkOwnerThreadEnforced);
  static_assert(!v631302::durable::kDurableTraceSinkResumeImplemented);
  static_assert(!v631302::durable::kDurableTraceSinkEngineIntegrated);
  static_assert(!v631302::durable::kDurableTraceSinkCampaignAuthority);
  if (argc != 3) return 64;
  const std::string command = argv[1];
  try {{
    v631302::durable::DurableJournal journal(argv[2]);
    if (command == "inspect") {{
      std::cout << "inspect " << journal.committed_offset() << " "
                << journal.committed_transaction_sequence() << "\\n";
      return 0;
    }}
    v631302::durable::DurableTraceSink sink(journal);
    if (command == "attach") return 65;
    if (command == "cross-thread") {{
      std::atomic<bool> rejected{{false}};
      std::thread crossed([&]() {{
        try {{
          sink.commit(
            v631302::Bytes{{0x01U}}, 0U, 1U,
            v631302::Root{{}}, v631302::Root{{}}
          );
        }} catch (const v631302::durable::DurableTraceSinkError&) {{
          rejected.store(true, std::memory_order_relaxed);
        }}
      }});
      crossed.join();
      std::cout << "cross-thread " << rejected.load() << " "
                << journal.committed_offset() << "\\n";
      return 0;
    }}
    v631302::PrivateSeedCapability capability(
      v631302::Root{{{_initializer(roots["secret"])}}}
    );
    v631302::EngineSession session(descriptor(), capability, &sink);
    const auto stream = session.bind_stream(
      v631302::Root{{{_initializer(roots["site"])}}},
      v631302::Root{{{_initializer(roots["object"])}}},
      41U,
      7U
    );
    if (command == "fail") {{
      const auto bytes_before = session.trace_bytes().size();
      journal.test_fail_write_call(v631302::durable::IoTarget::Trace, 2U);
      try {{
        (void)session.bounded(stream, 1U);
        return 66;
      }} catch (const v631302::durable::DurableJournalError&) {{}}
      std::cout << "fail " << session.event_count() << " "
                << (session.trace_bytes().size() == bytes_before) << " "
                << sink.committed_transaction_count() << " "
                << sink.committed_event_count() << " "
                << sink.committed_offset() << "\\n";
      return 0;
    }}
    if (command != "clean") return 64;
    const auto bounded = session.bounded(stream, 0x8000000000000001ULL);
    (void)session.raw_draw(stream);
    session.close(
      v631302::Root{{{_initializer(roots["trace-manifest"])}}},
      v631302::Root{{{_initializer(roots["engine-state"])}}}
    );
    std::cout << "clean ";
    hex(session.run_binding_root());
    std::cout << " ";
    hex(session.trace_root());
    std::cout << std::dec << " " << session.event_count() << " "
              << sink.committed_transaction_count() << " "
              << sink.committed_event_count() << " "
              << bounded.raw_draw_count << " "
              << sink.committed_offset() << "\\n";
    return 0;
  }} catch (const v631302::durable::DurableTraceSinkError& error) {{
    std::cout << "sink-error " << error.code() << "\\n";
    return 2;
  }} catch (const v631302::durable::DurableJournalError& error) {{
    std::cout << "journal-error " << error.code() << "\\n";
    return 3;
  }}
}}'''
    build_dir = tmp_path_factory.mktemp("native-631302-durable-sink")
    source = build_dir / "driver.cpp"
    executable = build_dir / "driver"
    source.write_text(source_text, encoding="ascii")
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


def _run(driver: Path, command: str, root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(driver), command, str(root)],
        text=True,
        capture_output=True,
    )


def test_durable_sink_persists_exact_trace_by_atomic_operation(
    durable_sink_driver: Path, tmp_path: Path
) -> None:
    store = tmp_path / "clean"
    store.mkdir()
    result = _run(durable_sink_driver, "clean", store)
    assert result.returncode == 0, result.stderr
    fields = result.stdout.strip().split()
    assert fields[0] == "clean"
    session_id = bytes.fromhex(fields[1])
    trace_root = bytes.fromhex(fields[2])
    event_count = int(fields[3])
    transaction_count = int(fields[4])
    sink_event_count = int(fields[5])
    bounded_draw_count = int(fields[6])
    durable_offset = int(fields[7])

    trace = (store / "trace.cbor").read_bytes()
    verified = verify_trace_bytes(
        trace,
        expected_session_id=session_id,
        expected_run_binding_root=session_id,
    )
    assert verified.closed is True
    assert verified.event_count == event_count == sink_event_count
    assert verified.trace_root == trace_root
    assert transaction_count == 4
    assert event_count == bounded_draw_count + 4
    assert event_count > transaction_count
    assert durable_offset == len(trace)


def test_durable_sink_failure_leaves_emitter_unchanged_and_recovers_prefix(
    durable_sink_driver: Path, tmp_path: Path
) -> None:
    store = tmp_path / "failure"
    store.mkdir()
    failed = _run(durable_sink_driver, "fail", store)
    assert failed.returncode == 0, failed.stderr
    fields = failed.stdout.strip().split()
    assert fields[:5] == ["fail", "1", "1", "1", "1"]
    committed_offset = int(fields[5])

    recovered = _run(durable_sink_driver, "inspect", store)
    assert recovered.returncode == 0, recovered.stderr
    assert recovered.stdout == f"inspect {committed_offset} 1\n"
    events = decode_trace_events((store / "trace.cbor").read_bytes())
    assert len(events) == 1
    assert events[0].global_sequence == 0


def test_durable_sink_rejects_nonempty_session_attachment(
    durable_sink_driver: Path, tmp_path: Path
) -> None:
    store = tmp_path / "nonempty"
    store.mkdir()
    assert _run(durable_sink_driver, "clean", store).returncode == 0
    rejected = _run(durable_sink_driver, "attach", store)
    assert rejected.returncode == 2
    assert "RNG_DURABLE_SINK_NONEMPTY_SESSION_UNSUPPORTED" in rejected.stdout


def test_durable_sink_rejects_cross_thread_commit(
    durable_sink_driver: Path, tmp_path: Path
) -> None:
    store = tmp_path / "cross-thread"
    store.mkdir()
    result = _run(durable_sink_driver, "cross-thread", store)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "cross-thread 1 0\n"
    assert (store / "trace.cbor").read_bytes() == b""
