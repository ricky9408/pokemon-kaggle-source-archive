from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import shutil
import subprocess

import pytest

from evaluation_v6_3_1.unified_rng_events import (
    BOUNDED_SAMPLE,
    RAW_DRAW,
    SESSION_CLOSE,
    STREAM_BIND,
    UnifiedRngEventError,
    build_event,
    bounded_sample_payload,
    decode_trace_events,
    raw_draw_payload,
    session_close_payload,
    stream_bind_payload,
    verify_trace_bytes,
)
from evaluation_v6_3_1.unified_rng_protocol import (
    ZERO_ID,
    canonical_cbor_encode,
    derive_raw_value,
    derive_stream_id,
    derive_stream_key,
)


ROOT = Path(__file__).resolve().parents[1]
HEADER_DIR = ROOT / "evaluation_v6_3_1" / "cpp"


def _root(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def _initializer(value: bytes) -> str:
    return ", ".join(f"0x{byte:02x}U" for byte in value)


def _compile(tmp_path: Path, name: str, source_text: str) -> Path:
    compiler = shutil.which("c++")
    if compiler is None:
        pytest.skip("a C++20 compiler is required")
    source = tmp_path / f"{name}.cpp"
    executable = tmp_path / name
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


def _run(executable: Path) -> list[str]:
    return subprocess.run(
        [str(executable)],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.splitlines()


def _expected_trace(
    *,
    session: bytes,
    schedule_seed: bytes,
    site_a: bytes,
    object_a: bytes,
    site_b: bytes,
    object_b: bytes,
    seed_root: bytes,
    manifest_root: bytes,
    state_root: bytes,
) -> tuple[bytes, tuple[object, ...], bytes, bytes, list[int]]:
    stream_a = derive_stream_id(session, site_a, object_a, 17, 3)
    stream_b = derive_stream_id(session, site_b, object_b, 29, 0)
    key_a = derive_stream_key(schedule_seed, site_a, object_a, 17, 3)
    key_b = derive_stream_key(schedule_seed, site_b, object_b, 29, 0)
    events = []
    global_hash = ZERO_ID
    stream_hashes: dict[bytes, bytes] = {}

    def append(event_type: int, stream_id: bytes, payload: list[object]) -> None:
        nonlocal global_hash
        previous_stream = ZERO_ID if event_type in (STREAM_BIND, SESSION_CLOSE) else stream_hashes[stream_id]
        event = build_event(
            event_type,
            session,
            len(events),
            global_hash,
            stream_id,
            previous_stream,
            ZERO_ID,
            ZERO_ID,
            payload,
        )
        events.append(event)
        global_hash = event.event_hash()
        if event_type != SESSION_CLOSE:
            stream_hashes[stream_id] = global_hash

    append(STREAM_BIND, stream_a, stream_bind_payload(site_a, object_a, 17, 3))
    append(STREAM_BIND, stream_b, stream_bind_payload(site_b, object_b, 29, 0))

    raw_a_0 = derive_raw_value(key_a, 0)
    append(RAW_DRAW, stream_a, raw_draw_payload(ZERO_ID, 0, raw_a_0))

    upper = (1 << 63) + 1
    limit = (1 << 64) - ((1 << 64) % upper)
    raw_b: list[int] = []
    while True:
        value = derive_raw_value(key_b, len(raw_b))
        raw_b.append(value)
        append(RAW_DRAW, stream_b, raw_draw_payload(ZERO_ID, len(raw_b) - 1, value))
        if value < limit:
            break
    append(
        BOUNDED_SAMPLE,
        stream_b,
        bounded_sample_payload(
            ZERO_ID,
            upper,
            0,
            len(raw_b),
            len(raw_b) - 1,
            raw_b[-1] % upper,
        ),
    )

    raw_a_1 = derive_raw_value(key_a, 1)
    append(RAW_DRAW, stream_a, raw_draw_payload(ZERO_ID, 1, raw_a_1))
    summaries = sorted(
        [
            [stream_a, 2, 0, 0, stream_hashes[stream_a]],
            [stream_b, len(raw_b), 0, 0, stream_hashes[stream_b]],
        ],
        key=lambda row: row[0],
    )
    append(
        SESSION_CLOSE,
        ZERO_ID,
        session_close_payload(
            seed_root,
            session,
            len(events) + 1,
            summaries,
            ZERO_ID,
            manifest_root,
            state_root,
            0,
            0,
        ),
    )
    trace = b"".join(event.to_bytes() for event in events)
    return trace, tuple(events), stream_a, stream_b, raw_b


def test_native_631302_trace_matches_python_and_full_verifier(tmp_path: Path) -> None:
    session = _root("session")
    schedule_seed = _root("schedule")
    site_a, object_a = _root("site-a"), _root("object-a")
    site_b, object_b = _root("site-b"), _root("object-b")
    seed_root = _root("seed-root")
    manifest_root = _root("manifest-root")
    state_root = _root("state-root")
    upper = (1 << 63) + 1

    program = f'''#include "V631302TraceEmitter.h"
#include <iomanip>
#include <iostream>

template <typename Range> void hex(const Range& values) {{
  for (const auto value : values) {{
    std::cout << std::hex << std::setfill('0') << std::setw(2)
              << static_cast<unsigned int>(value);
  }}
}}

int main() {{
  static_assert(!v631302::kEngineIntegrated);
  static_assert(!v631302::kDurablePersistenceImplemented);
  static_assert(!v631302::kCampaignAuthority);
  const v631302::Root session = {{{_initializer(session)}}};
  const v631302::Root schedule = {{{_initializer(schedule_seed)}}};
  const v631302::Root site_a = {{{_initializer(site_a)}}};
  const v631302::Root object_a = {{{_initializer(object_a)}}};
  const v631302::Root site_b = {{{_initializer(site_b)}}};
  const v631302::Root object_b = {{{_initializer(object_b)}}};
  v631302::TraceEmitter emitter(session, schedule);
  const auto stream_a = emitter.bind_stream(site_a, object_a, 17U, 3U);
  const auto stream_b = emitter.bind_stream(site_b, object_b, 29U, 0U);
  const auto raw_a_0 = emitter.raw_draw(stream_a);
  const auto bounded = emitter.bounded(stream_b, {upper}ULL);
  const auto raw_a_1 = emitter.raw_draw(stream_a);
  emitter.close(
    v631302::Root{{{_initializer(seed_root)}}},
    session,
    v631302::Root{{{_initializer(manifest_root)}}},
    v631302::Root{{{_initializer(state_root)}}}
  );
  std::cout << v631302::kEngineIntegrated << " "
            << v631302::kDurablePersistenceImplemented << " "
            << v631302::kCampaignAuthority << "\\n";
  hex(stream_a); std::cout << "\\n";
  hex(stream_b); std::cout << "\\n";
  std::cout << std::dec << raw_a_0 << "\\n";
  std::cout << bounded.result << " " << bounded.first_raw_counter << " "
            << bounded.raw_draw_count << " " << bounded.accepted_raw_counter << "\\n";
  std::cout << raw_a_1 << "\\n";
  std::cout << emitter.event_count() << "\\n";
  hex(emitter.trace_root()); std::cout << "\\n";
  hex(emitter.trace_bytes()); std::cout << "\\n";
}}'''
    executable = _compile(tmp_path, "native-vector", program)
    first = _run(executable)
    second = _run(executable)
    assert first == second

    expected_trace, expected_events, stream_a, stream_b, raw_b = _expected_trace(
        session=session,
        schedule_seed=schedule_seed,
        site_a=site_a,
        object_a=object_a,
        site_b=site_b,
        object_b=object_b,
        seed_root=seed_root,
        manifest_root=manifest_root,
        state_root=state_root,
    )
    trace = bytes.fromhex(first[8])
    assert first[0] == "0 0 0"
    assert first[1] == stream_a.hex()
    assert first[2] == stream_b.hex()
    assert first[3] == str(derive_raw_value(derive_stream_key(schedule_seed, site_a, object_a, 17, 3), 0))
    assert first[4] == f"{raw_b[-1] % upper} 0 {len(raw_b)} {len(raw_b) - 1}"
    assert len(raw_b) == 4
    assert first[5] == str(derive_raw_value(derive_stream_key(schedule_seed, site_a, object_a, 17, 3), 1))
    assert first[6] == str(len(expected_events))
    assert first[7] == expected_events[-1].event_hash().hex()
    assert trace == expected_trace

    decoded = decode_trace_events(trace)
    assert decoded == expected_events
    assert all(len(event.as_array()) == 10 and event.as_array()[0] == 631302 for event in decoded)
    verified = verify_trace_bytes(
        trace,
        expected_session_id=session,
        expected_run_binding_root=session,
    )
    assert verified.closed is True
    assert verified.event_count == len(expected_events)
    assert verified.trace_root.hex() == first[7]

    with pytest.raises(UnifiedRngEventError) as caught:
        verify_trace_bytes(trace[:-1])
    assert caught.value.code == "RNG_TRACE_TRAILING_PARTIAL_EVENT"
    with pytest.raises(UnifiedRngEventError) as caught:
        verify_trace_bytes(trace + b"\x00")
    assert caught.value.code == "RNG_CANONICAL_CBOR_MISMATCH"


def test_native_631302_append_failures_are_atomic(tmp_path: Path) -> None:
    session = _root("atomic-session")
    schedule_seed = _root("atomic-schedule")
    site = _root("atomic-site")
    object_id = _root("atomic-object")
    seed_root = _root("atomic-seed")
    manifest_root = _root("atomic-manifest")
    state_root = _root("atomic-state")
    key = derive_stream_key(schedule_seed, site, object_id, 7, 11)

    program = f'''#define V631302_TRACE_TEST_HOOKS
#include "V631302TraceEmitter.h"
#include <iomanip>
#include <iostream>

template <typename Range> void hex(const Range& values) {{
  for (const auto value : values) {{
    std::cout << std::hex << std::setfill('0') << std::setw(2)
              << static_cast<unsigned int>(value);
  }}
}}

int main() {{
  const v631302::Root session = {{{_initializer(session)}}};
  v631302::TraceEmitter emitter(
    session,
    v631302::Root{{{_initializer(schedule_seed)}}}
  );
  const v631302::Root site = {{{_initializer(site)}}};
  const v631302::Root object_id = {{{_initializer(object_id)}}};
  emitter.test_fail_next_append();
  try {{ (void)emitter.bind_stream(site, object_id, 7U, 11U); }}
  catch (const std::bad_alloc&) {{}}
  std::cout << "bind-fail " << emitter.event_count() << " "
            << emitter.trace_bytes().size() << "\\n";

  const auto stream = emitter.bind_stream(site, object_id, 7U, 11U);
  const auto bind_size = emitter.trace_bytes().size();
  const auto bind_root = emitter.trace_root();
  emitter.test_fail_next_append();
  try {{ (void)emitter.raw_draw(stream); }} catch (const std::bad_alloc&) {{}}
  std::cout << "raw-fail " << emitter.event_count() << " "
            << (emitter.trace_bytes().size() == bind_size) << " "
            << (emitter.trace_root() == bind_root) << "\\n";

  try {{ (void)emitter.bind_stream(site, object_id, 7U, 11U); }}
  catch (const std::logic_error&) {{
    std::cout << "duplicate " << emitter.event_count() << "\\n";
  }}

  const auto first = emitter.raw_draw(stream);
  const auto before_size = emitter.trace_bytes().size();
  const auto before_root = emitter.trace_root();
  const auto before_count = emitter.event_count();
  emitter.test_fail_append_at_sequence(before_count + 1U);
  try {{ (void)emitter.bounded(stream, 1U); }} catch (const std::bad_alloc&) {{}}
  std::cout << "bounded-fail " << emitter.event_count() << " "
            << (emitter.trace_bytes().size() == before_size) << " "
            << (emitter.trace_root() == before_root) << "\\n";
  const auto second = emitter.raw_draw(stream);
  std::cout << first << " " << second << "\\n";
  emitter.close(
    v631302::Root{{{_initializer(seed_root)}}},
    session,
    v631302::Root{{{_initializer(manifest_root)}}},
    v631302::Root{{{_initializer(state_root)}}}
  );
  hex(emitter.trace_bytes()); std::cout << "\\n";
}}'''
    executable = _compile(tmp_path, "native-atomic", program)
    observed = _run(executable)
    assert observed[:4] == [
        "bind-fail 0 0",
        "raw-fail 1 1 1",
        "duplicate 1",
        "bounded-fail 2 1 1",
    ]
    assert observed[4] == f"{derive_raw_value(key, 0)} {derive_raw_value(key, 1)}"
    trace = bytes.fromhex(observed[5])
    verified = verify_trace_bytes(
        trace,
        expected_session_id=session,
        expected_run_binding_root=session,
    )
    assert verified.closed is True
    assert [event.event_type for event in verified.events] == [
        STREAM_BIND,
        RAW_DRAW,
        RAW_DRAW,
        SESSION_CLOSE,
    ]


def test_native_631302_sink_commits_one_complete_bounded_operation(tmp_path: Path) -> None:
    session = _root("sink-session")
    schedule_seed = _root("sink-schedule")
    site = _root("sink-site")
    object_id = _root("sink-object")
    seed_root = _root("sink-seed")
    manifest_root = _root("sink-manifest")
    state_root = _root("sink-state")
    upper = (1 << 63) + 1
    key = derive_stream_key(schedule_seed, site, object_id, 31, 9)
    raw_values: list[int] = []
    limit = (1 << 64) - ((1 << 64) % upper)
    while True:
        value = derive_raw_value(key, len(raw_values))
        raw_values.append(value)
        if value < limit:
            break

    program = f'''#include "V631302TraceEmitter.h"
#include <iostream>
#include <stdexcept>
#include <vector>

class Sink final : public v631302::TraceTransactionSink {{
public:
  void commit(
    const v631302::Bytes& bytes,
    std::uint64_t first,
    std::uint64_t count,
    const v631302::Root& previous,
    const v631302::Root& final
  ) override {{
    if (fail_next) {{
      fail_next = false;
      throw std::runtime_error("injected sink failure");
    }}
    transactions.push_back(bytes);
    first_sequences.push_back(first);
    event_counts.push_back(count);
    previous_hashes.push_back(previous);
    final_hashes.push_back(final);
  }}

  bool fail_next = false;
  std::vector<v631302::Bytes> transactions;
  std::vector<std::uint64_t> first_sequences;
  std::vector<std::uint64_t> event_counts;
  std::vector<v631302::Root> previous_hashes;
  std::vector<v631302::Root> final_hashes;
}};

int main() {{
  static_assert(v631302::kAtomicTransactionSinkImplemented);
  static_assert(!v631302::kDurablePersistenceImplemented);
  Sink sink;
  const v631302::Root session = {{{_initializer(session)}}};
  v631302::TraceEmitter emitter(
    session,
    v631302::Root{{{_initializer(schedule_seed)}}},
    &sink
  );
  const auto stream = emitter.bind_stream(
    v631302::Root{{{_initializer(site)}}},
    v631302::Root{{{_initializer(object_id)}}},
    31U,
    9U
  );
  const auto bind_size = emitter.trace_bytes().size();
  const auto bind_root = emitter.trace_root();
  const auto bounded = emitter.bounded(stream, {upper}ULL);
  const v631302::Bytes bounded_delta(
    emitter.trace_bytes().begin() + static_cast<std::ptrdiff_t>(bind_size),
    emitter.trace_bytes().end()
  );
  std::cout << sink.transactions.size() << " "
            << sink.first_sequences[1] << " " << sink.event_counts[1] << " "
            << (sink.transactions[1] == bounded_delta) << " "
            << (sink.previous_hashes[1] == bind_root) << " "
            << (sink.final_hashes[1] == emitter.trace_root()) << "\\n";
  std::cout << bounded.raw_draw_count << " " << bounded.accepted_raw_counter << "\\n";

  const auto trace_before = emitter.trace_bytes();
  const auto root_before = emitter.trace_root();
  const auto count_before = emitter.event_count();
  const auto calls_before = sink.transactions.size();
  sink.fail_next = true;
  try {{ (void)emitter.bounded(stream, 1U); }}
  catch (const std::runtime_error&) {{}}
  std::cout << (emitter.trace_bytes() == trace_before) << " "
            << (emitter.trace_root() == root_before) << " "
            << (emitter.event_count() == count_before) << " "
            << (sink.transactions.size() == calls_before) << "\\n";

  std::cout << emitter.raw_draw(stream) << "\\n";
  emitter.close(
    v631302::Root{{{_initializer(seed_root)}}},
    session,
    v631302::Root{{{_initializer(manifest_root)}}},
    v631302::Root{{{_initializer(state_root)}}}
  );
  std::cout << emitter.event_count() << " " << sink.transactions.size() << "\\n";
}}'''
    executable = _compile(tmp_path, "native-transaction-sink", program)
    observed = _run(executable)
    assert observed[0] == f"2 1 {len(raw_values) + 1} 1 1 1"
    assert observed[1] == f"{len(raw_values)} {len(raw_values) - 1}"
    assert observed[2] == "1 1 1 1"
    assert observed[3] == str(derive_raw_value(key, len(raw_values)))
    assert observed[4] == f"{len(raw_values) + 4} 4"


def test_native_631302_cbor_width_and_sequence_boundaries(tmp_path: Path) -> None:
    session = _root("width-session")
    schedule_seed = _root("width-schedule")
    site = _root("width-site")
    object_id = _root("width-object")
    seed_root = _root("width-seed")
    manifest_root = _root("width-manifest")
    state_root = _root("width-state")
    values = (0, 23, 24, 255, 256, 65535, 65536, (1 << 32) - 1, 1 << 32)

    program = f'''#include "V631302TraceEmitter.h"
#include <iomanip>
#include <iostream>

template <typename Range> void hex(const Range& values) {{
  for (const auto value : values) {{
    std::cout << std::hex << std::setfill('0') << std::setw(2)
              << static_cast<unsigned int>(value);
  }}
}}

int main() {{
  const std::uint64_t values[] = {{
    0ULL, 23ULL, 24ULL, 255ULL, 256ULL, 65535ULL, 65536ULL,
    4294967295ULL, 4294967296ULL
  }};
  for (const auto value : values) {{
    v631302::Bytes encoded;
    v631302::detail::cbor_uint(encoded, value);
    hex(encoded); std::cout << "\\n";
  }}
  const v631302::Root session = {{{_initializer(session)}}};
  v631302::TraceEmitter emitter(
    session,
    v631302::Root{{{_initializer(schedule_seed)}}}
  );
  const auto stream = emitter.bind_stream(
    v631302::Root{{{_initializer(site)}}},
    v631302::Root{{{_initializer(object_id)}}},
    65535U,
    65536U
  );
  for (std::uint64_t index = 0; index < 260U; ++index) {{
    (void)emitter.raw_draw(stream);
  }}
  emitter.close(
    v631302::Root{{{_initializer(seed_root)}}},
    session,
    v631302::Root{{{_initializer(manifest_root)}}},
    v631302::Root{{{_initializer(state_root)}}}
  );
  hex(emitter.trace_bytes()); std::cout << "\\n";
}}'''
    executable = _compile(tmp_path, "native-widths", program)
    observed = _run(executable)
    assert observed[: len(values)] == [canonical_cbor_encode(value).hex() for value in values]

    trace = bytes.fromhex(observed[-1])
    stream = derive_stream_id(session, site, object_id, 65535, 65536)
    key = derive_stream_key(schedule_seed, site, object_id, 65535, 65536)
    verified = verify_trace_bytes(
        trace,
        expected_session_id=session,
        expected_run_binding_root=session,
    )
    assert verified.event_count == 262
    assert verified.events[0].event_type == STREAM_BIND
    assert verified.events[-1].event_type == SESSION_CLOSE
    for sequence in (23, 24, 255, 256):
        event = verified.events[sequence]
        assert event.global_sequence == sequence
        assert event.to_bytes() in trace
    raw_events = verified.events[1:261]
    assert all(event.event_type == RAW_DRAW and event.stream_id == stream for event in raw_events)
    assert [event.payload[1] for event in raw_events] == list(range(260))
    assert [event.payload[2] for event in raw_events] == [
        derive_raw_value(key, counter) for counter in range(260)
    ]


def test_native_631302_registry_thread_ownership_and_bounded_cleanup(tmp_path: Path) -> None:
    session = _root("registry-session")
    schedule_seed = _root("registry-schedule")
    site = _root("registry-site")
    object_id = _root("registry-object")
    seed_root = _root("registry-seed")
    manifest_root = _root("registry-manifest")
    state_root = _root("registry-state")

    program = f'''#define V631302_TRACE_TEST_HOOKS
#include "V631302TraceEmitter.h"
#include <iostream>
#include <thread>

int main() {{
  static_assert(v631302::kOwnerThreadEnforcementImplemented);
  static_assert(!v631302::kProcessWideRegistryImplemented);
  static_assert(v631302::kTranslationUnitRegistryImplemented);
  static_assert(!v631302::kDerivedKeyZeroizationImplemented);
  static_assert(v631302::kSensitiveHmacBufferWipeImplemented);
  const v631302::Root session = {{{_initializer(session)}}};
  const v631302::Root schedule = {{{_initializer(schedule_seed)}}};
  bool duplicate_session_rejected = false;
  bool crossed_thread_rejected = false;
  bool draw_committed = false;
  bool member_keys_erased = false;
  bool live_stream_registered = false;
  {{
    v631302::TraceEmitter emitter(session, schedule);
    try {{
      v631302::TraceEmitter duplicate(session, schedule);
    }} catch (const std::logic_error&) {{
      duplicate_session_rejected = true;
    }}
    const auto stream = emitter.bind_stream(
      v631302::Root{{{_initializer(site)}}},
      v631302::Root{{{_initializer(object_id)}}},
      41U,
      2U
    );
    std::thread crossed([&]() {{
      try {{
        (void)emitter.raw_draw(stream);
      }} catch (const std::logic_error&) {{
        crossed_thread_rejected = true;
      }}
    }});
    crossed.join();
    (void)emitter.raw_draw(stream);
    draw_committed = emitter.event_count() == 2U;
    emitter.close(
      v631302::Root{{{_initializer(seed_root)}}},
      session,
      v631302::Root{{{_initializer(manifest_root)}}},
      v631302::Root{{{_initializer(state_root)}}}
    );
    member_keys_erased = emitter.test_derived_keys_are_zero();
    live_stream_registered =
      v631302::registry_detail::test_stream_count_for_session(session) == 1U;
  }}
  const bool stream_registry_cleaned =
    v631302::registry_detail::test_stream_count_for_session(session) == 0U;
  const bool bounded_tombstone_retained =
    v631302::registry_detail::test_session_tombstone_count() == 1U;
  std::cout << duplicate_session_rejected << " "
            << crossed_thread_rejected << " "
            << draw_committed << " "
            << member_keys_erased << " "
            << live_stream_registered << " "
            << stream_registry_cleaned << " "
            << bounded_tombstone_retained << "\\n";
}}'''
    executable = _compile(tmp_path, "native-registry-thread-zero", program)
    assert _run(executable) == ["1 1 1 1 1 1 1"]


def test_native_631302_sink_reentry_is_rejected_without_deadlock(tmp_path: Path) -> None:
    session = _root("sink-reentry-session")
    schedule_seed = _root("sink-reentry-schedule")
    site = _root("sink-reentry-site")
    object_id = _root("sink-reentry-object")
    nested_site = _root("sink-reentry-nested-site")

    program = f'''#include "V631302TraceEmitter.h"
#include <iostream>

class ReenteringSink final : public v631302::TraceTransactionSink {{
public:
  v631302::TraceEmitter* emitter = nullptr;
  bool rejected = false;

  void commit(
    const v631302::Bytes&,
    std::uint64_t,
    std::uint64_t,
    const v631302::Root&,
    const v631302::Root&
  ) override {{
    try {{
      (void)emitter->bind_stream(
        v631302::Root{{{_initializer(nested_site)}}},
        v631302::Root{{{_initializer(object_id)}}},
        7U,
        1U
      );
    }} catch (const std::logic_error&) {{
      rejected = true;
    }}
  }}
}};

int main() {{
  static_assert(v631302::kSinkCallbackReentryRejected);
  ReenteringSink sink;
  v631302::TraceEmitter emitter(
    v631302::Root{{{_initializer(session)}}},
    v631302::Root{{{_initializer(schedule_seed)}}},
    &sink
  );
  sink.emitter = &emitter;
  (void)emitter.bind_stream(
    v631302::Root{{{_initializer(site)}}},
    v631302::Root{{{_initializer(object_id)}}},
    6U,
    0U
  );
  std::cout << sink.rejected << " " << emitter.event_count() << "\\n";
}}'''
    executable = _compile(tmp_path, "native-sink-reentry", program)
    observed = subprocess.run(
        [str(executable)],
        check=True,
        text=True,
        capture_output=True,
        timeout=10,
    ).stdout.strip()
    assert observed == "1 1"
