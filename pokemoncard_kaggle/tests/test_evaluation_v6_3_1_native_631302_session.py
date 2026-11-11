from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import shutil
import subprocess

import pytest

from evaluation_v6_3_1.unified_rng_events import verify_trace_bytes
from evaluation_v6_3_1.unified_rng_protocol import (
    PublicReport,
    build_run_binding,
    canonical_cbor_encode,
    derive_raw_value,
    derive_schedule_seed,
    derive_stream_key,
    run_binding_root,
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
    result = subprocess.run(
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
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.fail(result.stderr)
    return executable


def _descriptor_values(common_seed_id: int = 0xFEDCBA98) -> dict[str, bytes | int]:
    return {
        "seed_commitment_root": _root("session-seed-commitment"),
        "panel_schedule_root": _root("session-panel-schedule"),
        "common_seed_id": common_seed_id,
        "candidate_archive_sha256": _root("session-candidate"),
        "control_archive_sha256": _root("session-control"),
        "candidate_seat": 1,
        "engine_binary_sha256": _root("session-engine"),
        "ruleset_sha256": _root("session-ruleset"),
        "card_catalog_sha256": _root("session-catalog"),
        "candidate_deck_root": _root("session-candidate-deck"),
        "control_deck_root": _root("session-control-deck"),
        "run_manifest_root": _root("session-run-manifest"),
    }


def _cpp_descriptor(values: dict[str, bytes | int]) -> str:
    roots = [
        "seed_commitment_root",
        "panel_schedule_root",
        "candidate_archive_sha256",
        "control_archive_sha256",
        "engine_binary_sha256",
        "ruleset_sha256",
        "card_catalog_sha256",
        "candidate_deck_root",
        "control_deck_root",
        "run_manifest_root",
    ]
    assignments = [
        f"descriptor.{name} = v631302::Root{{{_initializer(values[name])}}};"
        for name in roots
    ]
    assignments.extend(
        [
            f"descriptor.common_seed_id = {values['common_seed_id']}U;",
            f"descriptor.candidate_seat = {values['candidate_seat']}U;",
        ]
    )
    return "\n  ".join(assignments)


def test_native_engine_session_matches_python_run_binding_and_trace(tmp_path: Path) -> None:
    values = _descriptor_values()
    secret = _root("session-evaluator-secret")
    site = _root("session-site")
    object_id = _root("session-object")
    manifest = _root("session-trace-manifest")
    state = _root("session-end-state")
    program = f'''#include "V631302EngineSession.h"
#include <iomanip>
#include <iostream>
#include <type_traits>

template <typename Range> void hex(const Range& values) {{
  for (const auto value : values) {{
    std::cout << std::hex << std::setfill('0') << std::setw(2)
              << static_cast<unsigned int>(value);
  }}
}}

int main() {{
  static_assert(v631302::kEngineSessionBindingImplemented);
  static_assert(!v631302::kEngineSessionConnectedToOpenedEngine);
  static_assert(!v631302::kSealedCapabilityDescriptorImplemented);
  static_assert(!v631302::kDurableEngineJournalImplemented);
  static_assert(!v631302::kEngineSessionCampaignAuthority);
  static_assert(!std::is_copy_constructible_v<v631302::PrivateSeedCapability>);
  static_assert(!std::is_move_constructible_v<v631302::PrivateSeedCapability>);
  static_assert(!std::is_copy_constructible_v<v631302::EngineSession>);
  static_assert(!std::is_move_constructible_v<v631302::EngineSession>);
  v631302::PublicRunDescriptor descriptor{{}};
  {_cpp_descriptor(values)}
  v631302::PrivateSeedCapability capability(
    v631302::Root{{{_initializer(secret)}}}
  );
  v631302::EngineSession session(descriptor, capability);
  const auto stream = session.bind_stream(
    v631302::Root{{{_initializer(site)}}},
    v631302::Root{{{_initializer(object_id)}}},
    65535U,
    0xffffffffU
  );
  const auto raw = session.raw_draw(stream);
  session.close(
    v631302::Root{{{_initializer(manifest)}}},
    v631302::Root{{{_initializer(state)}}}
  );
  std::cout << capability.consumed() << " "
            << session.event_count() << " " << raw << "\\n";
  hex(session.match_id()); std::cout << "\\n";
  hex(session.run_binding_root()); std::cout << "\\n";
  hex(session.run_binding_bytes()); std::cout << "\\n";
  hex(session.trace_root()); std::cout << "\\n";
  hex(session.trace_bytes()); std::cout << "\\n";
}}'''
    executable = _compile(tmp_path, "native-session-vector", program)
    first = subprocess.run(
        [str(executable)], check=True, text=True, capture_output=True
    ).stdout.splitlines()
    second = subprocess.run(
        [str(executable)], check=True, text=True, capture_output=True
    ).stdout.splitlines()
    assert first == second

    binding = build_run_binding(
        seed_commitment_root_value=values["seed_commitment_root"],
        panel_schedule_root=values["panel_schedule_root"],
        common_seed_id=values["common_seed_id"],
        candidate_archive_sha256=values["candidate_archive_sha256"],
        control_archive_sha256=values["control_archive_sha256"],
        candidate_seat=values["candidate_seat"],
        engine_binary_sha256=values["engine_binary_sha256"],
        ruleset_sha256=values["ruleset_sha256"],
        card_catalog_sha256=values["card_catalog_sha256"],
        candidate_deck_root=values["candidate_deck_root"],
        control_deck_root=values["control_deck_root"],
        run_manifest_root=values["run_manifest_root"],
    )
    binding_root = run_binding_root(binding)
    schedule = derive_schedule_seed(
        secret,
        values["panel_schedule_root"],
        values["common_seed_id"],
    )
    stream_key = derive_stream_key(schedule, site, object_id, 65535, 0xFFFFFFFF)
    trace = bytes.fromhex(first[5])
    assert first[0] == f"1 3 {derive_raw_value(stream_key, 0)}"
    assert first[1] == binding.match_id.hex()
    assert first[2] == binding_root.hex()
    assert bytes.fromhex(first[3]) == canonical_cbor_encode(binding.as_array())
    assert first[3] == binding.to_bytes().hex()
    verified = verify_trace_bytes(
        trace,
        expected_session_id=binding_root,
        expected_run_binding_root=binding_root,
    )
    assert verified.closed is True
    assert verified.trace_root.hex() == first[4]
    assert secret not in bytes.fromhex(first[3])
    assert secret not in trace
    assert PublicReport().authority == "NO_UPLOAD"


def test_native_engine_session_rejects_invalid_seat_and_capability_reuse(tmp_path: Path) -> None:
    values = _descriptor_values(0xFFFFFFFF)
    program = f'''#include "V631302EngineSession.h"
#include <iostream>
int main() {{
  v631302::PublicRunDescriptor descriptor{{}};
  {_cpp_descriptor(values)}
  descriptor.candidate_seat = 2U;
  v631302::PrivateSeedCapability invalid_capability(
    v631302::Root{{{_initializer(_root('invalid-seat-secret'))}}}
  );
  try {{ v631302::EngineSession invalid(descriptor, invalid_capability); }}
  catch (const std::invalid_argument&) {{ std::cout << "invalid-seat\\n"; }}
  descriptor.candidate_seat = 1U;
  v631302::PrivateSeedCapability capability(
    v631302::Root{{{_initializer(_root('reuse-secret'))}}}
  );
  v631302::EngineSession first(descriptor, capability);
  try {{ v631302::EngineSession second(descriptor, capability); }}
  catch (const std::logic_error&) {{ std::cout << "capability-reused\\n"; }}
  std::cout << first.event_count() << " " << capability.consumed() << "\\n";
}}'''
    executable = _compile(tmp_path, "native-session-guards", program)
    observed = subprocess.run(
        [str(executable)], check=True, text=True, capture_output=True
    ).stdout.splitlines()
    assert observed == ["invalid-seat", "capability-reused", "0 1"]


def test_private_seed_capability_is_single_use_under_thread_race(tmp_path: Path) -> None:
    values = _descriptor_values(0x10203040)
    program = f'''#include "V631302EngineSession.h"
#include <atomic>
#include <iostream>
#include <thread>

int main() {{
  static_assert(v631302::kPrivateSeedCapabilitySynchronized);
  v631302::PublicRunDescriptor descriptor{{}};
  {_cpp_descriptor(values)}
  v631302::PrivateSeedCapability capability(
    v631302::Root{{{_initializer(_root('capability-race-secret'))}}}
  );
  std::atomic<bool> start{{false}};
  std::atomic<unsigned int> successes{{0U}};
  std::atomic<unsigned int> rejected{{0U}};
  auto consume = [&]() {{
    while (!start.load(std::memory_order_acquire)) {{
      std::this_thread::yield();
    }}
    try {{
      v631302::EngineSession session(descriptor, capability);
      successes.fetch_add(1U, std::memory_order_relaxed);
    }} catch (const std::logic_error&) {{
      rejected.fetch_add(1U, std::memory_order_relaxed);
    }}
  }};
  std::thread first(consume);
  std::thread second(consume);
  start.store(true, std::memory_order_release);
  first.join();
  second.join();
  std::cout << successes.load() << " " << rejected.load() << " "
            << capability.consumed() << "\\n";
}}'''
    executable = _compile(tmp_path, "native-capability-race", program)
    observed = subprocess.run(
        [str(executable)], check=True, text=True, capture_output=True
    ).stdout.strip()
    assert observed == "1 1 1"


def test_native_schedule_is_neutral_to_archive_and_seat_metadata(tmp_path: Path) -> None:
    left = _descriptor_values(0x10203040)
    right = dict(left)
    right["candidate_archive_sha256"] = _root("neutrality-other-candidate")
    right["control_archive_sha256"] = _root("neutrality-other-control")
    right["candidate_seat"] = 0
    secret = _root("neutrality-secret")
    site = _root("neutrality-site")
    object_id = _root("neutrality-object")
    program = f'''#include "V631302EngineSession.h"
#include <iostream>
int main() {{
  v631302::PublicRunDescriptor left_descriptor{{}};
  {_cpp_descriptor(left).replace('descriptor.', 'left_descriptor.')}
  v631302::PublicRunDescriptor right_descriptor{{}};
  {_cpp_descriptor(right).replace('descriptor.', 'right_descriptor.')}
  const v631302::Root secret = {{{_initializer(secret)}}};
  v631302::PrivateSeedCapability left_capability(secret);
  v631302::PrivateSeedCapability right_capability(secret);
  v631302::EngineSession left_session(left_descriptor, left_capability);
  v631302::EngineSession right_session(right_descriptor, right_capability);
  const v631302::Root site = {{{_initializer(site)}}};
  const v631302::Root object_id = {{{_initializer(object_id)}}};
  const auto left_stream = left_session.bind_stream(site, object_id, 19U, 7U);
  const auto right_stream = right_session.bind_stream(site, object_id, 19U, 7U);
  const auto left_raw = left_session.raw_draw(left_stream);
  const auto right_raw = right_session.raw_draw(right_stream);
  std::cout << (left_session.run_binding_root() != right_session.run_binding_root())
            << " " << (left_stream != right_stream)
            << " " << (left_raw == right_raw) << "\\n";
}}'''
    executable = _compile(tmp_path, "native-session-neutrality", program)
    observed = subprocess.run(
        [str(executable)], check=True, text=True, capture_output=True
    ).stdout.strip()
    assert observed == "1 1 1"
