# Test-only bootstrap for the native Amendment-4 substrate.  This is not the
# pending canonical worker and cannot establish a profile, artifact, or authority.
import sys


def head(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def enc(value):
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode("utf-8")
        return head(3, len(data)) + data
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(enc(item) for item in value)
    raise ValueError("unsupported test-only CBOR value")


def dec(data, offset=0):
    start = offset
    if offset >= len(data):
        raise ValueError("truncated")
    first = data[offset]
    offset += 1
    major = first >> 5
    additional = first & 31
    if major not in (0, 2, 3, 4) or additional >= 28:
        raise ValueError("kind")
    if additional < 24:
        value = additional
    else:
        width = 1 << (additional - 24)
        if offset + width > len(data):
            raise ValueError("length")
        value = int.from_bytes(data[offset:offset + width], "big")
        offset += width
        minimum = {1: 24, 2: 1 << 8, 4: 1 << 16, 8: 1 << 32}[width]
        if value < minimum:
            raise ValueError("noncanonical")
    if major == 0:
        result = value
    elif major == 2:
        if offset + value > len(data):
            raise ValueError("bytes")
        result = data[offset:offset + value]
        offset += value
    elif major == 3:
        if offset + value > len(data):
            raise ValueError("text")
        result = data[offset:offset + value].decode("utf-8")
        offset += value
    else:
        result = []
        for _ in range(value):
            item, offset = dec(data, offset)
            result.append(item)
    raw = data[start:offset]
    if enc(result) != raw:
        raise ValueError("noncanonical")
    return result, offset


def fail():
    raise SystemExit(80)


if sys.argv != ["-c", "V631302_DIAGNOSTIC_WORKER_V1", "worker/v631302_diagnostic_worker_v1.py"]:
    fail()
if (sys.flags.isolated != 1 or sys.flags.no_site != 1 or sys.flags.ignore_environment != 1 or
        sys.flags.no_user_site != 1 or sys.flags.safe_path != 1 or
        sys.flags.dont_write_bytecode != 1 or sys.flags.utf8_mode != 1 or sys.flags.optimize != 0):
    fail()
frame = sys.stdin.buffer.read()
if len(frame) < 16 or frame[:8] != b"V631DI01":
    fail()
length = int.from_bytes(frame[8:16], "big")
if length != len(frame) - 16:
    fail()
try:
    payload, end = dec(frame[16:])
    if end != length or not isinstance(payload, list) or len(payload) != 5:
        fail()
    if payload[0:2] != [631302, 1]:
        fail()
    profile, byte_rows, raw = payload[2:]
    # The frozen worker owns all profile semantics and reserved-global checks.
    # This test fixture only echoes a syntactically complete returned profile so
    # the native constructor and post-worker exact-equality boundary can be
    # tested without editing the canonical worker module.
    if not isinstance(raw, bytes) or not isinstance(profile, list) or len(profile) != 8:
        fail()
except (UnicodeDecodeError, ValueError, TypeError, IndexError):
    fail()

# The raw value is intentionally never decoded or used as profile input.  This
# test-only branch simulates an untrusted entry result changing one profile byte;
# native code must reject it and must never repair it.
if raw == b"\xf6":
    profile = list(profile)
    profile[0] = bytes([profile[0][0] ^ 1]) + profile[0][1:]
artifact = enc([631302, 1, profile, [], [], [], [], [], []])
sys.stdout.buffer.write(b"V631DO01" + len(artifact).to_bytes(8, "big") + artifact)
