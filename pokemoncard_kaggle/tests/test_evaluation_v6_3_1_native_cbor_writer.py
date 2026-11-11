from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from evaluation_v6_3_1.eir_prebinding import eir_canonical_cbor_encode


ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / "evaluation_v6_3_1/native/state3_extractor/CborWriter.h"
SOURCE = ROOT / "evaluation_v6_3_1/native/state3_extractor/CborWriter.cpp"


def _hex(value: bytes) -> str:
    return value.hex()


def test_native_writer_matches_eir_encoder_in_linux_amd64_docker(tmp_path: Path) -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is required for the Linux/amd64 native writer test")

    harness = tmp_path / "harness.cpp"
    harness.write_text(
        r'''#include "CborWriter.h"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using evaluation_v6_3_1::native::CborWriter;

static std::string hex(const std::vector<CborWriter::Byte>& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (std::uint8_t byte : bytes) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 0x0f]);
    }
    return result;
}

static void emit(std::uint64_t value) {
    CborWriter writer;
    writer.write_uint(value);
    std::cout << hex(writer.bytes()) << '\n';
}

static void emit_nested() {
    CborWriter writer;
    writer.write_array(3);
    writer.write_uint(1);
    writer.write_array(3);
    writer.write_uint(2);
    writer.write_bytes("payload");
    writer.write_text("text");
    writer.write_uint(3);
    std::cout << hex(writer.bytes()) << '\n';
}

static void emit_string_boundaries() {
    CborWriter bytes255;
    bytes255.write_bytes(std::string(255, 'x'));
    std::cout << hex(bytes255.bytes()) << '\n';

    CborWriter bytes256;
    bytes256.write_bytes(std::string(256, 'y'));
    std::cout << hex(bytes256.bytes()) << '\n';

    CborWriter text65535;
    text65535.write_text(std::string(65535, 'z'));
    std::cout << hex(text65535.bytes()) << '\n';
}

static void emit_array_boundaries() {
    for (std::uint64_t length : {23ULL, 24ULL, 255ULL, 256ULL}) {
        CborWriter writer;
        writer.write_array(length);
        for (std::uint64_t index = 0; index < length; ++index) {
            writer.write_uint(0);
        }
        std::cout << hex(writer.bytes()) << '\n';
    }
}

static void emit_utf8() {
    CborWriter writer;
    writer.write_text(std::string("\xc3\xa9\xe6\x97\xa5\xf0\x9f\x94\xa5", 9));
    std::cout << hex(writer.bytes()) << '\n';
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    if (std::string(argv[1]) == "boundaries") {
        for (std::uint64_t value : {0ULL, 23ULL, 24ULL, 255ULL, 256ULL,
                                    65535ULL, 65536ULL, 0xffffffffULL,
                                    0x100000000ULL, 0xffffffffffffffffULL}) {
            emit(value);
        }
        return 0;
    }
    if (std::string(argv[1]) == "vectors") {
        CborWriter empty;
        empty.write_array(0);
        std::cout << hex(empty.bytes()) << '\n';
        emit_nested();
        emit_string_boundaries();
        return 0;
    }
    if (std::string(argv[1]) == "array-boundaries") {
        emit_array_boundaries();
        return 0;
    }
    if (std::string(argv[1]) == "utf8") {
        emit_utf8();
        return 0;
    }
    if (std::string(argv[1]) == "invalid") {
        CborWriter writer;
        try {
            writer.write_text(std::string("\xc0", 1));
        } catch (const std::invalid_argument&) {
            return 0;
        }
        return 1;
    }
    if (std::string(argv[1]) == "stdout") {
        CborWriter writer;
        writer.write_array(3);
        writer.write_uint(7);
        writer.write_bytes(std::string("\x00\xff", 2));
        writer.write_text("ok");
        writer.write_to(std::cout);
        return 0;
    }
    return 3;
}
''',
        encoding="utf-8",
    )
    image = "debian:bookworm-slim"
    command = [
        docker,
        "run",
        "--rm",
        "--platform",
        "linux/amd64",
        "-v",
        f"{ROOT}:/src:ro",
        "-v",
        f"{tmp_path}:/work",
        "-w",
        "/work",
        image,
        "bash",
        "-ceu",
        (
            "apt-get update >/dev/null && "
            "apt-get install -y --no-install-recommends clang-16 >/dev/null && "
            "clang++-16 -std=c++20 -Wall -Wextra -Werror -pedantic "
            "/src/evaluation_v6_3_1/native/state3_extractor/CborWriter.cpp "
            "harness.cpp -I /src/evaluation_v6_3_1/native/state3_extractor -o harness && "
                "./harness boundaries > boundary.out && "
                "./harness boundaries > boundary-again.out && "
                "cmp boundary.out boundary-again.out && "
                "./harness array-boundaries > arrays.out && "
                "./harness utf8 > utf8.out && "
                "./harness invalid && "
            "./harness stdout > binary.out"
        ),
    ]
    subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    boundary = (tmp_path / "boundary.out").read_text(encoding="ascii").splitlines()
    expected_boundary = [
        _hex(eir_canonical_cbor_encode(value))
        for value in [0, 23, 24, 255, 256, 65535, 65536, 0xFFFFFFFF, 0x100000000, 0xFFFFFFFFFFFFFFFF]
    ]
    assert boundary == expected_boundary
    assert (tmp_path / "boundary.out").read_bytes() == (tmp_path / "boundary-again.out").read_bytes()
    array_lengths = [23, 24, 255, 256]
    observed_arrays = (tmp_path / "arrays.out").read_text(encoding="ascii").splitlines()
    expected_arrays = [
        _hex(eir_canonical_cbor_encode([0] * length)) for length in array_lengths
    ]
    assert observed_arrays == expected_arrays
    assert (tmp_path / "utf8.out").read_text(encoding="ascii").strip() == _hex(
        eir_canonical_cbor_encode("é日🔥")
    )
    # Reuse the compiled Linux/amd64 binary in a second container invocation;
    # redirecting inside the container keeps arbitrary bytes off text pipes.
    vector_command = command[:-1] + ["./harness vectors > vectors.out"]
    subprocess.run(vector_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    observed = (tmp_path / "vectors.out").read_text(encoding="ascii").splitlines()
    expected_vectors = [
        _hex(eir_canonical_cbor_encode([])),
        _hex(eir_canonical_cbor_encode([1, [2, b"payload", "text"], 3])),
        _hex(eir_canonical_cbor_encode([b"x" * 255])),
        _hex(eir_canonical_cbor_encode([b"y" * 256])),
        _hex(eir_canonical_cbor_encode(["z" * 65535])),
    ]
    # The harness emits standalone values for string boundary cases.
    expected_vectors[2:] = [
        _hex(eir_canonical_cbor_encode(b"x" * 255)),
        _hex(eir_canonical_cbor_encode(b"y" * 256)),
        _hex(eir_canonical_cbor_encode("z" * 65535)),
    ]
    assert observed == expected_vectors
    assert (tmp_path / "binary.out").read_bytes() == eir_canonical_cbor_encode([7, b"\x00\xff", "ok"])
