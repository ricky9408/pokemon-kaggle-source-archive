from __future__ import annotations

from types import MappingProxyType

import pytest

from evaluation_v6_3_1.launch_gate_stage1_packer import (
    EMPTY_PATH_OFFSET,
    END_BR64,
    NO_UPLOAD,
    PAGE_SIZE,
    PRODUCTION_UPLOAD_AUTHORIZED,
    Stage1PackResult,
    Stage1PackerError,
    pack_stage1_trailer,
)


def _page(code: bytes, *, empty_path: int = 0) -> bytes:
    assert len(code) <= EMPTY_PATH_OFFSET
    return code + bytes([0xCC]) * (EMPTY_PATH_OFFSET - len(code)) + bytes([empty_path])


def test_packs_exact_prefix_zero_padding_and_trailer_metadata() -> None:
    base = b"base-supervisor"  # Deliberately not ELF: the packer must not parse it.
    page = _page(END_BR64 + b"\x90", empty_path=0)

    result = pack_stage1_trailer(base, page, len(END_BR64) + 1)

    assert isinstance(result, Stage1PackResult)
    assert result.final_image[: len(base)] == base
    assert result.final_image[len(base) : PAGE_SIZE] == b"\x00" * (PAGE_SIZE - len(base))
    assert result.final_image[PAGE_SIZE : PAGE_SIZE + PAGE_SIZE] == page
    assert result.metadata["gate_file_offset"] == PAGE_SIZE
    assert result.metadata["padding_length"] == PAGE_SIZE - len(base)
    assert result.metadata["final_length"] == PAGE_SIZE * 2
    assert result.metadata["gate_code_size"] == len(END_BR64) + 1


def test_metadata_is_immutable_and_explicitly_zero_authority() -> None:
    result = pack_stage1_trailer(b"x" * PAGE_SIZE, _page(END_BR64), len(END_BR64))

    assert isinstance(result.metadata, MappingProxyType)
    assert result.metadata["state"] == NO_UPLOAD
    assert result.metadata["authority"] is False
    assert result.metadata["zero_authority"] is True
    assert result.metadata["calibration_upload_authorized"] is False
    assert result.metadata["production_upload_authorized"] is PRODUCTION_UPLOAD_AUTHORIZED is False
    with pytest.raises(TypeError):
        result.metadata["state"] = "AUTHORIZED"  # type: ignore[index]


def test_bytes_subclasses_are_normalized_through_the_buffer_protocol() -> None:
    class AdversarialBytes(bytes):
        def __len__(self) -> int:
            return 0

        def __getitem__(self, key: object) -> bytes:
            return b"attacker-controlled-slice"

        def __add__(self, other: object) -> bytes:
            return b"attacker-controlled-concatenation"

    base = AdversarialBytes(b"base")
    page = AdversarialBytes(_page(END_BR64))
    result = pack_stage1_trailer(base, page, len(END_BR64))

    assert result.final_image[:4] == b"base"
    assert result.final_image[result.metadata["gate_file_offset"] :] == bytes(memoryview(page))
    assert result.metadata["base_length"] == 4


@pytest.mark.parametrize(
    ("page", "code_size", "code"),
    [
        (_page(b"\x90\x90"), 4, "GATE_ENTRY_INVALID"),
        (_page(END_BR64, empty_path=1), 4, "GATE_EMPTY_PATH_INVALID"),
        (_page(END_BR64 + b"\x90"), 4, "GATE_PADDING_INVALID"),
    ],
)
def test_rejects_invalid_gate_page(page: bytes, code_size: int, code: str) -> None:
    with pytest.raises(Stage1PackerError, match=code):
        pack_stage1_trailer(b"base", page, code_size)


@pytest.mark.parametrize("code_size", [-1, 0, 3, PAGE_SIZE, True, 4.0])
def test_rejects_invalid_code_size(code_size: object) -> None:
    with pytest.raises(Stage1PackerError, match="GATE_CODE_SIZE_INVALID"):
        pack_stage1_trailer(b"base", _page(END_BR64), code_size)  # type: ignore[arg-type]


def test_rejects_wrong_page_length_and_accepts_exact_page_boundary() -> None:
    with pytest.raises(Stage1PackerError, match="GATE_PAGE_SIZE_INVALID"):
        pack_stage1_trailer(b"base", b"short", 4)

    result = pack_stage1_trailer(b"base" * PAGE_SIZE, _page(END_BR64), 4)
    assert result.metadata["gate_file_offset"] == PAGE_SIZE * 4
    assert len(result.final_image) == PAGE_SIZE * 5


def test_bytearray_inputs_are_snapshotted_without_mutating_them() -> None:
    base = bytearray(b"base")
    page = bytearray(_page(END_BR64))
    result = pack_stage1_trailer(base, page, 4)

    base[0] = ord("X")
    page[0] = 0
    assert result.final_image.startswith(b"base")
    assert result.final_image[result.metadata["gate_file_offset"]] == END_BR64[0]
