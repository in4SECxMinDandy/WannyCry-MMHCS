"""Test fixtures and configuration for the test suite."""

import json
import struct
from pathlib import Path

import pytest

from core.config_manager import get_default_config

TESTS_DIR = Path(__file__).parent
PROJECT_ROOT = TESTS_DIR.parent


def _build_minimal_pe(sections: list[tuple[str, bytes]] | None = None) -> bytes:
    """Build a minimal valid PE file for testing.

    Args:
        sections: List of (name, data) tuples for sections.

    Returns:
        Bytes of a valid PE file.
    """
    if sections is None:
        sections = [(".text", b"\x90" * 512), (".data", b"\x00" * 256)]

    section_count = len(sections)
    section_headers_size = section_count * 40
    nt_headers_size = 4 + 20 + 224

    e_lfanew = 64
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, e_lfanew)

    pe_signature = b"PE\x00\x00"

    coff_header = bytearray(20)
    struct.pack_into("<H", coff_header, 0, 0x8664)
    struct.pack_into("<H", coff_header, 2, section_count)
    struct.pack_into("<I", coff_header, 4, 0)
    struct.pack_into("<I", coff_header, 8, 0)
    struct.pack_into("<I", coff_header, 12, 0)
    struct.pack_into("<H", coff_header, 16, 0xE0)
    struct.pack_into("<H", coff_header, 18, 0x0102)

    opt_header = bytearray(224)
    struct.pack_into("<H", opt_header, 0, 0x020B)
    section_headers_offset = e_lfanew + nt_headers_size
    first_section_rva = 0x1000
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = e_lfanew + nt_headers_size + section_headers_size
    size_of_headers = ((headers_size + file_alignment - 1) // file_alignment) * file_alignment

    struct.pack_into("<I", opt_header, 32, 0x1000)
    struct.pack_into("<I", opt_header, 36, file_alignment)
    struct.pack_into("<I", opt_header, 60, 0x100000)
    struct.pack_into("<I", opt_header, 64, size_of_headers)
    struct.pack_into("<I", opt_header, 72, section_alignment)
    struct.pack_into("<I", opt_header, 76, file_alignment)

    nt_headers = pe_signature + coff_header + opt_header

    section_table = bytearray(section_headers_size)
    section_data_list: list[bytes] = []
    current_rva = first_section_rva
    raw_offset = size_of_headers

    for i, (name, data) in enumerate(sections):
        off = i * 40
        name_bytes = name.encode("ascii")[:8].ljust(8, b"\x00")
        section_table[off : off + 8] = name_bytes
        vsize = len(data)
        padded_vsize = ((vsize + file_alignment - 1) // file_alignment) * file_alignment
        struct.pack_into("<I", section_table, off + 8, vsize)
        struct.pack_into("<I", section_table, off + 12, current_rva)
        struct.pack_into("<I", section_table, off + 16, padded_vsize)
        struct.pack_into("<I", section_table, off + 20, raw_offset)
        if name == ".text":
            struct.pack_into("<I", section_table, off + 36, 0x60000020)
        elif name == ".data":
            struct.pack_into("<I", section_table, off + 36, 0xC0000040)
        else:
            struct.pack_into("<I", section_table, off + 36, 0x40000040)
        section_data_list.append(data + b"\x00" * (padded_vsize - vsize))
        current_rva += ((vsize + section_alignment - 1) // section_alignment) * section_alignment
        raw_offset += padded_vsize

    pe_data = bytearray(size_of_headers)
    pe_data[0:64] = dos_header
    pe_data[e_lfanew : e_lfanew + len(nt_headers)] = nt_headers
    pe_data[section_headers_offset : section_headers_offset + section_headers_size] = section_table

    full_data = bytes(pe_data)
    for sd in section_data_list:
        full_data += sd

    return full_data


@pytest.fixture
def mock_config() -> dict:
    """Provide a complete test configuration."""
    return get_default_config()


@pytest.fixture
def tmp_config_file(tmp_path: Path, mock_config: dict) -> Path:
    """Write a temporary config.json file."""
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(mock_config))
    return config_path


@pytest.fixture
def tmp_pe_file(tmp_path: Path) -> Path:
    """Create a temporary minimal PE file."""
    pe_data = _build_minimal_pe()
    pe_path = tmp_path / "test_pe.exe"
    pe_path.write_bytes(pe_data)
    return pe_path


@pytest.fixture
def tmp_pe_file_wannacry_mock(tmp_path: Path) -> Path:
    """Create a PE file containing WannaCry IOC strings."""
    sections = [
        (".text", b"\x90" * 1000 + b"MsWinZonesCacheCounterMutexA\x00" + b"WANACRY!\x00" + b"\x90" * 500),
        (".data", b"iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com\x00"),
    ]
    pe_data = _build_minimal_pe(sections)
    pe_path = tmp_path / "mock_wannacry.exe"
    pe_path.write_bytes(pe_data)
    return pe_path


@pytest.fixture
def tmp_benign_file(tmp_path: Path) -> Path:
    """Create a file with benign content (like notepad)."""
    file_path = tmp_path / "notepad_mock.exe"
    pe_data = _build_minimal_pe([
        (".text", b"Notepad-like text section\x00" + b"\xcc" * 512),
        (".data", b"\x00" * 256),
        (".rsrc", b"\x01" * 128),
    ])
    file_path.write_bytes(pe_data)
    return file_path


@pytest.fixture
def tmp_text_file(tmp_path: Path) -> Path:
    """Create a plain text file (not PE)."""
    file_path = tmp_path / "readme.txt"
    file_path.write_text("This is a plain text file. Not a PE executable.")
    return file_path


@pytest.fixture
def tmp_empty_file(tmp_path: Path) -> Path:
    """Create an empty file."""
    file_path = tmp_path / "empty.bin"
    file_path.write_bytes(b"")
    return file_path


@pytest.fixture
def tmp_wannacry_yara(tmp_path: Path) -> Path:
    """Copy the WannaCry YARA rules to temp directory."""
    src = PROJECT_ROOT / "rules" / "wannacry.yar"
    dst = tmp_path / "wannacry.yar"
    dst.write_text(src.read_text())
    return dst


@pytest.fixture
def tmp_blackcat_yara(tmp_path: Path) -> Path:
    """Copy the BlackCat YARA rules to temp directory."""
    src = PROJECT_ROOT / "rules" / "blackcat.yar"
    dst = tmp_path / "blackcat.yar"
    dst.write_text(src.read_text())
    return dst


@pytest.fixture
def tmp_pe_file_blackcat_mock(tmp_path: Path) -> Path:
    """Create a PE file containing BlackCat IOC strings."""
    sections = [
        (
            ".text",
            b"\x90" * 500
            + b"encrypt_app::windows\x00"
            + b"locker::core::\x00"
            + b"rust_panic\x00"
            + b"BCryptEncrypt\x00"
            + b"\x90" * 500,
        ),
        (
            ".rdata",
            b"vssadmin delete shadows /all /quiet\x00"
            + b"RECOVER-files-FILES.txt\x00"
            + b"\x00" * 200,
        ),
    ]
    pe_data = _build_minimal_pe(sections)
    pe_path = tmp_path / "mock_blackcat.exe"
    pe_path.write_bytes(pe_data)
    return pe_path
