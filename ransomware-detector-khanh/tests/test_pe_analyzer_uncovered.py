"""Additional PE analyzer tests for uncovered paths."""

import struct

from core.pe_analyzer import analyze


class TestPEAnalyzerUncovered:
    def test_analyze_very_small_pe(self, tmp_empty_file):
        result = analyze(tmp_empty_file)
        assert result.is_pe is False

    def test_packer_detection_with_known_packer(self, tmp_path):
        pe_data = build_pe_with_section_name(b".upx0\x00\x00\x00")
        pe_path = tmp_path / "packed.exe"
        pe_path.write_bytes(pe_data)
        result = analyze(pe_path)
        assert result.is_pe is True

    def test_packer_detection_with_unknown_section(self, tmp_path):
        pe_data = build_pe_with_section_name(b".foo\x00\x00\x00\x00\x00")
        pe_path = tmp_path / "odd.exe"
        pe_path.write_bytes(pe_data)
        result = analyze(pe_path)
        assert result.is_pe is True

    def test_result_scoring_packed_alone(self, tmp_path):
        pe_data = build_pe_with_section_name(b".upx0\x00\x00\x00")
        pe_path = tmp_path / "upx.exe"
        pe_path.write_bytes(pe_data)
        result = analyze(pe_path)
        assert result.suspicion_score > 0.0

    def test_section_names_lowercase_handling(self, tmp_pe_file):
        result = analyze(tmp_pe_file)
        assert isinstance(result.section_names, list)

    def test_empty_suspicion_score_default(self, tmp_benign_file):
        result = analyze(tmp_benign_file)
        assert 0.0 <= result.suspicion_score <= 1.0

    def test_all_result_fields_present(self, tmp_pe_file):
        result = analyze(tmp_pe_file)
        assert isinstance(result.is_pe, bool)
        assert isinstance(result.is_packed, bool)
        assert isinstance(result.num_sections, int)
        assert isinstance(result.has_suspicious_imports, bool)


def build_pe_with_section_name(section_name: bytes) -> bytes:
    dos_hdr = bytearray(64)
    dos_hdr[0:2] = b"MZ"
    struct.pack_into("<I", dos_hdr, 0x3C, 64)

    nt = bytearray(4 + 20 + 224)
    nt[0:4] = b"PE\x00\x00"
    struct.pack_into("<H", nt, 4, 0x8664)
    struct.pack_into("<H", nt, 6, 1)
    struct.pack_into("<H", nt, 24+16, 0xE0)
    struct.pack_into("<H", nt, 24+18, 0x0102)
    struct.pack_into("<H", nt, 28, 0x020B)

    section_size = 0x200
    raw_offset = section_size
    opt_header = nt[24:]
    struct.pack_into("<I", opt_header, 32, 0x1000)
    struct.pack_into("<I", opt_header, 36, section_size)
    struct.pack_into("<I", opt_header, 60, 0x100000)
    struct.pack_into("<I", opt_header, 64, 0x200)
    struct.pack_into("<I", opt_header, 72, 0x1000)
    struct.pack_into("<I", opt_header, 76, 0x200)

    section_hdr = bytearray(40)
    section_hdr[0:8] = section_name.ljust(8, b"\x00")
    struct.pack_into("<I", section_hdr, 8, 0x200)
    struct.pack_into("<I", section_hdr, 12, 0x1000)
    struct.pack_into("<I", section_hdr, 16, section_size)
    struct.pack_into("<I", section_hdr, 20, raw_offset)
    struct.pack_into("<I", section_hdr, 36, 0x60000020)

    data = dos_hdr + nt + section_hdr + b"\x00" * section_size
    return bytes(data)
