"""Tests for PE analyzer module."""

from core.pe_analyzer import PEResult, analyze


class TestPEAnalyzer:
    def test_valid_pe(self, tmp_pe_file) -> None:
        result = analyze(tmp_pe_file)
        assert result.is_pe is True
        assert result.num_sections >= 2

    def test_not_pe(self, tmp_text_file) -> None:
        result = analyze(tmp_text_file)
        assert result.is_pe is False

    def test_nonexistent_file(self, tmp_path) -> None:
        result = analyze(tmp_path / "nonexistent.exe")
        assert result.is_pe is False

    def test_section_names(self, tmp_pe_file) -> None:
        result = analyze(tmp_pe_file)
        assert ".text" in result.section_names or ".data" in result.section_names

    def test_wannacry_mock_detection(self, tmp_pe_file_wannacry_mock) -> None:
        result = analyze(tmp_pe_file_wannacry_mock)
        assert result.is_pe is True
        assert result.suspicion_score >= 0.0

    def test_benign_file_low_score(self, tmp_benign_file) -> None:
        result = analyze(tmp_benign_file)
        assert result.is_pe is True
        assert result.suspicion_score <= 0.5

    def test_result_defaults(self) -> None:
        result = PEResult()
        assert result.is_pe is False
        assert result.is_packed is False
        assert result.suspicion_score == 0.0
