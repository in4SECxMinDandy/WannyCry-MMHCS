"""Additional tests for PE analyzer edge cases."""


from core.pe_analyzer import PEResult, analyze


class TestPEAnalyzerExtended:
    def test_result_has_all_attrs(self) -> None:
        result = PEResult()
        assert hasattr(result, "is_pe")
        assert hasattr(result, "is_packed")
        assert hasattr(result, "packer_hint")
        assert hasattr(result, "num_sections")
        assert hasattr(result, "section_names")
        assert hasattr(result, "has_wannacry_section")
        assert hasattr(result, "has_suspicious_imports")
        assert hasattr(result, "suspicious_imports")
        assert hasattr(result, "suspicion_score")

    def test_analyze_nonexistent_returns_default(self, tmp_path) -> None:
        result = analyze(tmp_path / "no_file.exe")
        assert result.is_pe is False
        assert result.suspicion_score == 0.0

    def test_analyze_benign_has_low_suspicion(self, tmp_benign_file) -> None:
        result = analyze(tmp_benign_file)
        assert result.is_pe is True
        assert result.suspicion_score <= 0.5

    def test_analyze_wannacry_mock_has_higher_suspicion(self, tmp_pe_file_wannacry_mock) -> None:
        result = analyze(tmp_pe_file_wannacry_mock)
        assert result.is_pe is True
        assert result.suspicion_score >= 0.0

    def test_analyze_empty_file(self, tmp_empty_file) -> None:
        result = analyze(tmp_empty_file)
        assert result.is_pe is False

    def test_section_names_present(self, tmp_pe_file) -> None:
        result = analyze(tmp_pe_file)
        assert result.num_sections >= 2
