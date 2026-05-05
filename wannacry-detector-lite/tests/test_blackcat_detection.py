"""Tests for BlackCat/ALPHV ransomware detection capabilities."""


from core.scanner import _combine_verdict


class TestCombineVerdictBlackCat:
    """Test _combine_verdict with BlackCat-specific signals."""

    def test_yara_blackcat_match_returns_blackcat(self):
        """YARA matches starting with 'BlackCat' should return blackcat verdict."""
        result = _combine_verdict(
            ml_label="benign",
            ml_score=0.0,
            ml_threshold=0.7,
            pe_score=0.0,
            yara_matches=["BlackCat_Rust_Strings"],
        )
        assert result == "blackcat"

    def test_yara_blackcat_multiple_matches(self):
        """Multiple BlackCat YARA matches should return blackcat."""
        result = _combine_verdict(
            ml_label="benign",
            ml_score=0.0,
            ml_threshold=0.7,
            pe_score=0.0,
            yara_matches=["BlackCat_Config_Strings", "BlackCat_Anti_Recovery"],
        )
        assert result == "blackcat"

    def test_yara_wannacry_match_still_returns_wannacry(self):
        """WannaCry YARA matches should still return wannacry verdict."""
        result = _combine_verdict(
            ml_label="benign",
            ml_score=0.0,
            ml_threshold=0.7,
            pe_score=0.0,
            yara_matches=["WannaCry_Strings"],
        )
        assert result == "wannacry"

    def test_yara_mixed_matches_blackcat_takes_priority(self):
        """When both BlackCat and WannaCry YARA match, BlackCat takes priority."""
        result = _combine_verdict(
            ml_label="benign",
            ml_score=0.0,
            ml_threshold=0.7,
            pe_score=0.0,
            yara_matches=["BlackCat_Rust_Strings", "WannaCry_Strings"],
        )
        assert result == "blackcat"

    def test_ml_blackcat_with_pe_returns_blackcat(self):
        """ML label blackcat + PE score >= 0.3 should return blackcat."""
        result = _combine_verdict(
            ml_label="blackcat",
            ml_score=0.85,
            ml_threshold=0.7,
            pe_score=0.4,
            yara_matches=[],
        )
        assert result == "blackcat"

    def test_ml_blackcat_low_pe_returns_suspicious(self):
        """ML label blackcat but PE score < 0.3 should return suspicious."""
        result = _combine_verdict(
            ml_label="blackcat",
            ml_score=0.85,
            ml_threshold=0.7,
            pe_score=0.1,
            yara_matches=[],
        )
        assert result == "suspicious"

    def test_ml_blackcat_below_threshold_returns_benign(self):
        """ML label blackcat below threshold should return benign."""
        result = _combine_verdict(
            ml_label="blackcat",
            ml_score=0.3,
            ml_threshold=0.7,
            pe_score=0.0,
            yara_matches=[],
        )
        assert result == "benign"

    def test_no_signals_returns_benign(self):
        """No signals from any engine should return benign."""
        result = _combine_verdict(
            ml_label="benign",
            ml_score=0.1,
            ml_threshold=0.7,
            pe_score=0.1,
            yara_matches=[],
        )
        assert result == "benign"

    def test_high_pe_only_returns_suspicious(self):
        """High PE score without ML/YARA should return suspicious."""
        result = _combine_verdict(
            ml_label="benign",
            ml_score=0.0,
            ml_threshold=0.7,
            pe_score=0.7,
            yara_matches=[],
        )
        assert result == "suspicious"

    def test_unknown_yara_rule_returns_suspicious(self):
        """YARA match with non-family prefix returns suspicious."""
        result = _combine_verdict(
            ml_label="benign",
            ml_score=0.0,
            ml_threshold=0.7,
            pe_score=0.0,
            yara_matches=["Generic_Ransomware_Rule"],
        )
        assert result == "suspicious"


class TestPEAnalyzerBlackCat:
    """Test PE analyzer BlackCat-specific detection."""

    def test_pe_result_has_blackcat_fields(self):
        """PEResult should have BlackCat-specific fields."""
        from core.pe_analyzer import PEResult

        result = PEResult()
        assert hasattr(result, "has_blackcat_indicators")
        assert hasattr(result, "blackcat_imports")
        assert hasattr(result, "is_rust_binary")
        assert hasattr(result, "detected_family")
        assert result.has_blackcat_indicators is False
        assert result.blackcat_imports == []
        assert result.is_rust_binary is False
        assert result.detected_family is None

    def test_blackcat_imports_set_exists(self):
        """BLACKCAT_IMPORTS set should contain expected API names."""
        from core.pe_analyzer import BLACKCAT_IMPORTS

        assert "BCryptEncrypt" in BLACKCAT_IMPORTS
        assert "BCryptDecrypt" in BLACKCAT_IMPORTS
        assert "CreateToolhelp32Snapshot" in BLACKCAT_IMPORTS
        assert "TerminateProcess" in BLACKCAT_IMPORTS

    def test_rust_indicators_set_exists(self):
        """RUST_INDICATORS set should contain expected Rust markers."""
        from core.pe_analyzer import RUST_INDICATORS

        assert "rust_panic" in RUST_INDICATORS
        assert "core::panicking" in RUST_INDICATORS


class TestReportGeneratorBlackCat:
    """Test report generator BlackCat verdict counting."""

    def test_summary_includes_blackcat(self):
        """generate_summary should include blackcat count."""
        from core.report_generator import ReportGenerator, ScanResult

        gen = ReportGenerator(output_dir="reports")
        results = [
            ScanResult(file_path="a.exe", verdict="wannacry"),
            ScanResult(file_path="b.exe", verdict="blackcat"),
            ScanResult(file_path="c.exe", verdict="blackcat"),
            ScanResult(file_path="d.exe", verdict="suspicious"),
            ScanResult(file_path="e.exe", verdict="benign"),
        ]
        summary = gen.generate_summary(results)
        assert summary["wannacry"] == 1
        assert summary["blackcat"] == 2
        assert summary["suspicious"] == 1
        assert summary["benign"] == 1
        assert summary["total"] == 5


class TestDatasetBuilderBlackCat:
    """Test dataset builder BlackCat sample generation."""

    def test_generate_blackcat_sample_returns_16_features(self):
        """BlackCat synthetic sample should have 16 features."""
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
        from build_wannacry_dataset import generate_blackcat_sample

        sample = generate_blackcat_sample(42)
        assert len(sample) == 16
        assert all(isinstance(v, float) for v in sample)

    def test_blackcat_sample_high_entropy(self):
        """BlackCat samples should have high entropy (>= 7.0)."""
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
        from build_wannacry_dataset import generate_blackcat_sample

        sample = generate_blackcat_sample(42)
        assert sample[0] >= 7.0  # entropy_full

    def test_blackcat_sample_many_sections(self):
        """BlackCat samples should have >= 6 sections (Rust binary)."""
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
        from build_wannacry_dataset import generate_blackcat_sample

        sample = generate_blackcat_sample(42)
        assert sample[13] >= 6.0  # num_sections
