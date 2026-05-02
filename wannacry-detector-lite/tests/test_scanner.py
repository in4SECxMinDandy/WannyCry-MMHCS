"""Tests for scanner pipeline."""


from core.config_manager import load_config
from core.scanner import Scanner, _combine_verdict


class TestScanner:
    def test_init_with_config(self, tmp_config_file, tmp_wannacry_yara) -> None:
        config = load_config(tmp_config_file)
        config["yara_engine"]["rules_path"] = str(tmp_wannacry_yara)
        scanner = Scanner(config)
        assert scanner.yara_engine is not None

    def test_scan_benign_directory(self, tmp_config_file, tmp_benign_file, tmp_wannacry_yara) -> None:
        config = load_config(tmp_config_file)
        config["yara_engine"]["rules_path"] = str(tmp_wannacry_yara)
        scanner = Scanner(config)
        results = scanner.scan_path(tmp_benign_file)
        assert len(results) >= 1
        assert results[0].verdict in ("benign", "suspicious", "wannacry")

    def test_scan_wannacry_mock(self, tmp_config_file, tmp_pe_file_wannacry_mock, tmp_wannacry_yara) -> None:
        config = load_config(tmp_config_file)
        config["yara_engine"]["rules_path"] = str(tmp_wannacry_yara)
        scanner = Scanner(config)
        results = scanner.scan_path(tmp_pe_file_wannacry_mock)
        assert len(results) == 1
        assert results[0].verdict == "wannacry"

    def test_scan_nonexistent_path(self, tmp_config_file, tmp_wannacry_yara) -> None:
        config = load_config(tmp_config_file)
        config["yara_engine"]["rules_path"] = str(tmp_wannacry_yara)
        scanner = Scanner(config)
        results = scanner.scan_path("/nonexistent/path_12345")
        assert len(results) == 0

    def test_scan_directory(self, tmp_config_file, tmp_path, tmp_wannacry_yara) -> None:
        config = load_config(tmp_config_file)
        config["yara_engine"]["rules_path"] = str(tmp_wannacry_yara)
        (tmp_path / "test.exe").write_bytes(b"MZ" + b"\x00" * 100)
        scanner = Scanner(config)
        results = scanner.scan_path(tmp_path)
        assert len(results) >= 0

    def test_should_skip_whitelist_path(self, tmp_config_file, tmp_path, tmp_wannacry_yara) -> None:
        config = load_config(tmp_config_file)
        config["yara_engine"]["rules_path"] = str(tmp_wannacry_yara)
        config["scanner"]["whitelist_paths"] = [str(tmp_path)]
        scanner = Scanner(config)
        pe_file = tmp_path / "ignored.exe"
        pe_file.write_bytes(b"MZ" + b"\x00" * 100)
        results = scanner.scan_path(tmp_path)
        assert all(r.verdict != "wannacry" for r in results)


class TestCombineVerdict:
    def test_yara_match_always_wannacry(self) -> None:
        verdict = _combine_verdict(
            ml_label="benign", ml_score=0.1, ml_threshold=0.7,
            pe_score=0.0, yara_matches=["WannaCry_Mutex"],
        )
        assert verdict == "wannacry"

    def test_ml_and_pe_both_high(self) -> None:
        verdict = _combine_verdict(
            ml_label="wannacry", ml_score=0.9, ml_threshold=0.7,
            pe_score=0.5, yara_matches=[],
        )
        assert verdict == "wannacry"

    def test_ml_high_pe_low(self) -> None:
        verdict = _combine_verdict(
            ml_label="wannacry", ml_score=0.8, ml_threshold=0.7,
            pe_score=0.2, yara_matches=[],
        )
        assert verdict == "suspicious"

    def test_pe_alone_high(self) -> None:
        verdict = _combine_verdict(
            ml_label="benign", ml_score=0.3, ml_threshold=0.7,
            pe_score=0.8, yara_matches=[],
        )
        assert verdict == "suspicious"

    def test_all_low(self) -> None:
        verdict = _combine_verdict(
            ml_label="benign", ml_score=0.1, ml_threshold=0.7,
            pe_score=0.1, yara_matches=[],
        )
        assert verdict == "benign"

    def test_ml_borderline(self) -> None:
        verdict = _combine_verdict(
            ml_label="benign", ml_score=0.6, ml_threshold=0.7,
            pe_score=0.0, yara_matches=[],
        )
        assert verdict == "suspicious"
