"""Tests for scanner edge cases and uncovered paths."""


from core.config_manager import get_default_config
from core.scanner import Scanner, _combine_verdict


class TestScannerEdgeCases:
    def test_should_scan_file_too_large(self, tmp_pe_file, tmp_wannacry_yara):
        cfg = get_default_config()
        cfg["scanner"]["max_file_size_mb"] = 0.0001
        cfg["yara_engine"]["rules_path"] = str(tmp_wannacry_yara)
        scanner = Scanner(cfg)
        assert not scanner._should_scan(tmp_pe_file)

    def test_should_scan_whitelisted_path(self, tmp_pe_file, tmp_wannacry_yara):
        cfg = get_default_config()
        cfg["scanner"]["whitelist_paths"] = [str(tmp_pe_file.parent)]
        cfg["yara_engine"]["rules_path"] = str(tmp_wannacry_yara)
        scanner = Scanner(cfg)
        assert not scanner._should_scan(tmp_pe_file)

    def test_should_scan_wrong_extension(self, tmp_path):
        cfg = get_default_config()
        txt_file = tmp_path / "test.txt"
        txt_file.write_text("not an exe")
        scanner = Scanner(cfg)
        assert not scanner._should_scan(txt_file)

    def test_walk_directory_single_file(self, tmp_pe_file, tmp_wannacry_yara):
        cfg = get_default_config()
        cfg["yara_engine"]["rules_path"] = str(tmp_wannacry_yara)
        scanner = Scanner(cfg)
        files = scanner._walk_directory(tmp_pe_file)
        assert len(files) == 1

    def test_scan_with_single_worker(self, tmp_pe_file, tmp_wannacry_yara):
        cfg = get_default_config()
        cfg["scanner"]["max_workers"] = 1
        cfg["yara_engine"]["rules_path"] = str(tmp_wannacry_yara)
        scanner = Scanner(cfg)
        results = scanner.scan_path(tmp_pe_file)
        assert len(results) >= 1

    def test_scan_error_on_bad_file(self, tmp_path, tmp_wannacry_yara):
        cfg = get_default_config()
        cfg["yara_engine"]["rules_path"] = str(tmp_wannacry_yara)
        scanner = Scanner(cfg)
        bad_path = tmp_path / "bad.exe"
        bad_path.write_bytes(b"MZ" + b"\x00" * 100)
        results = scanner.scan_path(bad_path)
        assert len(results) >= 0

    def test_scan_path_does_not_exist(self, tmp_wannacry_yara):
        cfg = get_default_config()
        cfg["yara_engine"]["rules_path"] = str(tmp_wannacry_yara)
        scanner = Scanner(cfg)
        results = scanner.scan_path("/definitely/not/real/path")
        assert results == []

    def test_ml_engine_disabled_when_no_model(self, tmp_path, tmp_wannacry_yara):
        cfg = get_default_config()
        cfg["ml_engine"]["model_path"] = str(tmp_path / "no_model.pkl")
        cfg["yara_engine"]["rules_path"] = str(tmp_wannacry_yara)
        scanner = Scanner(cfg)
        assert scanner.ml_engine is None

    def test_yara_engine_disabled_when_no_rules(self, tmp_path):
        cfg = get_default_config()
        cfg["yara_engine"]["rules_dir"] = str(tmp_path / "no_rules_dir")
        cfg["yara_engine"]["rules_files"] = ["no_rules.yar"]
        cfg["yara_engine"].pop("rules_path", None)
        scanner = Scanner(cfg)
        assert scanner.yara_engine is None


class TestCombineVerdictExtended:
    def test_all_signals_strong(self):
        verdict = _combine_verdict(
            ml_label="wannacry", ml_score=0.95, ml_threshold=0.7,
            pe_score=0.8, yara_matches=["WannaCry_Mutex", "WannaCry_Strings"],
        )
        assert verdict == "wannacry"

    def test_only_yara_no_ml_no_pe(self):
        verdict = _combine_verdict(
            ml_label="benign", ml_score=0.0, ml_threshold=0.7,
            pe_score=0.0, yara_matches=["WannaCry_Killswitch"],
        )
        assert verdict == "wannacry"

    def test_ml_just_under_threshold_but_borderline(self):
        verdict = _combine_verdict(
            ml_label="wannacry", ml_score=0.69, ml_threshold=0.7,
            pe_score=0.0, yara_matches=[],
        )
        assert verdict == "suspicious"

    def test_ml_very_low_no_suspicion(self):
        verdict = _combine_verdict(
            ml_label="benign", ml_score=0.1, ml_threshold=0.7,
            pe_score=0.0, yara_matches=[],
        )
        assert verdict == "benign"

    def test_pe_medium_score(self):
        verdict = _combine_verdict(
            ml_label="benign", ml_score=0.1, ml_threshold=0.7,
            pe_score=0.65, yara_matches=[],
        )
        assert verdict == "suspicious"
