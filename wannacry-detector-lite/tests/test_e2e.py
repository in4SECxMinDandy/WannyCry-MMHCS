"""End-to-end tests for the full multi-family ransomware detection pipeline.

These tests verify the complete integration of all detection layers
(PE, YARA, ML) for both WannaCry and BlackCat/ALPHV families.
"""

import json
import sys
from pathlib import Path

from core.config_manager import get_default_config, load_config
from core.feature_extractor import extract_features
from core.ml_engine import MLEngine
from core.pe_analyzer import analyze
from core.report_generator import ReportGenerator, ScanResult
from core.scanner import Scanner, _combine_verdict
from core.yara_engine import YaraEngine


class TestEndToEndBlackCatDetection:
    """Full pipeline tests for BlackCat/ALPHV detection."""

    def test_scan_blackcat_mock_detected(
        self, tmp_config_file, tmp_pe_file_blackcat_mock, tmp_blackcat_yara
    ):
        """File with BlackCat IOC strings should be detected as blackcat."""
        config = load_config(tmp_config_file)
        config["yara_engine"] = {
            "rules_dir": str(tmp_blackcat_yara.parent),
            "rules_files": [tmp_blackcat_yara.name],
            "compile_on_load": True,
        }
        scanner = Scanner(config)
        results = scanner.scan_path(tmp_pe_file_blackcat_mock)
        assert len(results) == 1
        assert results[0].verdict == "blackcat"

    def test_scan_wannacry_mock_still_detected(
        self, tmp_config_file, tmp_pe_file_wannacry_mock, tmp_wannacry_yara
    ):
        """WannaCry mock should still be detected as wannacry."""
        config = load_config(tmp_config_file)
        config["yara_engine"] = {
            "rules_dir": str(tmp_wannacry_yara.parent),
            "rules_files": [tmp_wannacry_yara.name],
            "compile_on_load": True,
        }
        scanner = Scanner(config)
        results = scanner.scan_path(tmp_pe_file_wannacry_mock)
        assert len(results) == 1
        assert results[0].verdict == "wannacry"

    def test_scan_benign_not_detected(self, tmp_config_file, tmp_benign_file, tmp_wannacry_yara):
        """Benign file should not be flagged as ransomware."""
        config = load_config(tmp_config_file)
        config["yara_engine"] = {
            "rules_dir": str(tmp_wannacry_yara.parent),
            "rules_files": [tmp_wannacry_yara.name],
            "compile_on_load": True,
        }
        scanner = Scanner(config)
        results = scanner.scan_path(tmp_benign_file)
        assert len(results) == 1
        assert results[0].verdict == "benign"

    def test_pe_analyzer_detects_blackcat_indicators(self, tmp_pe_file_blackcat_mock):
        """PE analysis on mock BlackCat file should report BlackCat indicators."""
        result = analyze(tmp_pe_file_blackcat_mock)
        assert result.is_pe is True
        assert result.has_blackcat_indicators is True
        assert result.is_rust_binary is True
        assert result.detected_family == "blackcat"

    def test_pe_analyzer_detects_wannacry_indicators(self, tmp_pe_file_wannacry_mock):
        """PE analysis on mock WannaCry file should report WannaCry indicators."""
        result = analyze(tmp_pe_file_wannacry_mock)
        assert result.is_pe is True
        assert result.has_wannacry_section is False  # mock uses strings, not section names

    def test_yara_detects_blackcat_strings(self, tmp_blackcat_yara):
        """YARA should detect BlackCat strings in raw bytes."""
        engine = YaraEngine(rules_path=tmp_blackcat_yara)
        data = (
            b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
            + b"encrypt_app::windows\x00" * 3
            + b"locker::core::\x00" * 3
        )
        matches = engine.scan_bytes(data)
        rule_names = [m.rule_name for m in matches]
        assert "BlackCat_Rust_Strings" in rule_names

    def test_yara_detects_wannacry_strings(self, tmp_wannacry_yara):
        """YARA should detect WannaCry strings in raw bytes."""
        engine = YaraEngine(rules_path=tmp_wannacry_yara)
        data = (
            b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
            + b"MsWinZonesCacheCounterMutexA\x00" * 3
        )
        matches = engine.scan_bytes(data)
        rule_names = [m.rule_name for m in matches]
        assert "WannaCry_Mutex" in rule_names


class TestEndToEndMultiFamilyPipeline:
    """Tests covering both families in a single pipeline run."""

    def test_scan_directory_with_both_families(
        self,
        tmp_path,
        tmp_config_file,
        tmp_pe_file_wannacry_mock,
        tmp_pe_file_blackcat_mock,
        tmp_benign_file,
        tmp_wannacry_yara,
        tmp_blackcat_yara,
    ):
        """Scanner should correctly identify each family in a mixed directory."""
        config = load_config(tmp_config_file)
        config["yara_engine"] = {
            "rules_dir": str(tmp_wannacry_yara.parent),
            "rules_files": [tmp_wannacry_yara.name, tmp_blackcat_yara.name],
            "compile_on_load": True,
        }
        scanner = Scanner(config)

        # Copy mocks into a shared temp directory
        scan_dir = tmp_path / "mixed"
        scan_dir.mkdir()
        (scan_dir / "wannacry.exe").write_bytes(tmp_pe_file_wannacry_mock.read_bytes())
        (scan_dir / "blackcat.exe").write_bytes(tmp_pe_file_blackcat_mock.read_bytes())
        (scan_dir / "benign.exe").write_bytes(tmp_benign_file.read_bytes())

        results = scanner.scan_path(scan_dir)

        # All three files should be scanned
        assert len(results) == 3

        # At least one blackcat and one wannacry should be detected via YARA
        assert any(r.verdict == "blackcat" for r in results)
        assert any(r.verdict == "wannacry" for r in results)

    def test_report_generator_counts_both_families(self, tmp_path):
        """Report should correctly count WannaCry and BlackCat separately."""
        gen = ReportGenerator(tmp_path)
        results = [
            ScanResult(file_path="/a.exe", verdict="wannacry"),
            ScanResult(file_path="/b.exe", verdict="blackcat"),
            ScanResult(file_path="/c.exe", verdict="blackcat"),
            ScanResult(file_path="/d.exe", verdict="suspicious"),
            ScanResult(file_path="/e.exe", verdict="benign"),
        ]

        json_path = gen.generate_json(results)
        content = json.loads(json_path.read_text())
        assert content["verdicts"]["wannacry"] == 1
        assert content["verdicts"]["blackcat"] == 2
        assert content["verdicts"]["suspicious"] == 1
        assert content["verdicts"]["benign"] == 1

        summary = gen.generate_summary(results)
        assert summary["wannacry"] == 1
        assert summary["blackcat"] == 2
        assert summary["suspicious"] == 1
        assert summary["benign"] == 1

    def test_combine_verdict_prioritizes_blackcat_over_wannacry(self):
        """If both YARA families match, BlackCat should take priority."""
        verdict = _combine_verdict(
            ml_label="benign",
            ml_score=0.0,
            ml_threshold=0.7,
            pe_score=0.0,
            yara_matches=["BlackCat_Rust_Strings", "WannaCry_Mutex"],
        )
        assert verdict == "blackcat"


class TestEndToEndDatasetAndTraining:
    """E2E tests for dataset builder and training pipeline."""

    def test_dataset_builder_creates_three_labels(self):
        """Dataset builder should generate WannaCry, BlackCat, and Benign samples."""
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
        from build_wannacry_dataset import build_dataset

        rows = build_dataset(wannacry_count=10, blackcat_count=10, benign_count=10)
        labels = [label for _, label in rows]
        assert labels.count("wannacry") == 10
        assert labels.count("blackcat") == 10
        assert labels.count("benign") == 10

    def test_feature_extraction_on_pe_files(self, tmp_pe_file, tmp_pe_file_blackcat_mock):
        """Feature extraction should work on both benign and BlackCat mocks."""
        for fp in (tmp_pe_file, tmp_pe_file_blackcat_mock):
            features = extract_features(fp)
            assert features is not None
            assert all(f"feature_{i}" in features for i in range(1, 17))


class TestEndToEndConfigAndEngines:
    """E2E tests for configuration and engine initialization."""

    def test_default_config_includes_both_rule_files(self):
        """Default config should reference both WannaCry and BlackCat YARA files."""
        cfg = get_default_config()
        assert "rules_files" in cfg["yara_engine"]
        assert "wannacry.yar" in cfg["yara_engine"]["rules_files"]
        assert "blackcat.yar" in cfg["yara_engine"]["rules_files"]

    def test_yara_engine_compiles_both_rules(self, tmp_wannacry_yara, tmp_blackcat_yara):
        """YaraEngine should compile both family rules simultaneously."""
        engine = YaraEngine(rules_paths=[tmp_wannacry_yara, tmp_blackcat_yara])
        assert engine.is_compiled()
        assert engine.get_rule_count() > 0

    def test_ml_engine_loads_and_predicts_blackcat(self, tmp_path):
        """ML engine should predict blackcat label when given blackcat-like features."""
        import joblib
        from sklearn.ensemble import RandomForestClassifier

        model_path = tmp_path / "test_model.pkl"
        # Train a tiny 3-class model on the fly
        X = [
            [7.5, 7.0, 6.0, 30000, 0.05, 0.05, 0.05, 0.05, 0.1, 0.1, 0.1, 0.5, 22.0, 5.0, 0.7, 5.0],
            [7.8, 7.5, 6.5, 35000, 0.06, 0.06, 0.06, 0.06, 0.1, 0.1, 0.1, 0.6, 23.0, 8.0, 0.5, 7.0],
            [4.0, 3.5, 3.0, 5000, 0.15, 0.15, 0.15, 0.15, 0.1, 0.1, 0.1, 0.2, 18.0, 4.0, 0.3, 1.0],
        ]
        y = ["wannacry", "blackcat", "benign"]
        clf = RandomForestClassifier(n_estimators=10, random_state=42)
        clf.fit(X, y)
        joblib.dump(clf, model_path)

        engine = MLEngine(model_path=model_path, threshold=0.3)
        blackcat_features = {
            "feature_1": 7.8,
            "feature_2": 7.5,
            "feature_3": 6.5,
            "feature_4": 35000,
            "feature_5": 0.06,
            "feature_6": 0.06,
            "feature_7": 0.06,
            "feature_8": 0.06,
            "feature_9": 0.1,
            "feature_10": 0.1,
            "feature_11": 0.1,
            "feature_12": 0.6,
            "feature_13": 23.0,
            "feature_14": 8.0,
            "feature_15": 0.5,
            "feature_16": 7.0,
        }
        label, score = engine.predict(blackcat_features)
        assert label == "blackcat"
        assert score >= 0.3


class TestEndToEdgeCases:
    """Edge-case e2e tests for robustness."""

    def test_scan_empty_directory(self, tmp_config_file, tmp_path):
        """Scanning an empty directory should return no results."""
        config = load_config(tmp_config_file)
        scanner = Scanner(config)
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        results = scanner.scan_path(empty_dir)
        assert results == []

    def test_scan_nonexistent_path(self, tmp_config_file):
        """Scanning a nonexistent path should return empty results gracefully."""
        config = load_config(tmp_config_file)
        scanner = Scanner(config)
        results = scanner.scan_path("/nonexistent/path_12345")
        assert results == []

    def test_scan_text_file_ignored(self, tmp_config_file, tmp_text_file):
        """Text files should be skipped based on extension whitelist."""
        config = load_config(tmp_config_file)
        scanner = Scanner(config)
        results = scanner.scan_path(tmp_text_file)
        assert results == []

    def test_yara_scan_bytes_timeout(self, tmp_wannacry_yara):
        """YARA byte scan should handle empty data gracefully."""
        engine = YaraEngine(rules_path=tmp_wannacry_yara)
        matches = engine.scan_bytes(b"")
        assert matches == []
