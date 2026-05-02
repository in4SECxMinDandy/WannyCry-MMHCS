"""End-to-end WannaCry detection tests."""

import json

from core.config_manager import load_config
from core.feature_extractor import extract_features
from core.pe_analyzer import analyze
from core.report_generator import ReportGenerator, ScanResult
from core.scanner import Scanner


class TestEndToEndWannaCryDetection:
    """Integration tests verifying full detection pipeline."""

    def test_mock_wannacry_detected(self, tmp_config_file, tmp_pe_file_wannacry_mock, tmp_wannacry_yara):
        """File with WannaCry IOC strings should be detected as wannacry."""
        config = load_config(tmp_config_file)
        config["yara_engine"]["rules_path"] = str(tmp_wannacry_yara)
        scanner = Scanner(config)
        results = scanner.scan_path(tmp_pe_file_wannacry_mock)
        assert len(results) == 1
        assert results[0].verdict == "wannacry"

    def test_benign_file_not_detected(self, tmp_config_file, tmp_benign_file, tmp_wannacry_yara):
        """Benign file should not be flagged as wannacry."""
        config = load_config(tmp_config_file)
        config["yara_engine"]["rules_path"] = str(tmp_wannacry_yara)
        scanner = Scanner(config)
        results = scanner.scan_path(tmp_benign_file)
        assert len(results) == 1
        assert results[0].verdict == "benign"

    def test_yara_detects_mutex_string(self, tmp_wannacry_yara):
        """YARA should detect the WannaCry mutex string."""
        from core.yara_engine import YaraEngine

        engine = YaraEngine(rules_path=tmp_wannacry_yara)
        data = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"MsWinZonesCacheCounterMutexA\x00" * 5
        matches = engine.scan_bytes(data)
        rule_names = [m.rule_name for m in matches]
        assert "WannaCry_Mutex" in rule_names

    def test_feature_extraction_entropy(self, tmp_pe_file):
        """Entropy of known PE file should be extractable."""
        features = extract_features(tmp_pe_file)
        assert features is not None
        assert 0.0 <= features["feature_1"] <= 8.0

    def test_pe_analysis_on_mock(self, tmp_pe_file_wannacry_mock):
        """PE analysis on mock WannaCry file should return results."""
        result = analyze(tmp_pe_file_wannacry_mock)
        assert result.is_pe is True

    def test_report_generation(self, tmp_path):
        """Report generator should produce valid CSV and JSON."""
        gen = ReportGenerator(tmp_path)
        results = [
            ScanResult(
                file_path="/test/ransom.exe",
                verdict="wannacry",
                ml_score=0.95,
                pe_suspicion_score=0.7,
                yara_matches=["WannaCry_Mutex"],
                file_size=1024,
                sha256="abc123",
                scan_time="2024-01-01T00:00:00Z",
            ),
            ScanResult(
                file_path="/test/notepad.exe",
                verdict="benign",
                ml_score=0.1,
                pe_suspicion_score=0.0,
                yara_matches=[],
                file_size=2048,
                sha256="def456",
                scan_time="2024-01-01T00:00:00Z",
            ),
        ]

        csv_path = gen.generate_csv(results)
        assert csv_path.exists()
        assert csv_path.stat().st_size > 0

        json_path = gen.generate_json(results)
        assert json_path.exists()
        content = json.loads(json_path.read_text())
        assert content["total_files"] == 2
        assert content["verdicts"]["wannacry"] == 1
        assert content["verdicts"]["benign"] == 1

        summary = gen.generate_summary(results)
        assert summary["total"] == 2
        assert summary["wannacry"] == 1
        assert summary["benign"] == 1
        assert summary["yara_hits"] == 1
