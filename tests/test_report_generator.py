"""Tests for report generator module."""

from pathlib import Path

from core.report_generator import ReportGenerator, ScanResult


class TestReportGenerator:
    def test_generate_csv(self, tmp_path) -> None:
        gen = ReportGenerator(tmp_path)
        results = [
            ScanResult(
                file_path="/test/a.exe",
                verdict="wannacry",
                ml_score=0.9,
                yara_matches=["WannaCry_Mutex"],
            ),
            ScanResult(
                file_path="/test/b.exe",
                verdict="benign",
                ml_score=0.1,
            ),
        ]
        csv_path = gen.generate_csv(results)
        assert csv_path.exists()
        content = csv_path.read_text()
        assert "/test/a.exe" in content
        assert "wannacry" in content

    def test_generate_json(self, tmp_path) -> None:
        gen = ReportGenerator(tmp_path)
        results = [
            ScanResult(file_path="/test/a.exe", verdict="suspicious"),
        ]
        json_path = gen.generate_json(results)
        assert json_path.exists()
        import json
        data = json.loads(json_path.read_text())
        assert data["total_files"] == 1
        assert data["verdicts"]["suspicious"] == 1

    def test_generate_summary(self) -> None:
        gen = ReportGenerator(Path("/tmp"))
        results = [
            ScanResult(file_path="/a", verdict="wannacry", yara_matches=["R1"]),
            ScanResult(file_path="/b", verdict="wannacry", ml_score=0.8, yara_matches=[]),
            ScanResult(file_path="/c", verdict="suspicious"),
            ScanResult(file_path="/d", verdict="benign"),
        ]
        summary = gen.generate_summary(results)
        assert summary["total"] == 4
        assert summary["wannacry"] == 2
        assert summary["suspicious"] == 1
        assert summary["benign"] == 1
        assert summary["yara_hits"] == 1
        assert summary["ml_positives"] == 1

    def test_scan_result_to_dict(self) -> None:
        result = ScanResult(
            file_path="/test/a.exe",
            verdict="benign",
            yara_matches=["Rule1", "Rule2"],
        )
        d = result.to_dict()
        assert d["file_path"] == "/test/a.exe"
        assert d["yara_matches"] == "Rule1,Rule2"
