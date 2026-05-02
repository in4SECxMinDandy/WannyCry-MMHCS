"""Report generation in CSV and JSON formats."""

import csv
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from core.logger_setup import get_logger

logger = get_logger(__name__)


@dataclass
class ScanResult:
    """Result of scanning a single file."""

    file_path: str
    verdict: str
    ml_score: float = 0.0
    pe_suspicion_score: float = 0.0
    yara_matches: list[str] = field(default_factory=list)
    file_size: int = 0
    sha256: str = ""
    scan_time: str = ""

    def to_dict(self) -> dict:
        """Convert to serializable dictionary."""
        d = asdict(self)
        d["yara_matches"] = ",".join(d["yara_matches"])
        return d


class ReportGenerator:
    """Generate scan reports in various formats."""

    def __init__(self, output_dir: Path) -> None:
        """Initialize report generator.

        Args:
            output_dir: Directory for report output.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _generate_filename(self, fmt: str) -> Path:
        """Generate timestamped report filename.

        Args:
            fmt: File extension (without dot).

        Returns:
            Path to report file.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return self.output_dir / f"wannacry_scan_{timestamp}.{fmt}"

    def generate_csv(self, results: list[ScanResult]) -> Path:
        """Generate CSV report.

        Args:
            results: List of scan results.

        Returns:
            Path to generated CSV file.
        """
        filepath = self._generate_filename("csv")
        fieldnames = [
            "file_path", "verdict", "ml_score", "pe_suspicion_score",
            "yara_matches", "file_size", "sha256", "scan_time",
        ]
        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for r in results:
                    writer.writerow(r.to_dict())
            logger.info("CSV report written to %s", filepath)
            return filepath
        except OSError as e:
            logger.error("Failed to write CSV report: %s", e)
            raise

    def generate_json(self, results: list[ScanResult]) -> Path:
        """Generate JSON report.

        Args:
            results: List of scan results.

        Returns:
            Path to generated JSON file.
        """
        filepath = self._generate_filename("json")
        report = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "total_files": len(results),
            "verdicts": {
                "wannacry": sum(1 for r in results if r.verdict == "wannacry"),
                "suspicious": sum(1 for r in results if r.verdict == "suspicious"),
                "benign": sum(1 for r in results if r.verdict == "benign"),
            },
            "results": [r.to_dict() for r in results],
        }
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.info("JSON report written to %s", filepath)
            return filepath
        except OSError as e:
            logger.error("Failed to write JSON report: %s", e)
            raise

    def generate_summary(self, results: list[ScanResult]) -> dict:
        """Generate summary statistics.

        Args:
            results: List of scan results.

        Returns:
            Dictionary with summary stats.
        """
        return {
            "total": len(results),
            "wannacry": sum(1 for r in results if r.verdict == "wannacry"),
            "suspicious": sum(1 for r in results if r.verdict == "suspicious"),
            "benign": sum(1 for r in results if r.verdict == "benign"),
            "yara_hits": sum(1 for r in results if r.yara_matches),
            "ml_positives": sum(1 for r in results if r.ml_score >= 0.7),
        }
