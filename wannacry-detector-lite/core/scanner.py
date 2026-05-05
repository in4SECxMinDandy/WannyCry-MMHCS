"""Main scanner pipeline: walk directory, analyze files, produce verdicts."""

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from core.feature_extractor import extract_features
from core.fp_reducer import FPReducer
from core.logger_setup import get_logger
from core.ml_engine import MLEngine
from core.pe_analyzer import analyze as pe_analyze
from core.report_generator import ScanResult
from core.yara_engine import YaraEngine

logger = get_logger(__name__)


class Scanner:
    """Orchestrates the 3-layer detection pipeline: ML + PE + YARA."""

    def __init__(self, config: dict) -> None:
        """Initialize scanner with configuration.

        Args:
            config: Validated configuration dictionary from config_manager.
        """
        self.scanner_cfg = config["scanner"]
        self.ml_cfg = config["ml_engine"]
        self.pe_cfg = config["pe_analyzer"]
        self.yara_cfg = config["yara_engine"]

        self.extensions: set[str] = {
            ext.lower() if ext.startswith(".") else f".{ext.lower()}"
            for ext in self.scanner_cfg["scan_extensions"]
        }
        self.max_file_size: int = int(self.scanner_cfg["max_file_size_mb"]) * 1024 * 1024
        self.max_workers: int = self.scanner_cfg["max_workers"]

        self.fp_reducer = FPReducer(
            whitelist_hashes=self.scanner_cfg.get("whitelist_hashes", []),
            whitelist_paths=self.scanner_cfg.get("whitelist_paths", []),
        )

        self.ml_engine: MLEngine | None = None
        model_path = Path(self.ml_cfg["model_path"])
        if model_path.exists():
            try:
                self.ml_engine = MLEngine(
                    model_path=model_path,
                    threshold=self.ml_cfg["threshold"],
                )
            except Exception as e:
                logger.warning("ML engine unavailable: %s", e)
        else:
            logger.info("No ML model found at %s — ML layer disabled", model_path)

        self.yara_engine: YaraEngine | None = None
        yara_cfg = self.yara_cfg

        # Build list of YARA rule file paths
        rules_paths: list[Path] = []
        if "rules_files" in yara_cfg and "rules_dir" in yara_cfg:
            rules_dir = Path(yara_cfg["rules_dir"])
            for fname in yara_cfg["rules_files"]:
                rp = rules_dir / fname
                if rp.exists():
                    rules_paths.append(rp)
                else:
                    logger.warning("YARA rules file not found: %s", rp)
        elif "rules_path" in yara_cfg:
            # Legacy single-file config
            rp = Path(yara_cfg["rules_path"])
            if rp.exists():
                rules_paths.append(rp)

        if rules_paths:
            try:
                self.yara_engine = YaraEngine(
                    rules_paths=rules_paths,
                    compile_on_load=yara_cfg.get("compile_on_load", True),
                )
            except Exception as e:
                logger.warning("YARA engine unavailable: %s", e)
        else:
            logger.info("No YARA rules found — YARA layer disabled")

    def _should_scan(self, file_path: Path) -> bool:
        """Check if a file should be scanned.

        Args:
            file_path: File to check.

        Returns:
            True if file should be scanned.
        """
        if not file_path.is_file():
            return False
        if file_path.suffix.lower() not in self.extensions:
            return False
        try:
            if file_path.stat().st_size > self.max_file_size:
                logger.debug("Skipping large file: %s", file_path)
                return False
        except OSError:
            return False
        if self.fp_reducer.is_whitelisted(file_path):
            return False
        return True

    def _walk_directory(self, scan_path: Path) -> list[Path]:
        """Collect files to scan from directory.

        Args:
            scan_path: Path to directory or file.

        Returns:
            List of file paths to scan.
        """
        scan_path = Path(scan_path)
        if scan_path.is_file():
            return [scan_path] if self._should_scan(scan_path) else []

        files: list[Path] = []
        if self.scanner_cfg.get("recursive", True):
            for ext in self.extensions:
                files.extend(scan_path.rglob(f"*{ext}"))
        else:
            for item in scan_path.iterdir():
                if item.is_file() and item.suffix.lower() in self.extensions:
                    files.append(item)

        files = [f for f in files if self._should_scan(f)]
        return sorted(files)

    def _analyze_file(self, file_path: Path) -> ScanResult:
        """Run full detection pipeline on a single file.

        Args:
            file_path: Path to file to analyze.

        Returns:
            ScanResult with verdict and metadata.
        """
        result = ScanResult(
            file_path=str(file_path.resolve()),
            verdict="benign",
            scan_time=datetime.now(timezone.utc).isoformat(),
        )

        try:
            file_stat = file_path.stat()
            result.file_size = file_stat.st_size
        except OSError:
            pass

        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            result.sha256 = sha256.hexdigest()
        except (OSError, PermissionError):
            result.verdict = "error"
            return result

        ml_label = "benign"
        ml_score = 0.0
        if self.ml_engine:
            features = extract_features(file_path)
            if features:
                try:
                    ml_label, ml_score = self.ml_engine.predict(features)
                except Exception as e:
                    logger.debug("ML predict failed for %s: %s", file_path, e)
            result.ml_score = ml_score

        pe_result = pe_analyze(file_path)
        result.pe_suspicion_score = pe_result.suspicion_score

        yara_matches: list[str] = []
        if self.yara_engine:
            try:
                matches = self.yara_engine.scan_file(file_path)
                yara_matches = [m.rule_name for m in matches]
            except Exception as e:
                logger.debug("YARA scan failed for %s: %s", file_path, e)
        result.yara_matches = yara_matches

        verdict = _combine_verdict(
            ml_label=ml_label,
            ml_score=ml_score,
            ml_threshold=self.ml_cfg["threshold"],
            pe_score=pe_result.suspicion_score,
            yara_matches=yara_matches,
        )
        result.verdict = verdict

        if verdict != "benign":
            logger.info(
                "Detection: %s | verdict=%s | ml=%.3f | pe=%.2f | yara=%s",
                file_path.name,
                verdict,
                ml_score,
                pe_result.suspicion_score,
                yara_matches,
            )

        return result

    def scan_path(self, path: str | Path) -> list[ScanResult]:
        """Scan a file or directory for WannaCry indicators.

        Args:
            path: Path to file or directory.

        Returns:
            List of ScanResult objects.
        """
        target = Path(path)
        if not target.exists():
            logger.error("Path does not exist: %s", target)
            return []

        files = self._walk_directory(target)
        if not files:
            logger.info("No files to scan in %s", target)
            return []

        logger.info("Scanning %d file(s) in %s", len(files), target)
        start_time = time.monotonic()

        results: list[ScanResult] = []

        if self.max_workers <= 1:
            for file_path in files:
                results.append(self._analyze_file(file_path))
        else:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_map = {
                    executor.submit(self._analyze_file, fp): fp for fp in files
                }
                for future in as_completed(future_map):
                    try:
                        results.append(future.result())
                    except Exception as e:
                        fp = future_map[future]
                        logger.error("Error scanning %s: %s", fp, e)
                        results.append(ScanResult(
                            file_path=str(fp),
                            verdict="error",
                            scan_time=datetime.now(timezone.utc).isoformat(),
                        ))

        elapsed = time.monotonic() - start_time
        logger.info("Scan complete: %d files in %.2fs", len(results), elapsed)
        return results


def _combine_verdict(
    ml_label: str,
    ml_score: float,
    ml_threshold: float,
    pe_score: float,
    yara_matches: list[str],
) -> str:
    """Combine signals from all detection layers into a final verdict.

    Args:
        ml_label: Label from ML engine.
        ml_score: Confidence score from ML.
        ml_threshold: ML threshold from config.
        pe_score: Suspicion score from PE analyzer.
        yara_matches: List of matching YARA rule names.

    Returns:
        Final verdict: "wannacry", "blackcat", "suspicious", or "benign".
    """
    if yara_matches:
        # Check which family the YARA rules belong to
        has_blackcat = any(m.startswith("BlackCat") for m in yara_matches)
        has_wannacry = any(m.startswith("WannaCry") for m in yara_matches)
        if has_blackcat:
            return "blackcat"
        if has_wannacry:
            return "wannacry"
        # Generic YARA match — still suspicious
        return "suspicious"

    if ml_label == "blackcat" and ml_score >= ml_threshold:
        if pe_score >= 0.3:
            return "blackcat"
        return "suspicious"

    if ml_label == "wannacry" and ml_score >= ml_threshold:
        if pe_score >= 0.3:
            return "wannacry"
        return "suspicious"

    if pe_score >= 0.6:
        return "suspicious"

    if ml_score >= ml_threshold * 0.8:
        return "suspicious"

    return "benign"
