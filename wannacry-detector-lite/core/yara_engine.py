"""YARA engine wrapper for WannaCry detection."""

from dataclasses import dataclass, field
from pathlib import Path

import yara

from core.logger_setup import get_logger

logger = get_logger(__name__)


@dataclass
class YaraMatch:
    """Single YARA rule match result."""

    rule_name: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, str] = field(default_factory=dict)
    strings_matched: list[str] = field(default_factory=list)


class YaraEngine:
    """Wrapper around yara-python for WannaCry-specific rule matching."""

    def __init__(self, rules_path: Path, compile_on_load: bool = True) -> None:
        """Initialize YARA engine.

        Args:
            rules_path: Path to YARA rules file.
            compile_on_load: Whether to compile rules immediately.

        Raises:
            FileNotFoundError: If rules file does not exist.
            yara.Error: If rules compilation fails.
        """
        self.rules_path = Path(rules_path)
        self._rules: yara.Rules | None = None

        if compile_on_load:
            self.compile()

    def compile(self) -> None:
        """Compile YARA rules from file.

        Raises:
            FileNotFoundError: If rules file does not exist.
            yara.Error: If compilation fails.
        """
        if not self.rules_path.exists():
            raise FileNotFoundError(f"YARA rules file not found: {self.rules_path}")

        try:
            self._rules = yara.compile(filepath=str(self.rules_path))
            logger.info("YARA rules compiled from %s", self.rules_path)
        except yara.Error as e:
            logger.error("Failed to compile YARA rules: %s", e)
            raise

    def is_compiled(self) -> bool:
        """Check if rules are compiled."""
        return self._rules is not None

    def scan_file(self, file_path: Path, timeout: int = 60) -> list[YaraMatch]:
        """Scan a file for WannaCry YARA matches.

        Args:
            file_path: Path to file to scan.
            timeout: Timeout in seconds (default 60).

        Returns:
            List of YaraMatch objects for matching rules.
        """
        if not self._rules:
            logger.warning("YARA rules not compiled, attempting compile...")
            self.compile()

        try:
            matches = self._rules.match(str(file_path), timeout=timeout)
        except yara.TimeoutError:
            logger.warning("YARA scan timed out for %s", file_path)
            return []
        except yara.Error as e:
            logger.error("YARA scan error for %s: %s", file_path, e)
            return []

        results: list[YaraMatch] = []
        for match in matches:
            yara_result = YaraMatch(
                rule_name=match.rule,
                tags=list(match.tags),
                meta=dict(match.meta),
                strings_matched=[s.identifier for s in match.strings],
            )
            results.append(yara_result)
        return results

    def scan_bytes(self, data: bytes, timeout: int = 60) -> list[YaraMatch]:
        """Scan raw bytes for WannaCry YARA matches.

        Args:
            data: Raw bytes to scan.
            timeout: Timeout in seconds.

        Returns:
            List of YaraMatch objects.
        """
        if not self._rules:
            logger.warning("YARA rules not compiled, attempting compile...")
            self.compile()

        try:
            matches = self._rules.match(data=data, timeout=timeout)
        except yara.TimeoutError:
            logger.warning("YARA scan timed out on bytes")
            return []
        except yara.Error as e:
            logger.error("YARA byte scan error: %s", e)
            return []

        results: list[YaraMatch] = []
        for match in matches:
            yara_result = YaraMatch(
                rule_name=match.rule,
                tags=list(match.tags),
                meta=dict(match.meta),
                strings_matched=[s.identifier for s in match.strings],
            )
            results.append(yara_result)
        return results

    def get_rule_count(self) -> int:
        """Return number of compiled rules.

        Returns:
            Number of rules, or 0 if not compiled.
        """
        if not self._rules:
            return 0
        try:
            return len(self._rules)
        except TypeError:
            count = 0
            try:
                for _ in self._rules:
                    count += 1
            except Exception:
                return -1
            return count
