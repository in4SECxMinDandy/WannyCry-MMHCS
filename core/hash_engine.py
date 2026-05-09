"""SHA256 hash database engine for known malware detection."""

from pathlib import Path

from core.logger_setup import get_logger

logger = get_logger(__name__)


class HashEngine:
    """Lookup file SHA256 against a known-malware hash database."""

    def __init__(self, hash_file: Path | None = None) -> None:
        """Initialize hash engine.

        Args:
            hash_file: Path to text file with one SHA256 hash per line.
                       Lines starting with '#' or empty lines are skipped.
        """
        self._hash_file = Path(hash_file) if hash_file else None
        self._hash_set: set[str] | None = None

    def _load_hashes(self) -> set[str]:
        """Load hashes from file into a set for O(1) lookup."""
        if self._hash_set is not None:
            return self._hash_set

        self._hash_set = set()
        if not self._hash_file or not self._hash_file.exists():
            logger.warning("Hash database not found: %s", self._hash_file)
            return self._hash_set

        try:
            with open(self._hash_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    self._hash_set.add(line.lower())
            logger.info(
                "Loaded %d known-malware hashes from %s", len(self._hash_set), self._hash_file
            )
        except OSError as e:
            logger.error("Failed to load hash database: %s", e)

        return self._hash_set

    def is_known_malware(self, sha256_hash: str) -> bool:
        """Check if a SHA256 hash is in the known-malware database.

        Args:
            sha256_hash: Hex SHA256 hash string.

        Returns:
            True if hash is known malware.
        """
        hashes = self._load_hashes()
        if not hashes:
            return False
        return sha256_hash.lower() in hashes

    def get_hash_count(self) -> int:
        """Return number of hashes loaded."""
        return len(self._load_hashes())
