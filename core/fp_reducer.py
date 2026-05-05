"""False positive reducer via whitelist of hashes and paths."""

import hashlib
from pathlib import Path

from core.logger_setup import get_logger

logger = get_logger(__name__)


class FPReducer:
    """Simple whitelist-based false positive reducer."""

    def __init__(
        self,
        whitelist_hashes: list[str] | None = None,
        whitelist_paths: list[str] | None = None,
    ) -> None:
        """Initialize FP reducer.

        Args:
            whitelist_hashes: List of SHA256 hashes to whitelist.
            whitelist_paths: List of path prefixes to whitelist.
        """
        self.whitelist_hashes: set[str] = {h.lower() for h in (whitelist_hashes or [])}
        self.whitelist_paths: list[str] = whitelist_paths or []

    def is_whitelisted_hash(self, file_path: Path) -> bool:
        """Check if file SHA256 is in whitelist.

        Args:
            file_path: Path to file.

        Returns:
            True if hash is whitelisted.
        """
        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            file_hash = sha256.hexdigest().lower()
            if file_hash in self.whitelist_hashes:
                logger.debug("Whitelisted by hash: %s", file_path)
                return True
        except (OSError, PermissionError) as e:
            logger.warning("Cannot hash file %s: %s", file_path, e)
        return False

    def is_whitelisted_path(self, file_path: Path) -> bool:
        """Check if file path starts with a whitelisted prefix.

        Args:
            file_path: Path to file.

        Returns:
            True if path is whitelisted.
        """
        resolved = file_path.resolve()
        for prefix in self.whitelist_paths:
            try:
                if str(resolved).startswith(str(Path(prefix).resolve())):
                    logger.debug("Whitelisted by path: %s", file_path)
                    return True
            except Exception:
                if str(resolved).lower().startswith(prefix.lower()):
                    logger.debug("Whitelisted by path: %s", file_path)
                    return True
        return False

    def is_whitelisted(self, file_path: Path) -> bool:
        """Check both hash and path whitelists.

        Args:
            file_path: Path to file.

        Returns:
            True if file is whitelisted by either method.
        """
        return self.is_whitelisted_path(file_path) or self.is_whitelisted_hash(file_path)
