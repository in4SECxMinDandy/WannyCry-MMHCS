"""Configuration manager with JSON schema validation."""

import copy
import json
from pathlib import Path
from typing import Any

from core.logger_setup import get_logger

logger = get_logger(__name__)

DEFAULT_CONFIG = {
    "scanner": {
        "max_workers": 4,
        "recursive": True,
        "scan_extensions": [".exe", ".dll", ".sys", ".bin"],
        "max_file_size_mb": 100,
        "whitelist_hashes": [],
        "whitelist_paths": [],
    },
    "ml_engine": {
        "model_path": "models/wannacry_rf.pkl",
        "threshold": 0.7,
        "feature_count": 16,
    },
    "pe_analyzer": {
        "check_packer": True,
        "check_imports": True,
        "min_sections": 3,
    },
    "yara_engine": {
        "rules_dir": "rules",
        "rules_files": ["wannacry.yar", "blackcat.yar"],
        "compile_on_load": True,
    },
    "report": {
        "output_dir": "reports",
        "formats": ["csv", "json"],
        "include_metadata": True,
    },
}

REQUIRED_KEYS = {"scanner", "ml_engine", "pe_analyzer", "yara_engine", "report"}


class ConfigError(Exception):
    """Configuration validation error."""


def validate_config(config: dict[str, Any]) -> None:
    """Validate configuration structure against expected schema.

    Args:
        config: Configuration dictionary to validate.

    Raises:
        ConfigError: If required keys are missing or types are wrong.
    """
    missing = REQUIRED_KEYS - set(config.keys())
    if missing:
        raise ConfigError(f"Missing required config sections: {missing}")

    if not isinstance(config["scanner"]["max_workers"], int) or config["scanner"]["max_workers"] < 1:
        raise ConfigError("scanner.max_workers must be positive integer")
    max_fs = config["scanner"]["max_file_size_mb"]
    if not isinstance(max_fs, (int, float)) or max_fs <= 0:
        raise ConfigError("scanner.max_file_size_mb must be positive number")
    threshold = config["ml_engine"]["threshold"]
    if not isinstance(threshold, (int, float)) or not 0 < threshold <= 1:
        raise ConfigError("ml_engine.threshold must be in (0, 1]")


def load_config(config_path: Path) -> dict[str, Any]:
    """Load and validate configuration from JSON file.

    Args:
        config_path: Path to config.json file.

    Returns:
        Validated configuration dictionary.

    Raises:
        FileNotFoundError: If config file does not exist.
        ConfigError: If config fails validation.
    """
    config_path = Path(config_path)
    if not config_path.exists():
        logger.warning("Config file not found at %s, using defaults", config_path)
        return dict(DEFAULT_CONFIG)

    try:
        with open(config_path, encoding="utf-8") as f:
            config = json.load(f)
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in config file: %s", e)
        raise ConfigError(f"Invalid JSON in config: {e}") from e

    merged = copy.deepcopy(DEFAULT_CONFIG)
    for section in REQUIRED_KEYS:
        if section in config:
            merged[section].update(config[section])

    validate_config(merged)
    logger.info("Configuration loaded from %s", config_path)
    return merged


def get_default_config() -> dict[str, Any]:
    """Return the default configuration dictionary."""
    return copy.deepcopy(DEFAULT_CONFIG)
