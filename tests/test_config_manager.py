"""Tests for config manager module."""

import json

import pytest

from core.config_manager import (
    DEFAULT_CONFIG,
    ConfigError,
    get_default_config,
    load_config,
    validate_config,
)


class TestValidateConfig:
    def test_valid_default(self) -> None:
        cfg = get_default_config()
        validate_config(cfg)

    def test_missing_section(self) -> None:
        config = get_default_config()
        del config["scanner"]
        with pytest.raises(ConfigError, match="Missing required config sections"):
            validate_config(config)

    def test_invalid_max_workers(self) -> None:
        config = get_default_config()
        config["scanner"]["max_workers"] = 0
        with pytest.raises(ConfigError, match="max_workers"):
            validate_config(config)

    def test_invalid_threshold_too_low(self) -> None:
        config = get_default_config()
        config["ml_engine"]["threshold"] = 0
        with pytest.raises(ConfigError, match="threshold"):
            validate_config(config)

    def test_invalid_threshold_too_high(self) -> None:
        config = get_default_config()
        config["ml_engine"]["threshold"] = 1.5
        with pytest.raises(ConfigError, match="threshold"):
            validate_config(config)

    def test_negative_file_size(self) -> None:
        config = get_default_config()
        config["scanner"]["max_file_size_mb"] = -1
        with pytest.raises(ConfigError, match="max_file_size_mb"):
            validate_config(config)


class TestLoadConfig:
    def test_load_valid_config(self, tmp_path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(DEFAULT_CONFIG))
        result = load_config(config_path)
        assert result["scanner"]["max_workers"] == 4

    def test_load_missing_file(self, tmp_path) -> None:
        result = load_config(tmp_path / "nonexistent.json")
        assert result["scanner"]["max_workers"] == 4

    def test_load_invalid_json(self, tmp_path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text("{invalid json")
        with pytest.raises(ConfigError, match="Invalid JSON"):
            load_config(config_path)

    def test_load_partial_config(self, tmp_path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"scanner": {"max_workers": 8}}))
        result = load_config(config_path)
        assert result["scanner"]["max_workers"] == 8
        assert result["ml_engine"]["threshold"] == DEFAULT_CONFIG["ml_engine"]["threshold"]


class TestGetDefaultConfig:
    def test_returns_copy(self) -> None:
        cfg1 = get_default_config()
        cfg2 = get_default_config()
        assert cfg1 == cfg2
        assert cfg1 is not cfg2
