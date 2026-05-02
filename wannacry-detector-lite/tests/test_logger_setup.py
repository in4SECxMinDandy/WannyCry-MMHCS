"""Tests for logger setup module."""

import logging

from core.logger_setup import enable_debug, get_logger, setup_logging


class TestLoggerSetup:
    def test_setup_logging_default(self) -> None:
        setup_logging()
        root = logging.getLogger()
        assert len(root.handlers) >= 1

    def test_setup_logging_with_file(self, tmp_path) -> None:
        root = logging.getLogger()
        root.handlers.clear()
        log_file = tmp_path / "test.log"
        setup_logging(log_file=log_file)
        logger = get_logger(__name__)
        logger.info("test message")
        for handler in root.handlers:
            handler.flush()
        assert log_file.exists()
        content = log_file.read_text()
        assert "test message" in content

    def test_get_logger(self) -> None:
        logger = get_logger("test_module")
        assert logger.name == "test_module"

    def test_enable_debug(self) -> None:
        setup_logging(level=logging.INFO)
        enable_debug()
        root = logging.getLogger()
        assert root.level == logging.DEBUG

    def test_setup_logging_idempotent(self) -> None:
        root = logging.getLogger()
        root.handlers.clear()
        setup_logging()
        handlers_before = len(root.handlers)
        setup_logging()
        handlers_after = len(root.handlers)
        assert handlers_before == handlers_after
