"""Tests for logger configuration and wrapper functions."""

import logging
import unittest
from io import StringIO

from balancer.logger import (
    setup_logging,
    get_logger_or_fail,
    info,
    debug,
    warning,
    error,
    critical,
    _get_default_logger,
)


class TestLoggerSetup(unittest.TestCase):
    """Test setup_logging function."""

    def setUp(self):
        """Reset logging state before each test."""
        # Clear all handlers from root logger
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        # Reset module-level default logger
        from balancer import logger

        logger._default_logger = None

    def tearDown(self):
        """Reset logging state after each test."""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        from balancer import logger

        logger._default_logger = None

    def test_setup_logging_default(self):
        """Test setup_logging with no config uses defaults."""
        result = setup_logging()
        self.assertEqual(result.level, logging.INFO)

    def test_setup_logging_with_config_level(self):
        """Test setup_logging respects config level."""
        config = {"logging": {"level": "DEBUG"}}
        result = setup_logging(config)
        self.assertEqual(result.level, logging.DEBUG)

    def test_setup_logging_invalid_level_uses_default(self):
        """Test setup_logging uses INFO for invalid level."""
        config = {"logging": {"level": "INVALID"}}
        result = setup_logging(config)
        self.assertEqual(result.level, logging.INFO)

    def test_setup_logging_with_format(self):
        """Test setup_logging respects custom format."""
        config = {
            "logging": {
                "level": "INFO",
                "format": "%(levelname)s - %(message)s",
            }
        }
        result = setup_logging(config)
        handler = result.handlers[0]
        self.assertIn("levelname", handler.formatter._fmt)
        self.assertNotIn("asctime", handler.formatter._fmt)

    def test_setup_logging_no_duplicate_handlers(self):
        """Test setup_logging doesn't add duplicate handlers."""
        setup_logging()
        setup_logging()
        root_logger = logging.getLogger()
        self.assertEqual(len(root_logger.handlers), 1)

    def test_setup_logging_without_logging_key(self):
        """Test setup_logging handles config without logging key."""
        config = {"proxmox_api": {"host": "localhost"}}
        result = setup_logging(config)
        self.assertEqual(result.level, logging.INFO)


class TestGetLoggerOrFail(unittest.TestCase):
    """Test get_logger_or_fail function."""

    def setUp(self):
        """Reset logging state before each test."""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        from balancer import logger

        logger._default_logger = None

    def tearDown(self):
        """Reset logging state after each test."""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        from balancer import logger

        logger._default_logger = None

    def test_get_logger_or_fail_raises_when_not_configured(self):
        """Test get_logger_or_fail raises RuntimeError when not configured."""
        with self.assertRaises(RuntimeError) as context:
            get_logger_or_fail("test_logger")
        self.assertIn("not configured", str(context.exception))
        self.assertIn("setup_logging()", str(context.exception))

    def test_get_logger_or_fail_returns_logger_when_configured(self):
        """Test get_logger_or_fail returns logger when configured."""
        setup_logging()
        result = get_logger_or_fail("test_logger")
        self.assertIsInstance(result, logging.Logger)
        self.assertEqual(result.name, "test_logger")

    def test_get_logger_or_fail_returns_root_logger_when_name_none(self):
        """Test get_logger_or_fail returns root logger when name is None."""
        setup_logging()
        result = get_logger_or_fail(None)
        self.assertEqual(result.name, "root")


class TestDefaultLoggerFunctions(unittest.TestCase):
    """Test module-level logging wrapper functions."""

    def setUp(self):
        """Setup logging and capture output."""
        from balancer import logger

        logger._default_logger = None
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        setup_logging({"logging": {"level": "DEBUG"}})
        self.stream = StringIO()
        handler = logging.StreamHandler(self.stream)
        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)

    def tearDown(self):
        """Reset logging state."""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        from balancer import logger

        logger._default_logger = None

    def test_info_logs_message(self):
        """Test info function logs at INFO level."""
        info("test info message")
        self.assertIn("INFO", self.stream.getvalue())
        self.assertIn("test info message", self.stream.getvalue())

    def test_debug_logs_message(self):
        """Test debug function logs at DEBUG level."""
        debug("test debug message")
        self.assertIn("DEBUG", self.stream.getvalue())
        self.assertIn("test debug message", self.stream.getvalue())

    def test_warning_logs_message(self):
        """Test warning function logs at WARNING level."""
        warning("test warning message")
        self.assertIn("WARNING", self.stream.getvalue())
        self.assertIn("test warning message", self.stream.getvalue())

    def test_error_logs_message(self):
        """Test error function logs at ERROR level."""
        error("test error message")
        self.assertIn("ERROR", self.stream.getvalue())
        self.assertIn("test error message", self.stream.getvalue())

    def test_critical_logs_message(self):
        """Test critical function logs at CRITICAL level."""
        critical("test critical message")
        self.assertIn("CRITICAL", self.stream.getvalue())
        self.assertIn("test critical message", self.stream.getvalue())

    def test_info_with_args(self):
        """Test info function supports string formatting."""
        info("test %s with %d args", "format", 2)
        output = self.stream.getvalue()
        self.assertIn("test format with 2 args", output)

    def test_logger_functions_raise_when_not_setup(self):
        """Test logger wrapper functions raise when not configured."""
        # Reset to unconfigured state
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        from balancer import logger

        logger._default_logger = None

        with self.assertRaises(RuntimeError):
            info("should fail")


if __name__ == "__main__":
    unittest.main()
