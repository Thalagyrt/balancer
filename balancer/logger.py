__author__ = "James P. Riley"
__copyright__ = "Copyright (C) 2025 James P. Riley (@thalagyrt)"
__license__ = "GPL-3.0"

"""Logging configuration and logger factory for the balancer daemon."""

import logging


def setup_logging(config=None):
    """Set up logging configuration.

    Configures basic logging with timestamp, log level, and format.
    If config is provided, extracts logging settings from it.

    Args:
        config: Optional configuration dictionary containing a 'logging' section
            with keys for 'level', 'format', and optionally 'handlers'.

    Returns:
        The root logger that was configured.
    """
    level = logging.INFO
    fmt = "%(asctime)s - %(levelname)s - %(message)s"

    if config and "logging" in config:
        log_config = config["logging"]

        level_map = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL,
        }
        level_str = log_config.get("level", "INFO")
        if level_str in level_map:
            level = level_map[level_str]

        fmt = log_config.get("format", fmt)

    logger = logging.getLogger()
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


def get_logger_or_fail(name=None):
    """Get a named logger that will fail if the logger wasn't configured.

    This is a defensive variant that raises an exception if the logger
    wasn't set up via setup_logging(), making misconfigurations obvious.

    Args:
        name: Optional logger name. If None, uses __name__ as default.

    Returns:
        A configured logger instance.

    Raises:
        RuntimeError: If the logger wasn't configured via setup_logging().
    """
    logger = logging.getLogger(name)
    has_handlers = logger.handlers or (
        logger.parent is not None and logger.parent.handlers
    )
    if not has_handlers:
        raise RuntimeError(
            f"Logger '{name}' is not configured. Call setup_logging() first."
        )
    return logger


_default_logger = None


def _get_default_logger():
    """Get the module-level default logger."""
    global _default_logger
    if _default_logger is None:
        _default_logger = get_logger_or_fail()
    return _default_logger


def info(message, *args, **kwargs):
    """Log an INFO message using the default logger."""
    _get_default_logger().info(message, *args, **kwargs)


def debug(message, *args, **kwargs):
    """Log a DEBUG message using the default logger."""
    _get_default_logger().debug(message, *args, **kwargs)


def warning(message, *args, **kwargs):
    """Log a WARNING message using the default logger."""
    _get_default_logger().warning(message, *args, **kwargs)


def error(message, *args, **kwargs):
    """Log an ERROR message using the default logger."""
    _get_default_logger().error(message, *args, **kwargs)


def critical(message, *args, **kwargs):
    """Log a CRITICAL message using the default logger."""
    _get_default_logger().critical(message, *args, **kwargs)
