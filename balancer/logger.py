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
    # Default configuration
    level = logging.INFO
    fmt = "%(asctime)s - %(levelname)s - %(message)s"

    if config and "logging" in config:
        log_config = config["logging"]

        # Set log level
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

        # Set format
        fmt = log_config.get("format", fmt)

    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(level)

    # Avoid adding handlers multiple times
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


def get_logger(name=None):
    """Get a named logger.

    Args:
        name: Optional logger name. If None, uses __name__ as default.

    Returns:
        A configured logger instance.
    """
    if name is None:
        return logging.getLogger(__name__)
    return logging.getLogger(name)


def debug(message, *args, **kwargs):
    """Log a DEBUG message."""
    logging.debug(message, *args, **kwargs)


def info(message, *args, **kwargs):
    """Log an INFO message."""
    logging.info(message, *args, **kwargs)


def warning(message, *args, **kwargs):
    """Log a WARNING message."""
    logging.warning(message, *args, **kwargs)


def error(message, *args, **kwargs):
    """Log an ERROR message."""
    logging.error(message, *args, **kwargs)


def critical(message, *args, **kwargs):
    """Log a CRITICAL message."""
    logging.critical(message, *args, **kwargs)
