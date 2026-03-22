__author__ = "James P. Riley"
__copyright__ = "Copyright (C) 2025 James P. Riley (@thalagyrt)"
__license__ = "GPL-3.0"

"""Configuration loading and validation utilities."""

from . import logger
import yaml
import sys


def load_config(config_path="balancer.yaml"):
    """Load and parse the balancer configuration file.

    Reads the configuration file and returns the parsed configuration
    dictionary. Handles YAML parsing errors and file not found exceptions
    by logging a critical error and exiting.

    Args:
        config_path: Path to the configuration file (default: "balancer.yaml").

    Returns:
        dict: The parsed configuration dictionary, or exits if loading fails.
    """
    try:
        with open(config_path, "r") as config_file:
            return yaml.load(config_file, Loader=yaml.FullLoader)
    except (yaml.YAMLError, FileNotFoundError) as e:
        logger.critical(f"Unable to load config: {e}")
        sys.exit(1)


def validate_config(config):
    """Validate the configuration dictionary has required sections.

    Checks that the configuration contains all required sections and keys
    needed for the balancer to operate correctly.

    Args:
        config: The parsed configuration dictionary.

    Returns:
        tuple: (is_valid, errors) where is_valid is a boolean and errors
            is a list of error message strings.
    """
    errors = []

    # Check proxmox_api section
    if "proxmox_api" not in config:
        errors.append("Missing 'proxmox_api' section in config")
    else:
        api_config = config["proxmox_api"]
        required_api_keys = ["host", "port", "user", "token_id", "token_secret"]
        for key in required_api_keys:
            if key not in api_config:
                errors.append(f"Missing '{key}' in proxmox_api section")

    # Check balancer section
    if "balancer" not in config:
        errors.append("Missing 'balancer' section in config")
    else:
        balancer_config = config["balancer"]
        required_balancer_keys = ["memory_max", "cpu_max"]
        for key in required_balancer_keys:
            if key not in balancer_config:
                errors.append(f"Missing '{key}' in balancer section")

    # Check logging section
    if "logging" not in config:
        errors.append("Missing 'logging' section in config")
    else:
        logging_config = config["logging"]
        if "level" not in logging_config:
            errors.append("Missing 'level' in logging section")

    return len(errors) == 0, errors
