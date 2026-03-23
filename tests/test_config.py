"""Unit tests for the config module."""

import unittest
from unittest.mock import MagicMock, patch, mock_open
import sys
import os
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from balancer import config
from balancer import logger


class TestLoadConfig(unittest.TestCase):
    """Tests for load_config function."""

    def setUp(self):
        """Set up logging for tests."""
        logger.setup_logging({"logging": {"level": "DEBUG"}})

    def test_loads_valid_yaml(self):
        """Should load and parse valid YAML config."""
        yaml_content = """
proxmox_api:
  host: "localhost"
  port: 8006
  user: "user@pam"
  token_id: "test_token"
  token_secret: "secret123"
balancer:
  cpu_max: 0.8
  memory_max: 0.8
logging:
  level: INFO
"""
        with patch("builtins.open", mock_open(read_data=yaml_content)):
            cfg = config.load_config()
            self.assertEqual(cfg["proxmox_api"]["host"], "localhost")
            self.assertEqual(cfg["balancer"]["cpu_max"], 0.8)

    def test_loads_with_custom_path(self):
        """Should load config from custom path."""
        yaml_content = """
proxmox_api:
  host: "custom.example.com"
"""
        with patch("builtins.open", mock_open(read_data=yaml_content)) as mock_file:
            cfg = config.load_config("/path/to/custom.yaml")
            mock_file.assert_called_once_with("/path/to/custom.yaml", "r")
            self.assertEqual(cfg["proxmox_api"]["host"], "custom.example.com")

    def test_file_not_found(self):
        """Should exit when config file not found."""
        with patch("builtins.open", side_effect=FileNotFoundError("No such file")):
            with self.assertRaises(SystemExit):
                config.load_config()

    def test_invalid_yaml(self):
        """Should exit when YAML is invalid."""
        yaml_content = "invalid: yaml: content: ["
        with patch("builtins.open", mock_open(read_data=yaml_content)):
            with self.assertRaises(SystemExit):
                config.load_config()


class TestValidateConfig(unittest.TestCase):
    """Tests for validate_config function."""

    def setUp(self):
        """Set up logging for tests."""
        logger.setup_logging({"logging": {"level": "DEBUG"}})

    def test_valid_config(self):
        """Should return True for valid config."""
        config_dict = {
            "proxmox_api": {
                "host": "localhost",
                "port": 8006,
                "user": "user@pam",
                "token_id": "my_token",
                "token_secret": "my_secret",
            },
            "balancer": {
                "cpu_max": 0.8,
                "memory_max": 0.8,
            },
            "logging": {
                "level": "INFO",
            },
        }
        is_valid, errors = config.validate_config(config_dict)
        self.assertTrue(is_valid)
        self.assertEqual(errors, [])

    def test_missing_proxmox_api_section(self):
        """Should report error when proxmox_api section is missing."""
        config_dict = {}
        is_valid, errors = config.validate_config(config_dict)
        self.assertFalse(is_valid)
        self.assertEqual(len(errors), 3)
        self.assertIn("proxmox_api", errors[0])
        self.assertIn("balancer", errors[1])
        self.assertIn("logging", errors[2])

    def test_missing_host(self):
        """Should report error when host is missing."""
        config_dict = {
            "proxmox_api": {
                "port": 8006,
                "user": "user@pam",
                "token_id": "my_token",
                "token_secret": "my_secret",
            },
            "balancer": {
                "cpu_max": 0.8,
                "memory_max": 0.8,
            },
            "logging": {
                "level": "INFO",
            },
        }
        is_valid, errors = config.validate_config(config_dict)
        self.assertFalse(is_valid)
        self.assertEqual(len(errors), 1)
        self.assertIn("host", errors[0])

    def test_missing_port(self):
        """Should report error when port is missing."""
        config_dict = {
            "proxmox_api": {
                "host": "localhost",
                "user": "user@pam",
                "token_id": "my_token",
                "token_secret": "my_secret",
            },
            "balancer": {
                "cpu_max": 0.8,
                "memory_max": 0.8,
            },
            "logging": {
                "level": "INFO",
            },
        }
        is_valid, errors = config.validate_config(config_dict)
        self.assertFalse(is_valid)
        self.assertEqual(len(errors), 1)
        self.assertIn("port", errors[0])

    def test_missing_user(self):
        """Should report error when user is missing."""
        config_dict = {
            "proxmox_api": {
                "host": "localhost",
                "port": 8006,
                "token_id": "my_token",
                "token_secret": "my_secret",
            },
            "balancer": {
                "cpu_max": 0.8,
                "memory_max": 0.8,
            },
            "logging": {
                "level": "INFO",
            },
        }
        is_valid, errors = config.validate_config(config_dict)
        self.assertFalse(is_valid)
        self.assertEqual(len(errors), 1)
        self.assertIn("user", errors[0])

    def test_missing_token_id(self):
        """Should report error when token_id is missing."""
        config_dict = {
            "proxmox_api": {
                "host": "localhost",
                "port": 8006,
                "user": "user@pam",
                "token_secret": "my_secret",
            },
            "balancer": {
                "cpu_max": 0.8,
                "memory_max": 0.8,
            },
            "logging": {
                "level": "INFO",
            },
        }
        is_valid, errors = config.validate_config(config_dict)
        self.assertFalse(is_valid)
        self.assertEqual(len(errors), 1)
        self.assertIn("token_id", errors[0])

    def test_missing_token_secret(self):
        """Should report error when token_secret is missing."""
        config_dict = {
            "proxmox_api": {
                "host": "localhost",
                "port": 8006,
                "user": "user@pam",
                "token_id": "my_token",
            },
            "balancer": {
                "cpu_max": 0.8,
                "memory_max": 0.8,
            },
            "logging": {
                "level": "INFO",
            },
        }
        is_valid, errors = config.validate_config(config_dict)
        self.assertFalse(is_valid)
        self.assertEqual(len(errors), 1)
        self.assertIn("token_secret", errors[0])

    def test_missing_balancer_section(self):
        """Should report error when balancer section is missing."""
        config_dict = {
            "proxmox_api": {
                "host": "localhost",
                "port": 8006,
                "user": "user@pam",
                "token_id": "my_token",
                "token_secret": "my_secret",
            },
            "logging": {
                "level": "INFO",
            },
        }
        is_valid, errors = config.validate_config(config_dict)
        self.assertFalse(is_valid)
        self.assertEqual(len(errors), 1)
        self.assertIn("balancer", errors[0])

    def test_missing_memory_max(self):
        """Should report error when memory_max is missing."""
        config_dict = {
            "proxmox_api": {
                "host": "localhost",
                "port": 8006,
                "user": "user@pam",
                "token_id": "my_token",
                "token_secret": "my_secret",
            },
            "balancer": {
                "cpu_max": 0.8,
            },
            "logging": {
                "level": "INFO",
            },
        }
        is_valid, errors = config.validate_config(config_dict)
        self.assertFalse(is_valid)
        self.assertEqual(len(errors), 1)
        self.assertIn("memory_max", errors[0])

    def test_missing_cpu_max(self):
        """Should report error when cpu_max is missing."""
        config_dict = {
            "proxmox_api": {
                "host": "localhost",
                "port": 8006,
                "user": "user@pam",
                "token_id": "my_token",
                "token_secret": "my_secret",
            },
            "balancer": {
                "memory_max": 0.8,
            },
            "logging": {
                "level": "INFO",
            },
        }
        is_valid, errors = config.validate_config(config_dict)
        self.assertFalse(is_valid)
        self.assertEqual(len(errors), 1)
        self.assertIn("cpu_max", errors[0])

    def test_missing_logging_section(self):
        """Should report error when logging section is missing."""
        config_dict = {
            "proxmox_api": {
                "host": "localhost",
                "port": 8006,
                "user": "user@pam",
                "token_id": "my_token",
                "token_secret": "my_secret",
            },
            "balancer": {
                "cpu_max": 0.8,
                "memory_max": 0.8,
            },
        }
        is_valid, errors = config.validate_config(config_dict)
        self.assertFalse(is_valid)
        self.assertEqual(len(errors), 1)
        self.assertIn("logging", errors[0])

    def test_missing_logging_level(self):
        """Should report error when logging level is missing."""
        config_dict = {
            "proxmox_api": {
                "host": "localhost",
                "port": 8006,
                "user": "user@pam",
                "token_id": "my_token",
                "token_secret": "my_secret",
            },
            "balancer": {
                "cpu_max": 0.8,
                "memory_max": 0.8,
            },
            "logging": {},
        }
        is_valid, errors = config.validate_config(config_dict)
        self.assertFalse(is_valid)
        self.assertEqual(len(errors), 1)
        self.assertIn("level", errors[0])

    def test_multiple_missing_fields(self):
        """Should report all missing fields."""
        config_dict = {
            "proxmox_api": {
                "host": "localhost",
            }
        }
        is_valid, errors = config.validate_config(config_dict)
        self.assertFalse(is_valid)
        self.assertEqual(len(errors), 6)

    def test_config_with_all_sections(self):
        """Should accept config with all sections and fields."""
        config_dict = {
            "proxmox_api": {
                "host": "proxmox.example.com",
                "port": 443,
                "user": "user@pam",
                "token_id": "my_token",
                "token_secret": "my_secret",
            },
            "balancer": {
                "cpu_max": 0.8,
                "memory_max": 0.8,
            },
            "logging": {
                "level": "INFO",
            },
        }
        is_valid, errors = config.validate_config(config_dict)
        self.assertTrue(is_valid)
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
