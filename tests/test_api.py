"""Unit tests for the api module."""

import unittest
from unittest.mock import MagicMock, patch, mock_open
import sys
import os
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from balancer import api
from balancer import logger


class TestApiConnect(unittest.TestCase):
    """Tests for api_connect function."""

    def setUp(self):
        """Set up logging for tests."""
        logger.setup_logging({"logging": {"level": "DEBUG"}})

    @patch("balancer.api.proxmoxer.ProxmoxAPI")
    def test_creates_api_with_config(self, mock_proxmox_api):
        """Should create API with config values."""
        config = {
            "proxmox_api": {
                "host": "proxmox.example.com",
                "port": 443,
                "user": "user@pam",
                "token_id": "my_token",
                "token_secret": "my_secret",
            }
        }
        api_client = api.api_connect(config)
        mock_proxmox_api.assert_called_once_with(
            "proxmox.example.com",
            port=443,
            user="user@pam",
            token_name="my_token",
            token_value="my_secret",
        )

    @patch("balancer.api.proxmoxer.ProxmoxAPI")
    def test_uses_defaults_for_missing_values(self, mock_proxmox_api):
        """Should use default host and port when not specified."""
        config = {
            "proxmox_api": {
                "user": "user@pam",
                "token_id": "my_token",
                "token_secret": "my_secret",
            }
        }
        api_client = api.api_connect(config)
        mock_proxmox_api.assert_called_once_with(
            "localhost",
            port="8006",
            user="user@pam",
            token_name="my_token",
            token_value="my_secret",
        )


class TestValidateApiConnection(unittest.TestCase):
    """Tests for validate_api_connection function."""

    def setUp(self):
        """Set up logging for tests."""
        logger.setup_logging({"logging": {"level": "DEBUG"}})

    def test_valid_connection(self):
        """Should return True when API connection is valid."""
        mock_api = MagicMock()
        mock_api.nodes.return_value = [{"node": "node1", "status": "online"}]
        
        result = api.validate_api_connection(mock_api)
        self.assertTrue(result)
        mock_api.nodes.assert_called_once()

    def test_invalid_connection(self):
        """Should return False when API connection fails."""
        mock_api = MagicMock()
        mock_api.nodes.side_effect = Exception("Connection refused")
        
        result = api.validate_api_connection(mock_api)
        self.assertFalse(result)
        mock_api.nodes.assert_called_once()

    def test_empty_nodes_list(self):
        """Should return True even with empty nodes list."""
        mock_api = MagicMock()
        mock_api.nodes.return_value = []
        
        result = api.validate_api_connection(mock_api)
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
