__author__ = "James P. Riley"
__copyright__ = "Copyright (C) 2025 James P. Riley (@thalagyrt)"
__license__ = "GPL-3.0"

"""API connection utilities for Proxmox."""

from . import logger
import proxmoxer
import sys


def api_connect(config):
    """Create and return a Proxmox API connection.

    Builds a proxmoxer.ProxmoxAPI client using credentials and settings
    from the provided config dictionary. Uses sensible defaults for host
    and port if not specified in the configuration.

    Args:
        config: Dictionary containing 'proxmox_api' section with keys for
            host, port, user, token_id, and token_secret.

    Returns:
        proxmoxer.ProxmoxAPI: A configured Proxmox API client instance.
    """
    api = proxmoxer.ProxmoxAPI(
        config.get("proxmox_api").get("host", "localhost"),
        port=config.get("proxmox_api").get("port", "8006"),
        user=config.get("proxmox_api").get("user"),
        token_name=config.get("proxmox_api").get("token_id"),
        token_value=config.get("proxmox_api").get("token_secret"),
    )
    return api


def validate_api_connection(api):
    """Validate that the Proxmox API connection is working.

    Attempts to access the nodes endpoint to verify the API is reachable
    and authenticated correctly.

    Args:
        api: A proxmoxer.ProxmoxAPI client instance.

    Returns:
        bool: True if connection is valid, False otherwise.
    """
    try:
        list(api.nodes.get())
        return True
    except Exception as e:
        logger.error(f"API connection validation failed: {e}")
        return False
