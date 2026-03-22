from .config import load_config, validate_config
from .ema import CpuEMA
from .balancer import migrate_workload
from . import logger
from . import api
import proxmoxer
import sys
import time


def main():
    """Main entry point for the balancer daemon.

    Loads configuration, validates it, sets up logging, then enters an event
    loop that checks for workload imbalances and migrates VMs as needed.

    Runs indefinitely until the process is terminated externally.

    Returns:
        None (runs as long-lived daemon loop).
    """
    config = load_config()
    
    # Validate configuration before starting
    is_valid, errors = validate_config(config)
    if not is_valid:
        logger.critical("Configuration validation failed:")
        for error in errors:
            logger.critical(f"  - {error}")
        return
    
    logger.setup_logging(config)
    logger.info("Starting up.")

    # Validate API connection at startup
    try:
        api_client = api.api_connect(config)
        if not api.validate_api_connection(api_client):
            logger.critical("Failed to connect to Proxmox API. Exiting.")
            sys.exit(1)
    except Exception as e:
        logger.critical(f"Failed to connect to Proxmox API: {e}. Exiting.")
        sys.exit(1)

    cpu_ema = CpuEMA()

    while True:
        try:
            migrate_workload(config, cpu_ema, api_client)
        except proxmoxer.core.ResourceException as e:
            logger.error(f"API error during migration cycle: {e}")
        time.sleep(5)


if __name__ == "__main__":
    main()
