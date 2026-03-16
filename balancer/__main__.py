import utils
from balancer import migrate_workload
import logger
import time

def main():
    """Main entry point for the balancer daemon.

    Loads configuration, sets up logging, then enters an event loop that:
    - Checks if workload balancing is needed (CPU/memory overloaded or proactive)
    - Attempts to migrate a VM if beneficial
    - Sleeps 25 seconds after successful migration to allow it to complete
    - Sleeps 5 seconds between iterations regardless of outcome

    Runs indefinitely until the process is terminated externally.

    Returns:
        None (runs as long-lived daemon loop).
    """
    config = utils.load_config()
    logger.setup_logging(config)
    logger.info("Starting up.")
    while True:
        if migrate_workload(config):
            time.sleep(25)
        time.sleep(5)


if __name__ == "__main__":
    main()
