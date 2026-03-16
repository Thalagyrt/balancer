"""Utility functions for the balancer daemon."""

import logger
import proxmoxer
import yaml
import sys
import random
import time
import pandas
from statistics import mean

cpu_usage = {}


def load_config():
    """Load and parse the balancer configuration file.

    Reads 'balancer.yaml' from the current working directory and returns
    the parsed configuration dictionary. Handles YAML parsing errors and
    file not found exceptions by logging a critical error and exiting.

    Returns:
        dict: The parsed configuration dictionary, or exits if loading fails.
    """
    try:
        with open("balancer.yaml", "r") as config_file:
            return yaml.load(config_file, Loader=yaml.FullLoader)
    except (yaml.YAMLError, FileNotFoundError) as e:
        logger.critical(f"Unable to load config: {e}")
        sys.exit(1)


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


def cpu_ema(key, value):
    """Add a new value and return the exponentially weighted moving average.

    Maintains a sliding window of the last 10 measurements per key, then
    computes an exponential moving average with a span of 10 to smooth
    out transient CPU spikes before migration decisions are made.

    Args:
        key: Identifier for the metric (e.g., 'node_mynode' or 'vm_123').
        value: The current CPU usage measurement (percentage as float).

    Returns:
        float: The smoothed CPU usage value using EMA, or 0 if no history exists.
    """
    if key not in cpu_usage:
        cpu_usage[key] = []
    cpu_usage[key].append(value)
    cpu_usage[key] = cpu_usage[key][-10:]
    return float(pandas.DataFrame(cpu_usage[key]).ewm(span=10).mean().iat[-1, -1])


def clamp(n, min_val, max_val):
    """Clamp a value between min and max inclusive.

    Returns the input value n bounded to the range [min_val, max_val].
    If n is less than min_val, returns min_val. If n exceeds max_val,
    returns max_val. Otherwise returns n unchanged.

    Args:
        n: The value to clamp.
        min_val: The lower bound (inclusive).
        max_val: The upper bound (inclusive).

    Returns:
        The clamped value within [min_val, max_val].
    """
    return max(min(n, max_val), min_val)


def workload_cpu_as_host_pct(workload, node):
    """Convert a workload's CPU requirement to percentage of target node's capacity.

    Scales a VM's CPU allocation from its source node's perspective to
    what percentage of the target node's max CPU capacity it would consume.
    This normalizes CPU requirements across hosts with different core counts.

    Args:
        workload: Dictionary containing 'cpu' (workload's CPU shares) and
            'maxcpu' (workload's maximum vCPU allocation).
        node: Node dictionary containing 'maxcpu' (node's maximum CPU cores).

    Returns:
        float: The equivalent CPU percentage of the target node's capacity.
    """
    return workload["cpu"] * workload["maxcpu"] / node["maxcpu"]


def node_cpu_factor(source_node, target_node):
    """Compute the CPU capacity ratio between two nodes.

    Calculates a scaling factor that normalizes CPU metrics across nodes
    with different core counts. This factor is used when evaluating whether
    migrating a VM would appropriately balance load on nodes of varying sizes.

    Args:
        source_node: Source node dictionary with 'maxcpu' (total CPU cores).
        target_node: Target node dictionary with 'maxcpu' (total CPU cores).

    Returns:
        float: The ratio of source maxcpu to target maxcpu. A value > 1
            means the source has more cores; < 1 means fewer cores.
    """
    return source_node["maxcpu"] / target_node["maxcpu"]


def node_memory_pct(node):
    """Compute the memory usage percentage for a node.

    Calculates the ratio of currently used memory to maximum available memory
    for a Proxmox node. This percentage is used throughout the balancer to
    make decisions about which VMs should be migrated based on memory pressure.

    Args:
        node: A node dictionary from the Proxmox API containing 'mem' (current
            memory usage in MB) and 'maxmem' (total available memory in MB).

    Returns:
        float: The memory usage as a decimal fraction (e.g., 0.75 = 75%).
    """
    return node["mem"] / node["maxmem"]
