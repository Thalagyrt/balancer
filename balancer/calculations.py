__author__ = "James P. Riley"
__copyright__ = "Copyright (C) 2025 James P. Riley (@thalagyrt)"
__license__ = "GPL-3.0"

"""Calculation utilities for CPU and memory metrics."""

from statistics import mean

from . import logger
from . import constants


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


def compute_dynamic_memory_threshold(nodes):
    """Compute dynamic memory threshold based on node averages.

    Args:
        nodes: List of node dictionaries.

    Returns:
        float: Dynamic memory threshold value.
    """
    return (
        mean(node_memory_pct(node) for node in nodes)
        * constants.MEMORY_THRESHOLD_MULTIPLIER
    )
