__author__ = "James P. Riley"
__copyright__ = "Copyright (C) 2025 James P. Riley (@thalagyrt)"
__license__ = "GPL-3.0"

import logger
import proxmoxer
import yaml
import sys
import random
import time
import pandas
from statistics import mean
import utils

def migrate_workload(config):
    """Attempt to balance workloads by migrating a VM from overloaded to underutilized node.

    Performs the following steps in order:
    1. Connect to Proxmox API using configuration credentials
    2. Check for upcoming backup jobs and pause if one runs within 60 seconds
    3. Fetch all nodes, filtering to only online ones
    4. Parse CPU/memory thresholds from config (with sensible defaults)
    5. Compute dynamic memory threshold based on current node averages
    6. For each node, compute exponential moving average of CPU usage
    7. Determine if migration is needed and in what mode (CPU/memory balancing)
    8. Identify source (overloaded) and target nodes sorted by utilization
    9. Fetch all VM resources and filter to candidates on the source node
    10. Exclude locked (migrating) VMs from consideration
    11. Apply mode-specific sorting to exclude highest-utilization candidates when in CPU mode
    12. Shuffle candidates for non-deterministic migration order
    13. For each candidate, apply all constraint filters:
        - Memory max limit constraint
        - CPU max limit constraint
        - Memory balance (mem mode only)
        - CPU balance (cpu mode only)
        - HA rules (affinity/anti-affinity)
    14. Select the target with lowest utilization for the current mode
    15. Execute migration via Proxmox API

    Args:
        config: Configuration dictionary loaded from balancer.yaml, containing
            'proxmox_api' credentials and 'balancer' thresholds section.

    Returns:
        bool: True if a VM was successfully migrated, False otherwise.
               Returns False early if no balancing needed or no viable candidates.

    Raises:
        Exception: Any exception from proxmoxer.API calls will propagate.
        Program exits with sys.exit(1) on config load failure.
    """

    api = utils.api_connect(config)

    backup_jobs = api.cluster.backup.get()
    run_times = [job["next-run"] for job in backup_jobs if job["enabled"] == 1]
    if run_times:
        next_run = min(run_times)
        if next_run - time.time() < 60:
            logger.debug(
                "A backup job is scheduled in the next minute, pausing for 90 seconds"
            )
            time.sleep(90)
            return False

    nodes = api.nodes.get()

    nodes = [node for node in nodes if node["status"] == "online"]

    cpu_max = utils.clamp(config.get("balancer").get("cpu_max", 0.8), 0.5, 0.9)
    memory_max = utils.clamp(config.get("balancer").get("memory_max", 0.8), 0.5, 0.9)

    memory_threshold = mean(utils.node_memory_pct(node) for node in nodes) * 1.05
    logger.debug(f"Setting memory thresehold to {memory_threshold}")

    for node in nodes:
        node["cpu"] = utils.cpu_ema(f'node_{node["node"]}', node["cpu"])

    if any(node["cpu"] > cpu_max for node in nodes):
        logger.debug(f"A node is over the CPU maximum of {cpu_max}%")
        mode = "cpu"
        reason = "CPU maximum exceeded"
    elif any(utils.node_memory_pct(node) > memory_max for node in nodes):
        logger.debug(f"A node is over the memory maximum of {memory_max}%")
        mode = "mem"
        reason = "Memory maximum exceeded"
    elif any(utils.node_memory_pct(node) > memory_threshold for node in nodes):
        logger.debug(f"A node is over the memory threshold of {memory_threshold}")
        mode = "mem"
        reason = "Proactive balancing"
    else:
        logger.debug(f"No balancing is necessary")
        return False

    if mode == "mem":
        nodes = sorted(nodes, key=lambda node: utils.node_memory_pct(node), reverse=True)
    elif mode == "cpu":
        nodes = sorted(nodes, key=lambda node: node["cpu"], reverse=True)

    source_node = nodes[0]
    target_nodes = nodes[1:]

    logger.debug(f'Looking for a workload on {source_node["node"]}')
    resources = api.cluster.resources.get(type="vm")

    for resource in resources:
        if resource["status"] == "running":
            resource["cpu"] = utils.cpu_ema(f'vm_{resource["vmid"]}', resource["cpu"])

    if any(c for c in resources if c.get("lock") == "migrate"):
        logger.debug(
            f"A resource currently has an active migrationlock, taking no action"
        )
        return False

    candidates = utils.filter_resources(resources, source_node["node"])
    candidates = utils.filter_running(candidates)
    candidates = utils.filter_no_lock(candidates)

    if mode == "cpu":
        candidates = sorted(
            candidates,
            key=lambda candidate: utils.workload_cpu_as_host_pct(candidate, source_node),
            reverse=True,
        )[1:]

    if not candidates:
        logger.debug("No candidates fit selection criteria")
        return False

    ha_rules = api.cluster.ha.rules.get()

    random.shuffle(candidates)
    for candidate in candidates:
        logger.debug(f"Considering candidate {candidate['name']}")

        target_nodes = utils.filter_memory_constraints(target_nodes, candidate, memory_max)

        target_nodes = utils.filter_cpu_constraints(
            target_nodes, candidate, source_node, cpu_max
        )

        if mode == "mem":
            target_nodes = utils.filter_memory_balance(target_nodes, candidate, source_node)
        elif mode == "cpu":
            target_nodes = utils.filter_cpu_balance(target_nodes, candidate, source_node)

        target_nodes = utils.filter_ha_rules(target_nodes, candidate, resources, ha_rules)

        if not target_nodes:
            logger.debug("No nodes fit selection criteria")
            continue

        # Pick the least utilized node by the current execution mode
        target_node = sorted(target_nodes, key=lambda node: node[mode])[0]

        logger.info(
            f"{reason}: Migrating {candidate['name']} from {source_node['node']} to {target_node['node']}"
        )
        opts = {"target": target_node["node"], "online": 1, "with-conntrack-state": 1}
        api.nodes(source_node["node"]).qemu(candidate["vmid"]).migrate().post(**opts)

        return True

    return False
