__author__ = "James P. Riley"
__copyright__ = "Copyright (C) 2025 James P. Riley (@thalagyrt)"
__license__ = "GPL-3.0"

from . import logger
from . import api
from . import calculations
import time
import random
from . import filters
from . import constants

BACKUP_WINDOW_SECONDS = constants.BACKUP_WINDOW_SECONDS
BACKUP_PAUSE_SECONDS = constants.BACKUP_PAUSE_SECONDS
DEFAULT_CPU_MAX = constants.DEFAULT_CPU_MAX
DEFAULT_MEMORY_MAX = constants.DEFAULT_MEMORY_MAX
THRESHOLD_CLAMP_MIN = constants.THRESHOLD_CLAMP_MIN
THRESHOLD_CLAMP_MAX = constants.THRESHOLD_CLAMP_MAX
MEMORY_THRESHOLD_MULTIPLIER = constants.MEMORY_THRESHOLD_MULTIPLIER


def _check_backup_window(api):
    """Check if a backup job is scheduled within the backup window.

    If a backup is imminent, pauses execution to avoid interfering with
    backup operations.

    Args:
        api: Proxmox API client instance.

    Returns:
        bool: True if backup window is active (and we should pause),
              False otherwise.
    """
    backup_jobs = api.cluster.backup.get()
    run_times = [job["next-run"] for job in backup_jobs if job["enabled"] == 1]
    if run_times:
        next_run = min(run_times)
        if next_run - time.time() < constants.BACKUP_WINDOW_SECONDS:
            return True
    return False


def _get_online_nodes(api):
    """Fetch and filter to only online nodes.

    Args:
        api: Proxmox API client instance.

    Returns:
        list: List of online node dictionaries.
    """
    nodes = api.nodes.get()

    states = api.cluster.resources.get(type="node")
    hastates = {
        node['node']: node['hastate'] for node in states
    }

    return filters.filter_online_nodes(nodes, hastates)


def _get_balancing_config(config):
    """Extract balancing thresholds from configuration.

    Args:
        config: Configuration dictionary with 'balancer' section.

    Returns:
        tuple: (cpu_max, memory_max) threshold values, clamped to valid range.
    """
    cpu_max = calculations.clamp(
        config.get("balancer").get("cpu_max", constants.DEFAULT_CPU_MAX),
        constants.THRESHOLD_CLAMP_MIN,
        constants.THRESHOLD_CLAMP_MAX,
    )
    memory_max = calculations.clamp(
        config.get("balancer").get("memory_max", constants.DEFAULT_MEMORY_MAX),
        constants.THRESHOLD_CLAMP_MIN,
        constants.THRESHOLD_CLAMP_MAX,
    )
    return cpu_max, memory_max


def _apply_cpu_ema_to_nodes(nodes, cpu_ema):
    """Apply exponential moving average smoothing to node CPU values.

    Args:
        nodes: List of node dictionaries (modified in place).
        cpu_ema: CpuEMA instance for computing smoothed CPU values.

    Returns:
        list: The same nodes list with smoothed CPU values.
    """
    for node in nodes:
        node["cpu"] = cpu_ema.update(f'node_{node["node"]}', node["cpu"])
    return nodes


def _determine_balancing_mode(nodes, cpu_max, memory_max, memory_threshold):
    """Determine if balancing is needed and which mode to use.

    Checks nodes against CPU/memory thresholds and determines the
    appropriate balancing mode.

    Args:
        nodes: List of node dictionaries.
        cpu_max: Maximum CPU threshold.
        memory_max: Maximum memory threshold.
        memory_threshold: Dynamic memory threshold for proactive balancing.

    Returns:
        tuple: (mode, reason) where mode is 'cpu' or 'mem', or (None, None)
               if no balancing is needed.
    """
    if any(node["cpu"] > cpu_max for node in nodes):
        logger.debug(f"A node is over the CPU maximum of {cpu_max*100}%")
        return "cpu", "CPU maximum exceeded"

    if any(calculations.node_memory_pct(node) > memory_max for node in nodes):
        logger.debug(f"A node is over the memory maximum of {memory_max*100}%")
        return "mem", "Memory maximum exceeded"

    if any(calculations.node_memory_pct(node) > memory_threshold for node in nodes):
        logger.debug(
            f"A node is over the memory threshold of {round(memory_threshold*100, 2)}%"
        )
        return "mem", "Proactive balancing"

    logger.debug("No balancing is necessary")
    return None, None


def _select_source_and_targets(nodes, mode):
    """Sort nodes by utilization and select source/target nodes.

    Args:
        nodes: List of node dictionaries.
        mode: Balancing mode ('cpu' or 'mem').

    Returns:
        tuple: (source_node, target_nodes) where source is the most
               overloaded node and target_nodes is a list of remaining nodes.
    """
    if mode == "mem":
        nodes = sorted(
            nodes, key=lambda node: calculations.node_memory_pct(node), reverse=True
        )
    else:  # mode == "cpu"
        nodes = sorted(nodes, key=lambda node: node["cpu"], reverse=True)

    return nodes[0], nodes[1:]


def _apply_cpu_ema_to_vms(resources, cpu_ema):
    """Apply exponential moving average smoothing to VM CPU values.

    Args:
        resources: List of VM resource dictionaries (modified in place).
        cpu_ema: CpuEMA instance for computing smoothed CPU values.

    Returns:
        list: The same resources list with smoothed CPU values for running VMs.
    """
    for resource in resources:
        if resource["status"] == "running":
            resource["cpu"] = cpu_ema.update(f'vm_{resource["vmid"]}', resource["cpu"])
    return resources


def _check_migration_lock(resources):
    """Check if any resource has an active migration lock.

    Args:
        resources: List of VM resource dictionaries.

    Returns:
        bool: True if a migration lock is active, False otherwise.
    """
    if filters.filter_migration_lock(resources):
        logger.debug(
            "A resource currently has an active migration lock, taking no action"
        )
        return True
    return False


def _get_vm_candidates(resources, source_node, mode):
    """Filter and sort VM migration candidates.

    Args:
        resources: List of all VM resource dictionaries.
        source_node: Source node dictionary.
        mode: Balancing mode ('cpu' or 'mem').

    Returns:
        list: Filtered and sorted list of candidate VMs.
    """
    candidates = filters.filter_resources(resources, source_node["node"])
    candidates = filters.filter_running(candidates)
    candidates = filters.filter_no_lock(candidates)

    if mode == "cpu":
        candidates = sorted(
            candidates,
            key=lambda c: calculations.workload_cpu_as_host_pct(c, source_node),
            reverse=True,
        )[1:]

    return candidates


def _apply_candidate_filters(
    target_nodes, candidate, source_node, mode, cpu_max, memory_max, resources, ha_rules
):
    """Apply all constraint filters to find viable target nodes.

    Args:
        target_nodes: List of potential target node dictionaries.
        candidate: VM candidate dictionary.
        source_node: Source node dictionary.
        mode: Balancing mode ('cpu' or 'mem').
        cpu_max: Maximum CPU threshold.
        memory_max: Maximum memory threshold.
        resources: All VM resources (for HA rule evaluation).
        ha_rules: HA rules from Proxmox API.

    Returns:
        list: Filtered list of viable target nodes.
    """
    target_nodes = filters.filter_memory_constraints(
        target_nodes, candidate, memory_max
    )
    target_nodes = filters.filter_cpu_constraints(
        target_nodes, candidate, source_node, cpu_max
    )

    if mode == "mem":
        target_nodes = filters.filter_memory_balance(
            target_nodes, candidate, source_node
        )
    else:  # mode == "cpu"
        target_nodes = filters.filter_cpu_balance(target_nodes, candidate, source_node)

    target_nodes = filters.filter_ha_rules(target_nodes, candidate, resources, ha_rules)

    return target_nodes


def _select_best_target(target_nodes, mode):
    """Select the least utilized target node for the given mode.

    Args:
        target_nodes: List of viable target node dictionaries.
        mode: Balancing mode ('cpu' or 'mem').

    Returns:
        dict: The target node with lowest utilization for the mode.
    """
    if mode == "mem":
        return sorted(
            target_nodes, key=lambda node: calculations.node_memory_pct(node)
        )[0]
    else:  # mode == "cpu"
        return sorted(target_nodes, key=lambda node: node["cpu"])[0]


def _execute_migration(api_client, source_node, target_node, candidate):
    """Execute the VM migration via Proxmox API and monitor its progress.

    Initiates live migration, then monitors the VM's lock status to confirm
    the migration started and completed successfully.

    Args:
        api_client: Proxmox API client instance.
        source_node: Source node dictionary.
        target_node: Target node dictionary.
        candidate: VM candidate dictionary.

    Returns:
        bool: True if migration completed successfully, False if failed or timed out.
    """
    vmid = candidate["vmid"]

    opts = {"target": target_node["node"], "online": 1, "with-conntrack-state": 1}
    try:
        api_client.nodes(source_node["node"]).qemu(vmid).migrate().post(**opts)
    except Exception as e:
        logger.error(f"Error initiating migration: {e}")

    # Wait for migration to start and complete
    if not _await_migration_start(api_client, source_node, candidate):
        return False

    if not _await_migration_complete(api_client, source_node, target_node, candidate):
        return False

    return True


def _await_migration_start(api_client, source_node, candidate):
    """Wait for the migration lock to appear, confirming migration started.

    Checks every 5 seconds for up to 60 seconds (12 checks).

    Args:
        api_client: Proxmox API client instance.
        source_node: Source node dictionary.
        vmid: VM identifier.

    Returns:
        bool: True if migration lock appeared, False if timed out.
    """
    for _ in range(12):
        time.sleep(5)
        try:
            vm_status = (
                api_client.nodes(source_node["node"])
                .qemu(candidate["vmid"])
                .status.current.get()
            )
            if vm_status.get("lock") == "migrate":
                logger.info(f"Migration of {candidate["name"]} has begun")
                return True
        except Exception as e:
            logger.debug(f"Error checking VM status: {e}")

    logger.error(
        f"VM {candidate["vmid"]} migration failed to start - no migration lock appeared within 30 seconds"
    )
    return False


def _await_migration_complete(api_client, source_node, target_node, candidate):
    """Wait for the migration to complete by monitoring VM status.

    Checks every 15 seconds for up to 30 minutes (120 checks). Exits early
    if the VM disappears from the source node and appears on the target.

    Args:
        api_client: Proxmox API client instance.
        source_node: Source node dictionary.
        target_node: Target node dictionary.
        vmid: VM identifier.
        name: VM name for logging.

    Returns:
        bool: True if migration completed successfully, False if failed or timed out.
    """
    failures = 0
    for _ in range(4 * 30):
        time.sleep(15)
        try:
            if candidate["vmid"] not in [
                guest["vmid"]
                for guest in api_client.nodes(source_node["node"]).qemu().get()
            ]:
                if candidate["vmid"] in [
                    guest["vmid"]
                    for guest in api_client.nodes(target_node["node"]).qemu().get()
                ]:
                    logger.info(f"Migration of {candidate["name"]} is complete")
                    return True
                else:
                    logger.error(
                        f"VM {candidate["name"]} not found on {target_node['node']} after migration!"
                    )
                    return False
            failures = 0
        except Exception as e:
            logger.debug(f"Error checking VM status: {e}")
            failures = failures + 1
            if failures > 5:
                logger.error("Unable to check status 5 times consecutively. Aborting.")
                return False

    logger.error(f"Migration of {candidate["name"]} did not finish after 30 minutes!")
    return False


def migrate_workload(config, cpu_ema, api_client):
    """Attempt to balance workloads by migrating a VM from overloaded to underutilized node.

    Checks node CPU/memory utilization, selects a candidate VM from the most
    overloaded node, filters viable target nodes based on constraints and HA rules,
    then initiates live migration.

    Args:
        config: Configuration dictionary with 'proxmox_api' credentials and
            'balancer' thresholds section.
        cpu_ema: CpuEMA instance for computing smoothed CPU values.
        api_client: Proxmox API client instance.

    Returns:
        bool: True if a VM was migrated, False if no balancing needed or no
            viable candidates/targets.
    """
    if _check_backup_window(api_client):
        logger.debug(
            f"A backup job is scheduled in the next {constants.BACKUP_WINDOW_SECONDS} seconds, "
            f"pausing for {constants.BACKUP_PAUSE_SECONDS} seconds"
        )
        time.sleep(constants.BACKUP_PAUSE_SECONDS)
        return False

    nodes = _get_online_nodes(api_client)
    cpu_max, memory_max = _get_balancing_config(config)
    memory_threshold = calculations.compute_dynamic_memory_threshold(nodes)
    logger.debug(f"Setting memory threshold to {round(memory_threshold*100, 2)}%")

    _apply_cpu_ema_to_nodes(nodes, cpu_ema)
    mode, reason = _determine_balancing_mode(
        nodes, cpu_max, memory_max, memory_threshold
    )

    if mode is None:
        return False

    source_node, target_nodes = _select_source_and_targets(nodes, mode)

    logger.debug(f'Looking for a workload on {source_node["node"]}')

    resources = api_client.cluster.resources.get(type="vm")
    _apply_cpu_ema_to_vms(resources, cpu_ema)

    if _check_migration_lock(resources):
        return False

    candidates = _get_vm_candidates(resources, source_node, mode)

    if not candidates:
        logger.debug("No candidates fit selection criteria")
        return False

    ha_rules = api_client.cluster.ha.rules.get()
    random.shuffle(candidates)

    for candidate in candidates:
        logger.debug(f"Considering candidate {candidate['name']}")

        viable_targets = _apply_candidate_filters(
            target_nodes,
            candidate,
            source_node,
            mode,
            cpu_max,
            memory_max,
            resources,
            ha_rules,
        )

        if not viable_targets:
            logger.debug("No nodes fit selection criteria")
            continue

        logger.debug(
            f"Nodes in consideration are {[f"{target_node['node']} ({round(calculations.node_memory_pct(target_node)*100,2)}%)" for target_node in viable_targets]}"
        )

        target_node = _select_best_target(viable_targets, mode)

        logger.info(
            f"{reason}: Migrating {candidate['name']} from {source_node['node']} to {target_node['node']}"
        )
        #_execute_migration(api_client, source_node, target_node, candidate)

        return True

    return False
