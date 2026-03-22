"""Filter functions for migration candidate evaluation."""

from statistics import mean

from . import logger
from . import calculations
from . import constants


def filter_resources(resources, source_node):
    """Filter resources to only those on the source node.

    Extracts VM resources from the full resource list that are allocated
    to or running on a specific Proxmox node. Useful for narrowing down
    migration candidates when evaluating load balancing decisions.

    Args:
        resources: List of all VM resources from Proxmox API. Each item
            is a dictionary containing at least 'node' and 'vmid' keys.
        source_node: The name of the source node (string).

    Returns:
        list: Filtered list of resource dictionaries where each has
            matching node name equal to source_node.
    """
    return [c for c in resources if c["node"] == source_node]


def filter_running(candidates):
    """Filter candidates to only running VMs.

    Removes any VM resources from the candidate list that are not in
    the 'running' status. Ensures migration decisions are only made for
    active VMs.

    Args:
        candidates: List of VM resource dictionaries. Each contains at least
            a 'status' key with values like 'running', 'stopped', etc.

    Returns:
        list: Filtered list containing only resources where status == 'running'.
    """
    return [c for c in candidates if c["status"] == "running"]


def filter_no_lock(candidates):
    """Filter out candidates that have no lock key (VM has a lock).

    Removes any VM resources from the candidate list that have an active
    'migrate' lock, which indicates the VM is in an intermediate migration
    state and should not be selected as a migration candidate.

    Args:
        candidates: List of VM resource dictionaries. Each may contain
            a 'lock' key with value 'migrate' if locked.

    Returns:
        list: Filtered list containing only resources without an active
            migration lock (where c.get('lock') is not 'migrate').
    """
    return [c for c in candidates if not "lock" in c]


def filter_memory_constraints(target_nodes, candidate, memory_max):
    """Filter out nodes that would exceed memory_max if this guest migrated.

    Evaluates whether adding a candidate VM's memory to a target node would
    cause the node to exceed memory_max * 90% of its maxmem capacity. This
    threshold prevents migrations from creating dangerously memory-pressed nodes.

    Args:
        target_nodes: List of candidate target node dictionaries, each containing
            'mem' (current used memory), 'maxmem' (total available memory).
        candidate: The VM being considered for migration, containing a 'mem' key
            with its current memory allocation.
        memory_max: Maximum memory usage ratio allowed (0.0-1.0), e.g., 0.8 means
            nodes should not exceed 80% of their max memory capacity.

    Returns:
        list: Filtered list of target_nodes where adding the candidate VM would
            keep usage below memory_max * 0.9.
    """
    return [
        candidate_node
        for candidate_node in target_nodes
        if candidate_node["mem"] + candidate["mem"]
        < (candidate_node["maxmem"] * memory_max * constants.CONSTRAINT_SAFETY_FACTOR)
    ]


def filter_cpu_constraints(target_nodes, candidate, source_node, cpu_max):
    """Filter out nodes that would exceed cpu_max if this guest migrated.

    Evaluates whether adding a candidate VM's scaled CPU to a target node would
    cause the node to exceed cpu_max * 90% of its maxcpu capacity. Accounts for
    the candidate's actual CPU usage on its current node and applies a cross-node
    factor to normalize for different core counts.

    Args:
        target_nodes: List of candidate target node dictionaries, each containing
            'cpu' (current used CPU), 'maxcpu' (total available CPU).
        candidate: The VM being considered for migration. Must contain 'vmid',
            'name' keys, and be accessible via the source_node's context.
        source_node: The current node of the candidate VM. Used to compute the
            scaled CPU contribution via workload_cpu_as_host_pct and node_cpu_factor.
        cpu_max: Maximum CPU usage ratio allowed (0.0-1.0).

    Returns:
        list: Filtered list of target_nodes where adding the candidate VM would
            keep usage below cpu_max * 0.9 after scaling.
    """
    return [
        candidate_node
        for candidate_node in target_nodes
        if candidate_node["cpu"]
        + (
            calculations.workload_cpu_as_host_pct(candidate, source_node)
            * calculations.node_cpu_factor(source_node, candidate_node)
        )
        < (cpu_max * constants.CONSTRAINT_SAFETY_FACTOR)
    ]


def filter_memory_balance(target_nodes, candidate, source_node):
    """Filter out nodes that would not be a meet-in-the-middle for memory.

    Applies balance logic to ensure migrations don't create highly skewed
    memory distributions across nodes. A target node is excluded if
    its memory usage after migration would be higher than the midpoint
    memory usage between source and target nodes. This encourages balancing
    rather than concentration of memory pressure.

    Args:
        target_nodes: List of candidate target node dictionaries with 'mem',
            'maxmem' keys.
        candidate: The VM being considered for migration, containing 'mem'.
        source_node: The current node of the candidate, used to get its
            memory percentage via node_memory_pct().

    Returns:
        list: Filtered list where target nodes have memory ratio >= average
            of source and target node memory percentages.
    """
    return [
        candidate_node
        for candidate_node in target_nodes
        if ((candidate_node["mem"] + candidate["mem"]) / candidate_node["maxmem"])
        < mean(
            [calculations.node_memory_pct(source_node), calculations.node_memory_pct(candidate_node)]
        )
    ]


def filter_cpu_balance(target_nodes, candidate, source_node):
    """Filter out nodes that would not be a meet-in-the-middle for CPU.

    Applies balance logic to ensure migrations don't create highly skewed
    CPU distributions across nodes. A target node is excluded if its CPU
    usage after migration (accounting for scaled workload contribution)
    would be higher than the midpoint CPU usage between source and target
    nodes.

    Args:
        target_nodes: List of candidate target node dictionaries with 'cpu',
            'maxcpu' keys.
        candidate: The VM being considered for migration, used to compute
            scaled CPU contribution via workload_cpu_as_host_pct().
        source_node: The current node of the candidate, used to compute
            scaled CPU and its memory percentage.

    Returns:
        list: Filtered list where target nodes have CPU usage >= average
            of source and target CPU percentages after applying migration.
    """
    return [
        candidate_node
        for candidate_node in target_nodes
        if candidate_node["cpu"]
        + (
            calculations.workload_cpu_as_host_pct(candidate, source_node)
            * calculations.node_cpu_factor(source_node, candidate_node)
        )
        < mean([source_node["cpu"], candidate_node["cpu"]])
    ]


def filter_online_nodes(nodes):
    """Filter nodes to only those with online status.

    Extracts only the nodes that are currently online from the Proxmox
    cluster. This is used to ensure migration decisions only consider
    healthy, reachable nodes.

    Args:
        nodes: List of node dictionaries from Proxmox API, each containing
            at least a 'status' key with values like 'online', 'offline'.

    Returns:
        list: Filtered list containing only nodes where status == 'online'.
    """
    return [node for node in nodes if node["status"] == "online"]


def filter_migration_lock(resources):
    """Check if any resource has an active migration lock.

    Args:
        resources: List of VM resource dictionaries.

    Returns:
        bool: True if a migration lock is active, False otherwise.
    """
    return any(c.get("lock") == "migrate" for c in resources)


def filter_ha_rules(target_nodes, candidate, resources, ha_rules):
    """Filter out nodes that would violate an anti-affinity rule or have positive affinity.

    Filters candidate target nodes based on High Availability (HA) rules:
    - Nodes that contain a workload with an anti affinity rule for the candidate are excluded.
    - Positive affinity rules prevent migration (VM must stay on current node)

    Args:
        target_nodes: List of candidate target node dictionaries with 'node' key.
        candidate: The VM being considered for migration, containing 'vmid' and
            'name' keys, plus other attributes accessible through resources lookup.
        resources: All VM resources from the cluster, used to look up nodes
            by VMID when processing anti-affinity rules.
        ha_rules: List of HA rule dictionaries from proxmoxer, each containing
            'resources' (comma-separated resource identifiers), 'type', and
            'affinity' keys.

    Returns:
        list: Filtered target_nodes. Empty list if candidate has positive affinity,
            otherwise returns nodes that don't violate anti-affinity rules.
    """
    for ha_rule in ha_rules:
        rule_resources = ha_rule["resources"].split(",")
        rule_type = ha_rule["type"]
        rule_affinity = ha_rule["affinity"]

        if f"vm:{candidate['vmid']}" in rule_resources:
            # Anti-affinity between nodes - exclude candidate's current node
            if rule_type == "resource-affinity" and rule_affinity == "negative":
                for rule_resource in rule_resources:
                    vmid = int(rule_resource.split(":")[1])
                    resource = next((r for r in resources if r["vmid"] == vmid), None)

                    if resource:
                        target_nodes = [
                            candidate_node
                            for candidate_node in target_nodes
                            if not candidate_node["node"] == resource["node"]
                        ]
            # Positive affinity - skip the candidate entirely
            else:
                logger.debug(
                    "Candidate has either node affinity or vm affinity rule, skipping"
                )
                target_nodes = []

    return target_nodes
