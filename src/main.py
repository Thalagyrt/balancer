__author__ = "James P. Riley"
__copyright__ = "Copyright (C) 2025 James P. Riley (@thalagyrt)"
__license__ = "GPL-3.0"

import logging
import proxmoxer
import yaml
import sys
import random
import time
import pandas
import statistics

logger = logging.getLogger(__name__)

cpu_usage = {}


def load_config():
    try:
        with open("balancer.yaml", "r") as config_file:
            return yaml.load(config_file, Loader=yaml.FullLoader)
    except (yaml.YAMLError, FileNotFoundError) as e:
        logger.critical(f"Unable to load config: {e}")
        sys.exit(1)


def api_connect(config):
    api = proxmoxer.ProxmoxAPI(
        config.get("proxmox_api").get("host", "localhost"),
        port=config.get("proxmox_api").get("port", "8006"),
        user=config.get("proxmox_api").get("user"),
        token_name=config.get("proxmox_api").get("token_id"),
        token_value=config.get("proxmox_api").get("token_secret"),
    )
    return api


# Used to compute a running exponential moving average of CPU usage so we can avoid transient spikes for a second causing a migration event.
def cpu_ema(key, value):
    if key not in cpu_usage:
        cpu_usage[key] = []
    cpu_usage[key].append(value)
    cpu_usage[key] = cpu_usage[key][-10:]
    return float(pandas.DataFrame(cpu_usage[key]).ewm(span=10).mean().iat[-1, -1])


def clamp(n, min_val, max_val):
    return max(min(n, max_val), min_val)


def migrate_workload(config):
    api = api_connect(config)
    nodes = api.nodes.get()

    # Grab our alarm thresholds
    cpu_max = clamp(config.get("balancer").get("cpu_max", 0.8), 0.5, 0.9)
    memory_max = clamp(config.get("balancer").get("memory_max", 0.8), 0.5, 0.9)

    # Set the dynamic memory threshold
    used_memory = list(map(lambda x: x["mem"] / x["maxmem"], nodes))
    memory_threshold = statistics.mean(used_memory) * 1.2

    logger.debug(f"Setting memory thresehold to {memory_threshold}")

    for node in nodes:
        node["cpu"] = cpu_ema(f'node_{node["node"]}', node["cpu"])

    if any(node["cpu"] > cpu_max for node in nodes):
        logger.debug(f"A node is over the CPU maximum of {cpu_max}%")
        mode = "cpu"
        reason = "CPU maximum exceeded"
    elif any(node["mem"] / node["maxmem"] > memory_max for node in nodes):
        logger.debug(f"A node is over the memory maximum of {memory_max}%")
        mode = "mem"
        reason = "Memory maximum exceeded"
    elif any(node["mem"] / node["maxmem"] > memory_threshold for node in nodes):
        logger.debug(f"A node is over the memory threshold of {memory_threshold}")
        mode = "mem"
        reason = "Proactive balancing"
    else:
        logger.debug(f"No balancing is necessary")
        return False

    if mode == "mem":
      nodes = sorted(nodes, key=lambda node: node["mem"] / node["maxmem"], reverse=True)
    elif mode == "cpu":
      nodes = sorted(nodes, key=lambda node: node["cpu"], reverse=True)

    source_node = nodes[0]
    target_nodes = nodes[1:]

    logger.debug(f'Looking for a workload on {source_node["node"]}')
    resources = api.cluster.resources.get(type="vm")

    for resource in resources:
        resource["cpu"] = cpu_ema(f'vm_{resource["vmid"]}', resource["cpu"])

    for resource in resources:
        if resource.get("lock", None) == "migrate":
            logger.debug(
                f"{resource['name']} is currently migrating, waiting for completion"
            )
            return False

    # Quickly pare the list down to VMs not in a backup state, and that are currently running on the source node.
    candidates = list(
        filter(
            lambda resource: (not "lock" in resource)
            and (resource["status"] == "running")
            and (resource["node"] == source_node["node"]),
            resources,
        )
    )

    # If CPU, we specifically want to exclude the candidate with the highest utilization
    if mode == "cpu":
        candidates = sorted(
            candidates, key=lambda candidate: candidate["cpu"], reverse=True
        )[1:]

    if not candidates:
        logger.debug("No candidates fit selection criteria")
        return False

    # Fetch any HA rules as we'll use them later at this point
    ha_rules = api.cluster.ha.rules.get()

    random.shuffle(candidates)
    for candidate in candidates:
        logger.debug(f"Considering candidate {candidate['name']}")

        # Filter out nodes that this guest would throw over the memory_max limit
        target_nodes = list(
            filter(
                lambda x: x["mem"] + candidate["mem"]
                < (x["maxmem"] * memory_max * 0.9),
                target_nodes,
            )
        )

        # Filter out nodes that this guest would throw over the cpu_max limit
        target_nodes = list(
            filter(
                lambda x: x["cpu"]
                + (
                    # Scale the guest's CPU usage to host usage
                    (candidate["cpu"] * candidate["maxcpu"] / source_node["maxcpu"])
                    # Scale the resultant host usage to the target node's core count
                    * (source_node["maxcpu"] / x["maxcpu"])
                )
                < (cpu_max * 0.9),
                target_nodes,
            )
        )

        # Filter out nodes that would not be a meet-in-the-middle
        if mode == "mem":
            target_nodes = list(
                filter(
                    lambda x: ((x["mem"] + candidate["mem"]) / x["maxmem"])
                    < (
                        (
                            (source_node["mem"] / source_node["maxmem"])
                            + (x["mem"] / x["maxmem"])
                        )
                        / 2
                    ),
                    target_nodes,
                )
            )
        elif mode == "cpu":
            target_nodes = list(
                filter(
                    lambda x: x["cpu"]
                    + (
                        # Scale the guest's CPU usage to host usage
                        (candidate["cpu"] * candidate["maxcpu"] / source_node["maxcpu"])
                        # Scale the resultant host usage to the target node's core count
                        * (source_node["maxcpu"] / x["maxcpu"])
                    )
                    < ((source_node["cpu"] + x["cpu"]) / 2),
                    target_nodes,
                )
            )

        # Filter out nodes that would violate an anti-affinity rule, as well as candidates that
        for ha_rule in ha_rules:
            rules = ha_rule["resources"].split(",")
            rule_type = ha_rule["type"]
            rule_affinity = ha_rule["affinity"]

            if f'vm:{candidate["vmid"]}' in rules:
                for resource in rules:
                    vmid = int(resource.split(":")[1])
                    vm = list(filter(lambda x: x["vmid"] == vmid, resources))[0]
                    rule_nodes = list(filter(lambda x: x["node"] == vm["node"], nodes))
                    rule_node_names = list(map(lambda x: x["node"], rule_nodes))

                    if rule_type == "resource-affinity" and rule_affinity == "negative":
                        target_nodes = list(
                            filter(
                                lambda x: not x["node"] in rule_node_names, target_nodes
                            )
                        )
                    else:
                        logger.debug(
                            "Candidate has either node affinity or vm affinity rule, skipping"
                        )
                        target_nodes = []

        if not target_nodes:
            logger.debug("No nodes fit selection criteria")
            continue

        # Pick the least utilized node by the current execution mode
        target_node = sorted(target_nodes, key=lambda node: node[mode])[0]

        # Off we go!
        logger.info(
            f"{reason}: Migrating {candidate['name']} from {source_node['node']} to {target_node['node']}"
        )
        opts = {"target": target_node["node"], "online": 1, "with-conntrack-state": 1}
        api.nodes(source_node["node"]).qemu(candidate["vmid"]).migrate().post(**opts)

        return True

    return False


def main():
    config = load_config()
    log_level = config.get("logging").get("level", "INFO")
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s", level=log_level
    )
    logger.info("Starting up.")
    while True:
        if migrate_workload(config):
            # Ensure that we have enough time for a migration to begin so we don't kick off another right away
            time.sleep(25)
        time.sleep(5)


if __name__ == "__main__":
    main()
