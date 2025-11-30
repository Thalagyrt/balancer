# Proxmox Balancer: An Active Workload Distribution Agent

### This is not yet production tested. Use in production at your own risk.

This repository contains an opinionated, active workload balancer for **Proxmox Virtual Environment (PVE)** clusters.

This script is designed to act as a resource availability agent. Its primary objective is to execute the bare minimum number of necessary live migrations to ensure sufficient CPU and memory resources remain available for all running virtual machines (VMs). It continuously monitors the cluster and initiates migrations only when a node's sustained resource usage threatens to impact existing workloads, or when it can take a proactive measure to reduce the likelihood of a saturation condition.

## Key Design Philosophy

The balancer is not intended for aesthetic load distribution or keeping resource usage perfectly uniform. Its core principles are:

* Migrate workloads only when required to prevent resource saturation on a cluster node.
* Only trigger migrations when a tangible resource benefit to the overall cluster is identified.

## Requirements and Assumptions

This script makes specific assumptions about your Proxmox environment for correct operation:

* All cluster nodes must be of similar size in terms of available RAM and CPU cores. Memory balancing is not based on percentages, but active used bytes. CPU balancing, while based on percentages, will not function well if the percentages mean wildly different things from node to node.
* All cluster workloads (VMs) must reside on shared storage (e.g., Ceph, NFS, iSCSI) that is fully accessible by all cluster nodes. This is essential for enabling live migration.
* Proxmox Virtual Environment (PVE) 9.0 or higher is required.
* Only QEMU/KVM VMs are migrated; Linux Containers (LXC/CTs) are explicitly excluded as they currently cannot migrate without restarting the workload.

## Configuration Parameters

The following parameters are used to define the boundaries for when balancing actions are triggered. All values are clamped to ensure safe operation.

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `cpu_max` | Float (0.5-0.9) | 0.8 (80%) | The sustained EMA CPU utilization threshold that triggers resource depletion mode on a node. |
| `memory_max` | Float (0.5-0.9) | 0.8 (80%) | The absolute memory utilization threshold that a migration cannot exceed on the target node. |

For high availability (HA) and reliability, it is suggested to run this script through a reverse proxy configured to communicate with all cluster nodes in a failover or round-robin manner. This ensures continuous operation even if one node is temporarily offline.

We do not consider disk usage for migration at all, as per the requirements, all workloads are already on shared storage. Please monitor your storage utilization with another tool.

## Deployment

See [compose.yml](./compose.yml) and [balancer.yaml.example](./balancer.yaml.example)

---

## Decision-Making Workflow

If an active migration is running, the balancer will wait for it to complete before taking another action. This ensures that decisions are based on the real, live state of the cluster, and minimizes disruption caused by migrating too many workloads at once.

The balancer evaluates the cluster every 5 seconds using a two-stage resource check:

### 1. High CPU Utilization Check

This trigger for migration is a sustained, high CPU load.

* An Exponential Moving Average (EMA) is maintained for each node's CPU usage over the last minute. This smoothing prevents migrations based on quick transient spikes.
* If a node's CPU EMA exceeds the configured `cpu_max` threshold, we begin migrating workloads off of that node.
* The script identifies a VM to move off of the saturated node.
* The VM consuming the highest CPU on the saturated node is intentionally left untouched. The goal is to migrate other workloads to free up resources for the busiest VM, preventing resource contention.

### 2. High Memory Utilization Check

This trigger for migration is a node above a high threshold.

* If a node's memory usage exceeds the configured `memory_max` threshold, we begin migrating workloads off of that node.
* The script identifies a VM to move off of the saturated node.
* A random VM will be moved off the node until this threshold is no longer exceeded.

### 3. Proactive Balancing

If all nodes are below the high thresholds, the script shifts focus to memory usage to proactively distribute workloads.

* Dynamic Threshold: A `memory_threshold` is calculated, set 20% above the average memory utilization of all cluster nodes.
* If a node's current memory usage exceeds this dynamic `memory_threshold`, it is considered a candidate for balancing.
* A random VM will be moved off the node until this threshold is no longer exceeded. The intent is to only act when nodes are severely out of balance.

---

## Migration Selection Logic

In all cases, the script follows consistent logic to select the best migration candidate and destination:

1.  A workload is selected from the highest utilized source node that meets the migration criteria.
2.  The remaining nodes are each evaluated as a potential migration target.

A migration is only considered valid if it results in a "favorable outcome", defined by the following checks:

* The migration must not violate a configured anti-affinity constraint, and the workload being migrated must not have an explicitly set affinity rule to a node or other workload.
* The migration must not put the target node above the absolute `memory_max` or `cpu_max` thresholds. A small safety margin is applied to prevent creating a new borderline-saturated node.
* The migration must not simply flip the resource imbalance.
    * For the resource in question (CPU or Memory), the midpoint usage is calculated (e.g., if source is 40% and target is 60%, the midpoint is 50%).
    * If the migration would result in the target node's utilization rising above this midpoint, it is rejected. This ensures the move genuinely lowers the highest utilization.

From all nodes offering a favorable outcome, the VM is migrated to the least utilized eligible target node. If no favorable outcome is found, no migration takes place.
