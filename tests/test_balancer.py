"""Unit tests for balancer.py helper functions.

Tests the pure/helper functions in balancer.py that don't require
extensive API mocking. Functions requiring Proxmox API interaction
are excluded and would be better suited for integration tests.
"""

import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from balancer import balancer
from balancer import calculations
from balancer.ema import CpuEMA
from balancer import logger


class TestGetBalancingConfig(unittest.TestCase):
    """Tests for _get_balancing_config()."""

    def setUp(self):
        """Set up logger for each test."""
        logger.setup_logging()

    def test_returns_default_values_when_missing(self):
        """Returns default CPU and memory max when balancer section is missing values."""
        config = {"balancer": {}}
        cpu_max, memory_max = balancer._get_balancing_config(config)
        self.assertEqual(cpu_max, balancer.DEFAULT_CPU_MAX)
        self.assertEqual(memory_max, balancer.DEFAULT_MEMORY_MAX)

    def test_returns_custom_values_when_present(self):
        """Returns custom CPU and memory max when specified in config."""
        config = {"balancer": {"cpu_max": 0.7, "memory_max": 0.75}}
        cpu_max, memory_max = balancer._get_balancing_config(config)
        self.assertEqual(cpu_max, 0.7)
        self.assertEqual(memory_max, 0.75)

    def test_clamps_cpu_max_to_minimum(self):
        """Clamps cpu_max to THRESHOLD_CLAMP_MIN when below threshold."""
        config = {"balancer": {"cpu_max": 0.3}}
        cpu_max, _ = balancer._get_balancing_config(config)
        self.assertEqual(cpu_max, balancer.THRESHOLD_CLAMP_MIN)

    def test_clamps_cpu_max_to_maximum(self):
        """Clamps cpu_max to THRESHOLD_CLAMP_MAX when above threshold."""
        config = {"balancer": {"cpu_max": 0.95}}
        cpu_max, _ = balancer._get_balancing_config(config)
        self.assertEqual(cpu_max, balancer.THRESHOLD_CLAMP_MAX)

    def test_clamps_memory_max_to_minimum(self):
        """Clamps memory_max to THRESHOLD_CLAMP_MIN when below threshold."""
        config = {"balancer": {"memory_max": 0.4}}
        _, memory_max = balancer._get_balancing_config(config)
        self.assertEqual(memory_max, balancer.THRESHOLD_CLAMP_MIN)

    def test_clamps_memory_max_to_maximum(self):
        """Clamps memory_max to THRESHOLD_CLAMP_MAX when above threshold."""
        config = {"balancer": {"memory_max": 0.99}}
        _, memory_max = balancer._get_balancing_config(config)
        self.assertEqual(memory_max, balancer.THRESHOLD_CLAMP_MAX)

    def test_clamps_only_values_outside_range(self):
        """Only clamps values that are outside the valid range."""
        config = {"balancer": {"cpu_max": 0.3, "memory_max": 0.7}}
        cpu_max, memory_max = balancer._get_balancing_config(config)
        self.assertEqual(cpu_max, balancer.THRESHOLD_CLAMP_MIN)
        self.assertEqual(memory_max, 0.7)


class TestApplyCpuEmaToNodes(unittest.TestCase):
    """Tests for _apply_cpu_ema_to_nodes()."""

    def setUp(self):
        """Set up logger and create fresh CpuEMA instance for each test."""
        logger.setup_logging()
        self.cpu_ema = CpuEMA()

    def tearDown(self):
        """Clean up after each test."""
        pass

    def test_applies_ema_to_all_nodes(self):
        """Applies CPU EMA to all nodes in the list."""
        nodes = [
            {"node": "node1", "cpu": 0.5},
            {"node": "node2", "cpu": 0.6},
        ]
        result = balancer._apply_cpu_ema_to_nodes(nodes, self.cpu_ema)
        self.assertEqual(nodes[0]["cpu"], 0.5)
        self.assertEqual(nodes[1]["cpu"], 0.6)

    def test_modifies_nodes_in_place(self):
        """Modifies the input list in place and returns it."""
        nodes = [{"node": "node1", "cpu": 0.5}]
        result = balancer._apply_cpu_ema_to_nodes(nodes, self.cpu_ema)
        self.assertIs(result, nodes)

    def test_uses_node_name_for_ema_key(self):
        """Uses 'node_<name>' as the key for cpu_ema."""
        nodes = [{"node": "testnode", "cpu": 0.5}]
        balancer._apply_cpu_ema_to_nodes(nodes, self.cpu_ema)
        self.assertIn("node_testnode", self.cpu_ema._usage)


class TestApplyCpuEmaToVms(unittest.TestCase):
    """Tests for _apply_cpu_ema_to_vms()."""

    def setUp(self):
        """Set up logger and create fresh CpuEMA instance for each test."""
        logger.setup_logging()
        self.cpu_ema = CpuEMA()

    def tearDown(self):
        """Clean up after each test."""
        pass

    def test_applies_ema_only_to_running_vms(self):
        """Applies CPU EMA only to VMs with status 'running'."""
        resources = [
            {"vmid": 100, "status": "running", "cpu": 0.5},
            {"vmid": 101, "status": "stopped", "cpu": 0},
            {"vmid": 102, "status": "running", "cpu": 0.3},
        ]
        balancer._apply_cpu_ema_to_vms(resources, self.cpu_ema)
        self.assertIn("vm_100", self.cpu_ema._usage)
        self.assertNotIn("vm_101", self.cpu_ema._usage)
        self.assertIn("vm_102", self.cpu_ema._usage)

    def test_modifies_resources_in_place(self):
        """Modifies the input list in place and returns it."""
        resources = [{"vmid": 100, "status": "running", "cpu": 0.5}]
        result = balancer._apply_cpu_ema_to_vms(resources, self.cpu_ema)
        self.assertIs(result, resources)

    def test_uses_vmid_for_ema_key(self):
        """Uses 'vm_<vmid>' as the key for cpu_ema."""
        resources = [{"vmid": 123, "status": "running", "cpu": 0.5}]
        balancer._apply_cpu_ema_to_vms(resources, self.cpu_ema)
        self.assertIn("vm_123", self.cpu_ema._usage)

    def test_skips_non_running_vms(self):
        """Skips VMs that are not in running state."""
        resources = [
            {"vmid": 100, "status": "stopped", "cpu": 0},
            {"vmid": 101, "status": "paused", "cpu": 0.25},
        ]
        balancer._apply_cpu_ema_to_vms(resources, self.cpu_ema)
        self.assertNotIn("vm_100", self.cpu_ema._usage)
        self.assertNotIn("vm_101", self.cpu_ema._usage)


class TestDetermineBalancingMode(unittest.TestCase):
    """Tests for _determine_balancing_mode()."""

    def setUp(self):
        """Set up logger for each test."""
        logger.setup_logging()

    def test_returns_cpu_mode_when_cpu_exceeded(self):
        """Returns 'cpu' mode when a node exceeds cpu_max."""
        nodes = [
            {"node": "node1", "cpu": 0.9},
            {"node": "node2", "cpu": 0.5},
        ]
        mode, reason = balancer._determine_balancing_mode(
            nodes, cpu_max=0.8, memory_max=0.8, memory_threshold=0.7
        )
        self.assertEqual(mode, "cpu")
        self.assertEqual(reason, "CPU maximum exceeded")

    def test_returns_mem_mode_when_memory_exceeded(self):
        """Returns 'mem' mode when a node exceeds memory_max."""
        nodes = [
            {"node": "node1", "cpu": 0.5, "maxmem": 1000, "mem": 900},  # 90%
            {"node": "node2", "cpu": 0.5, "maxmem": 1000, "mem": 500},  # 50%
        ]
        mode, reason = balancer._determine_balancing_mode(
            nodes, cpu_max=0.8, memory_max=0.8, memory_threshold=0.7
        )
        self.assertEqual(mode, "mem")
        self.assertEqual(reason, "Memory maximum exceeded")

    def test_returns_proactive_mem_mode_when_threshold_exceeded(self):
        """Returns 'mem' mode with proactive balancing when memory threshold exceeded."""
        nodes = [
            {"node": "node1", "cpu": 0.5, "maxmem": 1000, "mem": 750},  # 75%
            {"node": "node2", "cpu": 0.5, "maxmem": 1000, "mem": 500},  # 50%
        ]
        mode, reason = balancer._determine_balancing_mode(
            nodes, cpu_max=0.8, memory_max=0.8, memory_threshold=0.7
        )
        self.assertEqual(mode, "mem")
        self.assertEqual(reason, "Proactive balancing")

    def test_returns_none_when_no_balancing_needed(self):
        """Returns (None, None) when no thresholds are exceeded."""
        nodes = [
            {"node": "node1", "cpu": 0.5, "maxmem": 1000, "mem": 400},  # 40%
            {"node": "node2", "cpu": 0.5, "maxmem": 1000, "mem": 300},  # 30%
        ]
        mode, reason = balancer._determine_balancing_mode(
            nodes, cpu_max=0.8, memory_max=0.8, memory_threshold=0.7
        )
        self.assertIsNone(mode)
        self.assertIsNone(reason)

    def test_cpu_check_takes_precedence_over_memory(self):
        """CPU check is evaluated before memory checks."""
        nodes = [
            {"node": "node1", "cpu": 0.9, "maxmem": 1000, "mem": 900},  # 90% CPU, 90% mem
        ]
        mode, reason = balancer._determine_balancing_mode(
            nodes, cpu_max=0.8, memory_max=0.8, memory_threshold=0.7
        )
        self.assertEqual(mode, "cpu")
        self.assertEqual(reason, "CPU maximum exceeded")

    def test_memory_max_check_takes_precedence_over_threshold(self):
        """Memory max check is evaluated before proactive threshold."""
        nodes = [
            {"node": "node1", "cpu": 0.5, "maxmem": 1000, "mem": 900},  # 90% mem
        ]
        mode, reason = balancer._determine_balancing_mode(
            nodes, cpu_max=0.8, memory_max=0.8, memory_threshold=0.7
        )
        self.assertEqual(mode, "mem")
        self.assertEqual(reason, "Memory maximum exceeded")


class TestSelectSourceAndTargets(unittest.TestCase):
    """Tests for _select_source_and_targets()."""

    def test_selects_highest_cpu_node_as_source_for_cpu_mode(self):
        """Selects the node with highest CPU as source in CPU mode."""
        nodes = [
            {"node": "node1", "cpu": 0.9},
            {"node": "node2", "cpu": 0.7},
            {"node": "node3", "cpu": 0.5},
        ]
        source, targets = balancer._select_source_and_targets(nodes, mode="cpu")
        self.assertEqual(source["node"], "node1")
        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0]["node"], "node2")
        self.assertEqual(targets[1]["node"], "node3")

    def test_selects_highest_memory_node_as_source_for_mem_mode(self):
        """Selects the node with highest memory as source in memory mode."""
        nodes = [
            {"node": "node1", "maxmem": 1000, "mem": 900},  # 90%
            {"node": "node2", "maxmem": 1000, "mem": 700},  # 70%
            {"node": "node3", "maxmem": 1000, "mem": 500},  # 50%
        ]
        source, targets = balancer._select_source_and_targets(nodes, mode="mem")
        self.assertEqual(source["node"], "node1")
        self.assertEqual(len(targets), 2)

    def test_returns_remaining_nodes_as_targets(self):
        """Returns all nodes except source as targets."""
        nodes = [
            {"node": "node1", "cpu": 0.9},
            {"node": "node2", "cpu": 0.7},
            {"node": "node3", "cpu": 0.5},
            {"node": "node4", "cpu": 0.3},
        ]
        source, targets = balancer._select_source_and_targets(nodes, mode="cpu")
        self.assertEqual(len(targets), 3)
        target_nodes = {t["node"] for t in targets}
        self.assertEqual(target_nodes, {"node2", "node3", "node4"})

    def test_targets_are_sorted_by_utilization(self):
        """Target nodes are sorted by utilization in descending order."""
        nodes = [
            {"node": "node1", "cpu": 0.9},
            {"node": "node2", "cpu": 0.4},
            {"node": "node3", "cpu": 0.7},
        ]
        source, targets = balancer._select_source_and_targets(nodes, mode="cpu")
        self.assertEqual(targets[0]["node"], "node3")  # 70%
        self.assertEqual(targets[1]["node"], "node2")  # 40%


class TestSelectBestTarget(unittest.TestCase):
    """Tests for _select_best_target()."""

    def test_selects_lowest_cpu_node_for_cpu_mode(self):
        """Selects the node with lowest CPU for CPU mode."""
        nodes = [
            {"node": "node1", "cpu": 0.3},
            {"node": "node2", "cpu": 0.5},
            {"node": "node3", "cpu": 0.2},
        ]
        target = balancer._select_best_target(nodes, mode="cpu")
        self.assertEqual(target["node"], "node3")

    def test_selects_lowest_memory_node_for_mem_mode(self):
        """Selects the node with lowest memory for memory mode."""
        nodes = [
            {"node": "node1", "maxmem": 1000, "mem": 300},  # 30%
            {"node": "node2", "maxmem": 1000, "mem": 500},  # 50%
            {"node": "node3", "maxmem": 1000, "mem": 200},  # 20%
        ]
        target = balancer._select_best_target(nodes, mode="mem")
        self.assertEqual(target["node"], "node3")

    def test_returns_first_node_when_single_target(self):
        """Returns the only node when there's a single target."""
        nodes = [{"node": "node1", "cpu": 0.5}]
        target = balancer._select_best_target(nodes, mode="cpu")
        self.assertEqual(target["node"], "node1")


if __name__ == "__main__":
    unittest.main()
