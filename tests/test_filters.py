"""Unit tests for the filters module."""

import unittest
from unittest.mock import MagicMock, patch
import sys
import os
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from balancer import filters
from balancer import logger


class TestFilterResources(unittest.TestCase):
    """Tests for filter_resources function."""

    def setUp(self):
        """Set up logging for tests."""
        logger.setup_logging({"logging": {"level": "DEBUG"}})

    def test_filters_to_source_node(self):
        """Should return only resources on the specified node."""
        resources = [
            {"node": "node1", "vmid": 100},
            {"node": "node2", "vmid": 200},
            {"node": "node1", "vmid": 300},
        ]
        result = filters.filter_resources(resources, "node1")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["vmid"], 100)
        self.assertEqual(result[1]["vmid"], 300)

    def test_empty_resources(self):
        """Should return empty list when no resources match."""
        resources = [
            {"node": "node2", "vmid": 200},
        ]
        result = filters.filter_resources(resources, "node1")
        self.assertEqual(len(result), 0)

    def test_no_matching_node(self):
        """Should return empty list when node doesn't exist."""
        resources = [
            {"node": "node1", "vmid": 100},
        ]
        result = filters.filter_resources(resources, "nonexistent")
        self.assertEqual(len(result), 0)


class TestFilterRunning(unittest.TestCase):
    """Tests for filter_running function."""

    def test_filters_to_running_only(self):
        """Should return only running VMs."""
        candidates = [
            {"vmid": 100, "status": "running"},
            {"vmid": 200, "status": "stopped"},
            {"vmid": 300, "status": "running"},
            {"vmid": 400, "status": "paused"},
        ]
        result = filters.filter_running(candidates)
        self.assertEqual(len(result), 2)
        vmids = [c["vmid"] for c in result]
        self.assertIn(100, vmids)
        self.assertIn(300, vmids)

    def test_all_stopped(self):
        """Should return empty list when all VMs are stopped."""
        candidates = [
            {"vmid": 100, "status": "stopped"},
            {"vmid": 200, "status": "stopped"},
        ]
        result = filters.filter_running(candidates)
        self.assertEqual(len(result), 0)

    def test_all_running(self):
        """Should return all candidates when all are running."""
        candidates = [
            {"vmid": 100, "status": "running"},
            {"vmid": 200, "status": "running"},
        ]
        result = filters.filter_running(candidates)
        self.assertEqual(len(result), 2)


class TestFilterNoLock(unittest.TestCase):
    """Tests for filter_no_lock function."""

    def test_filters_out_locked_vms(self):
        """Should exclude VMs with a lock key."""
        candidates = [
            {"vmid": 100, "status": "running"},
            {"vmid": 200, "status": "running", "lock": "migrate"},
            {"vmid": 300, "status": "running"},
        ]
        result = filters.filter_no_lock(candidates)
        self.assertEqual(len(result), 2)
        vmids = [c["vmid"] for c in result]
        self.assertNotIn(200, vmids)

    def test_all_locked(self):
        """Should return empty list when all VMs have locks."""
        candidates = [
            {"vmid": 100, "lock": "migrate"},
            {"vmid": 200, "lock": "migrate"},
        ]
        result = filters.filter_no_lock(candidates)
        self.assertEqual(len(result), 0)

    def test_none_locked(self):
        """Should return all candidates when none have locks."""
        candidates = [
            {"vmid": 100, "status": "running"},
            {"vmid": 200, "status": "running"},
        ]
        result = filters.filter_no_lock(candidates)
        self.assertEqual(len(result), 2)


class TestFilterMemoryConstraints(unittest.TestCase):
    """Tests for filter_memory_constraints function."""

    def test_filters_out_nodes_exceeding_memory_max(self):
        """Should exclude nodes that would exceed memory_max * 0.9."""
        target_nodes = [
            {"node": "node1", "mem": 4000, "maxmem": 16000},
            {"node": "node2", "mem": 8000, "maxmem": 16000},
        ]
        candidate = {"vmid": 100, "mem": 4000}
        memory_max = 0.8
        result = filters.filter_memory_constraints(target_nodes, candidate, memory_max)
        # node1: (4000 + 4000) / 16000 = 0.5 < 0.72 ✓
        # node2: (8000 + 4000) / 16000 = 0.75 > 0.72 ✗
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["node"], "node1")

    def test_all_nodes_exceed(self):
        """Should return empty list when all nodes would exceed."""
        target_nodes = [
            {"node": "node1", "mem": 10000, "maxmem": 16000},
        ]
        candidate = {"vmid": 100, "mem": 4000}
        memory_max = 0.8
        result = filters.filter_memory_constraints(target_nodes, candidate, memory_max)
        self.assertEqual(len(result), 0)

    def test_all_nodes_fit(self):
        """Should return all nodes when none would exceed."""
        target_nodes = [
            {"node": "node1", "mem": 2000, "maxmem": 16000},
            {"node": "node2", "mem": 3000, "maxmem": 16000},
        ]
        candidate = {"vmid": 100, "mem": 2000}
        memory_max = 0.8
        result = filters.filter_memory_constraints(target_nodes, candidate, memory_max)
        self.assertEqual(len(result), 2)


class TestFilterCpuConstraints(unittest.TestCase):
    """Tests for filter_cpu_constraints function."""

    def test_filters_out_nodes_exceeding_cpu_max(self):
        """Should exclude nodes that would exceed cpu_max * 0.9."""
        target_nodes = [
            {"node": "node1", "cpu": 0.3, "maxcpu": 16},
            {"node": "node2", "cpu": 0.6, "maxcpu": 16},
        ]
        candidate = {"vmid": 100, "cpu": 0.1, "maxcpu": 4}
        source_node = {"maxcpu": 16}
        cpu_max = 0.8
        result = filters.filter_cpu_constraints(
            target_nodes, candidate, source_node, cpu_max
        )
        # Scaled CPU contribution: 0.1 * 4 / 16 * 16/16 = 0.025
        # node1: 0.3 + 0.025 = 0.325 < 0.72 ✓
        # node2: 0.6 + 0.025 = 0.625 < 0.72 ✓
        self.assertEqual(len(result), 2)

    def test_node_exceeds_cpu_max(self):
        """Should exclude nodes that would exceed threshold."""
        target_nodes = [
            {"node": "node1", "cpu": 0.7, "maxcpu": 16},
        ]
        candidate = {"vmid": 100, "cpu": 0.1, "maxcpu": 4}
        source_node = {"maxcpu": 16}
        cpu_max = 0.8
        result = filters.filter_cpu_constraints(
            target_nodes, candidate, source_node, cpu_max
        )
        # Scaled CPU: 0.1 * 4 / 16 * 16/16 = 0.025
        # node1: 0.7 + 0.025 = 0.725 > 0.72 ✗
        self.assertEqual(len(result), 0)


class TestFilterMemoryBalance(unittest.TestCase):
    """Tests for filter_memory_balance function."""

    def test_filters_out_unbalanced_migrations(self):
        """Should exclude nodes where migration would not meet-in-the-middle."""
        target_nodes = [
            {"node": "node1", "mem": 2000, "maxmem": 16000},
            {"node": "node2", "mem": 10000, "maxmem": 16000},
        ]
        candidate = {"vmid": 100, "mem": 4000}
        source_node = {"mem": 12000, "maxmem": 16000}
        result = filters.filter_memory_balance(target_nodes, candidate, source_node)
        # source: 12000/16000 = 0.75
        # node1 after: (2000+4000)/16000 = 0.375, midpoint with source = 0.5625, 0.375 < 0.5625 ✓
        # node2 after: (10000+4000)/16000 = 0.875, midpoint with source = 0.8125, 0.875 > 0.8125 ✗
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["node"], "node1")

    def test_all_nodes_create_imbalance(self):
        """Should return empty list when all migrations create imbalance."""
        target_nodes = [
            {"node": "node1", "mem": 10000, "maxmem": 16000},
        ]
        candidate = {"vmid": 100, "mem": 4000}
        source_node = {"mem": 12000, "maxmem": 16000}
        result = filters.filter_memory_balance(target_nodes, candidate, source_node)
        self.assertEqual(len(result), 0)


class TestFilterCpuBalance(unittest.TestCase):
    """Tests for filter_cpu_balance function."""

    def test_filters_out_unbalanced_migrations(self):
        """Should exclude nodes where migration would not meet-in-the-middle."""
        target_nodes = [
            {"node": "node1", "cpu": 0.3, "maxcpu": 16},
            {"node": "node2", "cpu": 0.7, "maxcpu": 16},
        ]
        candidate = {"vmid": 100, "cpu": 0.1, "maxcpu": 4}
        source_node = {"cpu": 0.8, "maxcpu": 16}
        result = filters.filter_cpu_balance(target_nodes, candidate, source_node)
        # Scaled CPU: 0.1 * 4 / 16 * 16/16 = 0.025
        # node1 after: 0.3 + 0.025 = 0.325, midpoint = (0.8+0.3)/2 = 0.55, 0.325 < 0.55 ✓
        # node2 after: 0.7 + 0.025 = 0.725, midpoint = (0.8+0.7)/2 = 0.75, 0.725 < 0.75 ✓
        self.assertEqual(len(result), 2)

    def test_node_creates_imbalance(self):
        """Should exclude nodes that would create imbalance."""
        target_nodes = [
            {"node": "node1", "cpu": 0.75, "maxcpu": 16},
        ]
        candidate = {"vmid": 100, "cpu": 0.1, "maxcpu": 4}
        source_node = {"cpu": 0.8, "maxcpu": 16}
        result = filters.filter_cpu_balance(target_nodes, candidate, source_node)
        # Scaled CPU: 0.025
        # node1 after: 0.775, midpoint = 0.775, 0.775 < 0.775 ✗ (not strictly less)
        self.assertEqual(len(result), 0)


class TestFilterOnlineNodes(unittest.TestCase):
    """Tests for filter_online_nodes function."""

    def test_filters_to_online_only(self):
        """Should return only online nodes."""
        nodes = [
            {"node": "node1", "status": "online"},
            {"node": "node2", "status": "offline"},
            {"node": "node3", "status": "online"},
        ]
        result = filters.filter_online_nodes(nodes)
        self.assertEqual(len(result), 2)
        nodenames = [n["node"] for n in result]
        self.assertIn("node1", nodenames)
        self.assertIn("node3", nodenames)

    def test_all_offline(self):
        """Should return empty list when all nodes are offline."""
        nodes = [
            {"node": "node1", "status": "offline"},
            {"node": "node2", "status": "offline"},
        ]
        result = filters.filter_online_nodes(nodes)
        self.assertEqual(len(result), 0)


class TestFilterMigrationLock(unittest.TestCase):
    """Tests for filter_migration_lock function."""

    def test_returns_true_when_lock_exists(self):
        """Should return True when any resource has migrate lock."""
        resources = [
            {"vmid": 100, "status": "running"},
            {"vmid": 200, "status": "running", "lock": "migrate"},
        ]
        result = filters.filter_migration_lock(resources)
        self.assertTrue(result)

    def test_returns_false_when_no_locks(self):
        """Should return False when no resources have locks."""
        resources = [
            {"vmid": 100, "status": "running"},
            {"vmid": 200, "status": "running"},
        ]
        result = filters.filter_migration_lock(resources)
        self.assertFalse(result)

    def test_empty_resources(self):
        """Should return False for empty resource list."""
        resources = []
        result = filters.filter_migration_lock(resources)
        self.assertFalse(result)


class TestFilterHaRules(unittest.TestCase):
    """Tests for filter_ha_rules function."""

    def setUp(self):
        """Set up logging for tests."""
        logger.setup_logging({"logging": {"level": "DEBUG"}})

    def test_excludes_nodes_with_anti_affinity(self):
        """Should exclude nodes that have VMs with anti-affinity rules."""
        target_nodes = [
            {"node": "node1"},
            {"node": "node2"},
        ]
        candidate = {"vmid": 100, "name": "vm100"}
        resources = [
            {"vmid": 100, "node": "node1"},  # candidate is on node1
            {"vmid": 200, "node": "node2"},  # vm:200 is on node2
        ]
        ha_rules = [
            {
                "resources": "vm:100,vm:200",
                "type": "resource-affinity",
                "affinity": "negative",
            }
        ]
        result = filters.filter_ha_rules(target_nodes, candidate, resources, ha_rules)
        # vm:100 and vm:200 have anti-affinity
        # vm:200 is on node2, so node2 should be excluded as a target
        # The candidate (vm:100) is on node1, but node1 is also excluded because
        # when iterating rule_resources, vm:100 is found on node1
        # So both nodes get excluded
        self.assertEqual(len(result), 0)

    def test_excludes_all_with_positive_affinity(self):
        """Should return empty list when candidate has positive affinity."""
        target_nodes = [
            {"node": "node1"},
            {"node": "node2"},
        ]
        candidate = {"vmid": 100, "name": "vm100"}
        resources = []
        ha_rules = [
            {
                "resources": "vm:100",
                "type": "resource-affinity",
                "affinity": "positive",
            }
        ]
        result = filters.filter_ha_rules(target_nodes, candidate, resources, ha_rules)
        self.assertEqual(len(result), 0)

    def test_no_ha_rules(self):
        """Should return all nodes when no HA rules exist."""
        target_nodes = [
            {"node": "node1"},
            {"node": "node2"},
        ]
        candidate = {"vmid": 100, "name": "vm100"}
        resources = []
        ha_rules = []
        result = filters.filter_ha_rules(target_nodes, candidate, resources, ha_rules)
        self.assertEqual(len(result), 2)

    def test_node_affinity_excludes_all(self):
        """Should return empty list when candidate has node affinity."""
        target_nodes = [
            {"node": "node1"},
            {"node": "node2"},
        ]
        candidate = {"vmid": 100, "name": "vm100"}
        resources = []
        ha_rules = [
            {
                "resources": "vm:100",
                "type": "node-affinity",
                "affinity": "",
            }
        ]
        result = filters.filter_ha_rules(target_nodes, candidate, resources, ha_rules)
        self.assertEqual(len(result), 0)


if __name__ == "__main__":
    unittest.main()
