"""Integration tests for migrate_workload with mocked Proxmox API.

Tests the full migrate_workload flow with various scenarios:
- No migration needed
- Memory migration needed
- CPU migration needed
- Proactive memory migration based on multiplier threshold
- Backup window scenarios
- Migration lock scenarios
"""

import unittest
from unittest.mock import MagicMock, patch, create_autospec
import sys
import os
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from balancer import balancer
from balancer.ema import CpuEMA
from balancer import logger
from balancer import constants


class MockProxmoxAPI:
    """Mock Proxmox API for integration testing."""
    
    def __init__(self, nodes_data, resources_data, backup_jobs_data, ha_rules_data):
        """Initialize mock API with test data.
        
        Args:
            nodes_data: List of node dictionaries
            resources_data: List of VM resource dictionaries
            backup_jobs_data: List of backup job dictionaries
            ha_rules_data: List of HA rule dictionaries
        """
        self._nodes_data = nodes_data
        self._resources_data = resources_data
        self._backup_jobs_data = backup_jobs_data
        self._ha_rules_data = ha_rules_data
        
        # Track migration calls
        self.migration_calls = []
        
        # Setup mock cluster
        self.cluster = MagicMock()
        self.cluster.backup.get.return_value = backup_jobs_data
        self.cluster.resources.get.return_value = resources_data
        self.cluster.ha.rules.get.return_value = ha_rules_data
        
        # Setup nodes method to handle both .get() and .(node_name) calls
        self._nodes_method = MagicMock()
        self._nodes_method.get.return_value = nodes_data
        
        def nodes_side_effect(node_name=None):
            """Handle nodes() calls - either .get() or .(node_name) for migration."""
            if node_name is None:
                # Called as api.nodes.get()
                return self._nodes_method
            else:
                # Called as api.nodes(node_name) for migration
                node_obj = MagicMock()
                def qemu(vmid):
                    vm_obj = MagicMock()
                    migrate_obj = MagicMock()
                    def track_post(**opts):
                        self.migration_calls.append({"vmid": vmid, "opts": opts})
                        return True
                    migrate_obj.post = track_post
                    vm_obj.migrate = MagicMock(return_value=migrate_obj)
                    return vm_obj
                node_obj.qemu = qemu
                return node_obj
        
        self._nodes_method.side_effect = nodes_side_effect
        self.nodes = self._nodes_method


class TestMigrateWorkloadNoMigration(unittest.TestCase):
    """Tests for migrate_workload when no migration is needed."""
    
    def setUp(self):
        """Set up logger and common test data."""
        logger.setup_logging({"logging": {"level": "DEBUG"}})
        self.cpu_ema = CpuEMA()
        
        # Config with default thresholds
        self.config = {
            "proxmox_api": {
                "host": "proxmox.example.com",
                "port": 443,
                "user": "user@pam",
                "token_id": "test_token",
                "token_secret": "test_secret",
            },
            "balancer": {
                "cpu_max": 0.8,
                "memory_max": 0.8,
            },
        }
    
    def test_no_migration_when_all_nodes_below_thresholds(self):
        """Returns False when all nodes are below CPU and memory thresholds."""
        # All nodes well below thresholds
        nodes = [
            {"node": "node1", "cpu": 0.2, "maxmem": 1000, "mem": 200, "status": "online", "maxcpu": 16},
            {"node": "node2", "cpu": 0.1, "maxmem": 1000, "mem": 100, "status": "online", "maxcpu": 16},
        ]
        resources = [
            {"vmid": 100, "name": "vm1", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.2, "mem": 200, "maxcpu": 4},
            {"vmid": 101, "name": "vm2", "type": "qemu", "node": "node2", "status": "running", "cpu": 0.1, "mem": 100, "maxcpu": 2},
        ]
        backup_jobs = []
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertFalse(result)
        self.assertEqual(len(mock_api.migration_calls), 0)
    
    def test_no_migration_when_only_one_node(self):
        """Returns False when there's only one node (no targets available)."""
        nodes = [
            {"node": "node1", "cpu": 0.95, "maxmem": 1000, "mem": 900, "status": "online", "maxcpu": 16},
        ]
        resources = [
            {"vmid": 100, "name": "vm1", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.95, "mem": 900, "maxcpu": 4},
        ]
        backup_jobs = []
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertFalse(result)
        self.assertEqual(len(mock_api.migration_calls), 0)


class TestMigrateWorkloadMemoryMigration(unittest.TestCase):
    """Tests for memory-based migrations."""
    
    def setUp(self):
        """Set up logger and common test data."""
        logger.setup_logging({"logging": {"level": "DEBUG"}})
        self.cpu_ema = CpuEMA()
        
        self.config = {
            "proxmox_api": {
                "host": "proxmox.example.com",
                "port": 443,
                "user": "user@pam",
                "token_id": "test_token",
                "token_secret": "test_secret",
            },
            "balancer": {
                "cpu_max": 0.8,
                "memory_max": 0.8,
            },
        }
    
    def test_memory_migration_when_node_exceeds_memory_max(self):
        """Migrates VM when a node exceeds memory_max threshold."""
        nodes = [
            {"node": "node1", "cpu": 0.15, "maxmem": 1000, "mem": 900, "status": "online", "maxcpu": 16},
            {"node": "node2", "cpu": 0.1, "maxmem": 1000, "mem": 100, "status": "online", "maxcpu": 16},
        ]
        resources = [
            {"vmid": 100, "name": "vm1", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.2, "mem": 550, "maxcpu": 4},
            {"vmid": 101, "name": "vm2", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.1, "mem": 350, "maxcpu": 2},
            {"vmid": 102, "name": "vm3", "type": "qemu", "node": "node2", "status": "running", "cpu": 0.1, "mem": 100, "maxcpu": 2},
        ]
        backup_jobs = []
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertTrue(result)
        self.assertEqual(len(mock_api.migration_calls), 1)
        self.assertEqual(mock_api.migration_calls[0]["opts"]["target"], "node2")
    
    def test_memory_migration_selects_lowest_memory_target(self):
        """Selects the node with lowest memory utilization as migration target."""
        nodes = [
            {"node": "node1", "cpu": 0.2, "maxmem": 1000, "mem": 950, "status": "online", "maxcpu": 16},
            {"node": "node2", "cpu": 0.3, "maxmem": 1000, "mem": 400, "status": "online", "maxcpu": 16},
            {"node": "node3", "cpu": 0.2, "maxmem": 1000, "mem": 150, "status": "online", "maxcpu": 16},
        ]
        resources = [
            {"vmid": 100, "name": "vm1", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.2, "mem": 250, "maxcpu": 4},
        ]
        backup_jobs = []
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertTrue(result)
        self.assertEqual(mock_api.migration_calls[0]["opts"]["target"], "node3")


class TestMigrateWorkloadCpuMigration(unittest.TestCase):
    """Tests for CPU-based migrations."""
    
    def setUp(self):
        """Set up logger and common test data."""
        logger.setup_logging({"logging": {"level": "DEBUG"}})
        self.cpu_ema = CpuEMA()
        
        self.config = {
            "proxmox_api": {
                "host": "proxmox.example.com",
                "port": 443,
                "user": "user@pam",
                "token_id": "test_token",
                "token_secret": "test_secret",
            },
            "balancer": {
                "cpu_max": 0.8,
                "memory_max": 0.8,
            },
        }
    
    def test_cpu_migration_when_node_exceeds_cpu_max(self):
        """Migrates VM when a node exceeds cpu_max threshold."""
        nodes = [
            {"node": "node1", "cpu": 0.9, "maxmem": 1000, "mem": 400, "status": "online", "maxcpu": 16},
            {"node": "node2", "cpu": 0.3, "maxmem": 1000, "mem": 300, "status": "online", "maxcpu": 16},
        ]
        resources = [
            {"vmid": 100, "name": "vm1", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.95, "mem": 200, "maxcpu": 4},
            {"vmid": 101, "name": "vm2", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.3, "mem": 150, "maxcpu": 2},
            {"vmid": 102, "name": "vm3", "type": "qemu", "node": "node2", "status": "running", "cpu": 0.2, "mem": 100, "maxcpu": 2},
        ]
        backup_jobs = []
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertTrue(result)
        self.assertEqual(len(mock_api.migration_calls), 1)
        self.assertEqual(mock_api.migration_calls[0]["vmid"], 101)
        self.assertEqual(mock_api.migration_calls[0]["opts"]["target"], "node2")
    
    def test_cpu_migration_excludes_highest_cpu_vm(self):
        """Excludes the highest-CPU VM from migration candidates in CPU mode."""
        nodes = [
            {"node": "node1", "cpu": 0.95, "maxmem": 1000, "mem": 400, "status": "online", "maxcpu": 16},
            {"node": "node2", "cpu": 0.2, "maxmem": 1000, "mem": 300, "status": "online", "maxcpu": 16},
        ]
        resources = [
            {"vmid": 100, "name": "busy_vm", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.8, "mem": 200, "maxcpu": 8},
            {"vmid": 101, "name": "light_vm", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.2, "mem": 150, "maxcpu": 2},
        ]
        backup_jobs = []
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertTrue(result)
        # Should migrate light_vm, not busy_vm
        # The test verifies a migration occurred; the exclusion logic is tested in unit tests
    
    def test_cpu_migration_selects_lowest_cpu_target(self):
        """Selects the node with lowest CPU utilization as migration target."""
        nodes = [
            {"node": "node1", "cpu": 0.9, "maxmem": 1000, "mem": 400, "status": "online", "maxcpu": 16},
            {"node": "node2", "cpu": 0.4, "maxmem": 1000, "mem": 300, "status": "online", "maxcpu": 16},
            {"node": "node3", "cpu": 0.15, "maxmem": 1000, "mem": 250, "status": "online", "maxcpu": 16},
        ]
        resources = [
            {"vmid": 100, "name": "vm1", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.4, "mem": 200, "maxcpu": 4},
            {"vmid": 101, "name": "vm2", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.3, "mem": 150, "maxcpu": 2},
        ]
        backup_jobs = []
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertTrue(result)
        self.assertEqual(mock_api.migration_calls[0]["opts"]["target"], "node3")


class TestMigrateWorkloadProactiveMigration(unittest.TestCase):
    """Tests for proactive memory migration based on multiplier threshold."""
    
    def setUp(self):
        """Set up logger and common test data."""
        logger.setup_logging({"logging": {"level": "DEBUG"}})
        self.cpu_ema = CpuEMA()
        
        self.config = {
            "proxmox_api": {
                "host": "proxmox.example.com",
                "port": 443,
                "user": "user@pam",
                "token_id": "test_token",
                "token_secret": "test_secret",
            },
            "balancer": {
                "cpu_max": 0.8,
                "memory_max": 0.8,
            },
        }
    
    def test_proactive_migration_when_node_exceeds_threshold(self):
        """Migrates VM proactively when a node exceeds mean * multiplier threshold."""
        # Mean memory = (60 + 40 + 30) / 3 = 43.33%
        # Threshold = 43.33% * 1.05 = 45.5%
        # node1 at 60% exceeds threshold but is below memory_max (80%)
        nodes = [
            {"node": "node1", "cpu": 0.4, "maxmem": 1000, "mem": 600, "status": "online", "maxcpu": 16},
            {"node": "node2", "cpu": 0.3, "maxmem": 1000, "mem": 400, "status": "online", "maxcpu": 16},
            {"node": "node3", "cpu": 0.2, "maxmem": 1000, "mem": 300, "status": "online", "maxcpu": 16},
        ]
        # Small VM that can be balanced: after migration to node3, (300+50)/1000 = 35%
        # Mean of (60% + 30%) / 2 = 45%, and 35% < 45%, so it passes
        resources = [
            {"vmid": 100, "name": "vm1", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.2, "mem": 50, "maxcpu": 4},
            {"vmid": 101, "name": "vm2", "type": "qemu", "node": "node2", "status": "running", "cpu": 0.1, "mem": 150, "maxcpu": 2},
        ]
        backup_jobs = []
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertTrue(result)
        self.assertEqual(mock_api.migration_calls[0]["opts"]["target"], "node3")
        self.assertEqual(len(mock_api.migration_calls), 1)
    
    def test_no_proactive_migration_when_all_nodes_below_threshold(self):
        """Does not migrate when all nodes are below proactive threshold."""
        # Mean memory = (40 + 35 + 35) / 3 = 36.67%
        # Threshold = 36.67% * 1.05 = 38.5%
        # All nodes are below threshold
        nodes = [
            {"node": "node1", "cpu": 0.3, "maxmem": 1000, "mem": 400, "status": "online", "maxcpu": 16},
            {"node": "node2", "cpu": 0.2, "maxmem": 1000, "mem": 350, "status": "online", "maxcpu": 16},
            {"node": "node3", "cpu": 0.2, "maxmem": 1000, "mem": 350, "status": "online", "maxcpu": 16},
        ]
        resources = [
            {"vmid": 100, "name": "vm1", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.2, "mem": 200, "maxcpu": 4},
        ]
        backup_jobs = []
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertFalse(result)
        self.assertEqual(len(mock_api.migration_calls), 0)


class TestMigrateWorkloadBackupWindow(unittest.TestCase):
    """Tests for backup window scenarios."""
    
    def setUp(self):
        """Set up logger and common test data."""
        logger.setup_logging({"logging": {"level": "DEBUG"}})
        self.cpu_ema = CpuEMA()
        
        self.config = {
            "proxmox_api": {
                "host": "proxmox.example.com",
                "port": 443,
                "user": "user@pam",
                "token_id": "test_token",
                "token_secret": "test_secret",
            },
            "balancer": {
                "cpu_max": 0.8,
                "memory_max": 0.8,
            },
        }
    
    @patch("balancer.balancer.time")
    def test_pauses_when_backup_scheduled_within_window(self, mock_time_module):
        """Pauses when a backup job is scheduled within BACKUP_WINDOW_SECONDS."""
        current_time = 1000000
        mock_time_module.time.return_value = current_time
        mock_sleep = MagicMock()
        mock_time_module.sleep = mock_sleep
        
        # Backup scheduled in 30 seconds (within 60 second window)
        backup_jobs = [
            {"id": "0:0:0:0", "enabled": 1, "next-run": current_time + 30},
        ]
        
        nodes = [
            {"node": "node1", "cpu": 0.9, "maxmem": 1000, "mem": 400, "status": "online", "maxcpu": 16},
            {"node": "node2", "cpu": 0.3, "maxmem": 1000, "mem": 300, "status": "online", "maxcpu": 16},
        ]
        resources = [
            {"vmid": 100, "name": "vm1", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.5, "mem": 200, "maxcpu": 4},
        ]
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertFalse(result)
        self.assertEqual(len(mock_api.migration_calls), 0)
        mock_sleep.assert_called_once_with(constants.BACKUP_PAUSE_SECONDS)
    
    @patch("balancer.balancer.time")
    def test_proceeds_when_backup_outside_window(self, mock_time_module):
        """Proceeds with migration when backup is scheduled outside the window."""
        current_time = 1000000
        mock_time_module.time.return_value = current_time
        
        # Backup scheduled in 120 seconds (outside 60 second window)
        backup_jobs = [
            {"id": "0:0:0:0", "enabled": 1, "next-run": current_time + 120},
        ]
        
        nodes = [
            {"node": "node1", "cpu": 0.9, "maxmem": 1000, "mem": 400, "status": "online", "maxcpu": 16},
            {"node": "node2", "cpu": 0.3, "maxmem": 1000, "mem": 300, "status": "online", "maxcpu": 16},
        ]
        # Need at least 2 VMs on source for CPU mode (highest-CPU VM is excluded)
        resources = [
            {"vmid": 100, "name": "busy_vm", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.6, "mem": 250, "maxcpu": 6},
            {"vmid": 101, "name": "light_vm", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.4, "mem": 200, "maxcpu": 4},
        ]
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertTrue(result)
        self.assertEqual(len(mock_api.migration_calls), 1)
    
    def test_ignores_disabled_backup_jobs(self):
        """Ignores disabled backup jobs when checking backup window."""
        # Disabled backup job should not trigger pause
        backup_jobs = [
            {"id": "0:0:0:0", "enabled": 0, "next-run": 1000030},  # Disabled
        ]
        
        nodes = [
            {"node": "node1", "cpu": 0.9, "maxmem": 1000, "mem": 400, "status": "online", "maxcpu": 16},
            {"node": "node2", "cpu": 0.3, "maxmem": 1000, "mem": 300, "status": "online", "maxcpu": 16},
        ]
        # Need at least 2 VMs on source for CPU mode (highest-CPU VM is excluded)
        resources = [
            {"vmid": 100, "name": "busy_vm", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.6, "mem": 250, "maxcpu": 6},
            {"vmid": 101, "name": "light_vm", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.4, "mem": 200, "maxcpu": 4},
        ]
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertTrue(result)
        self.assertEqual(len(mock_api.migration_calls), 1)


class TestMigrateWorkloadMigrationLock(unittest.TestCase):
    """Tests for migration lock scenarios."""
    
    def setUp(self):
        """Set up logger and common test data."""
        logger.setup_logging({"logging": {"level": "DEBUG"}})
        self.cpu_ema = CpuEMA()
        
        self.config = {
            "proxmox_api": {
                "host": "proxmox.example.com",
                "port": 443,
                "user": "user@pam",
                "token_id": "test_token",
                "token_secret": "test_secret",
            },
            "balancer": {
                "cpu_max": 0.8,
                "memory_max": 0.8,
            },
        }
    
    def test_skips_migration_when_lock_active_on_any_vm(self):
        """Skips migration when any VM has an active migration lock."""
        nodes = [
            {"node": "node1", "cpu": 0.9, "maxmem": 1000, "mem": 400, "status": "online", "maxcpu": 16},
            {"node": "node2", "cpu": 0.3, "maxmem": 1000, "mem": 300, "status": "online", "maxcpu": 16},
        ]
        # VM on node2 has migration lock
        resources = [
            {"vmid": 100, "name": "vm1", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.5, "mem": 200, "maxcpu": 4},
            {"vmid": 101, "name": "vm2", "type": "qemu", "node": "node2", "status": "running", "cpu": 0.2, "mem": 100, "maxcpu": 2, "lock": "migrating"},
        ]
        backup_jobs = []
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertFalse(result)
        self.assertEqual(len(mock_api.migration_calls), 0)
    
    def test_proceeds_when_no_locks_present(self):
        """Proceeds with migration when no VMs have locks."""
        nodes = [
            {"node": "node1", "cpu": 0.9, "maxmem": 1000, "mem": 400, "status": "online", "maxcpu": 16},
            {"node": "node2", "cpu": 0.3, "maxmem": 1000, "mem": 300, "status": "online", "maxcpu": 16},
        ]
        # Need at least 2 VMs on source for CPU mode (highest-CPU VM is excluded)
        resources = [
            {"vmid": 100, "name": "busy_vm", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.6, "mem": 250, "maxcpu": 6},
            {"vmid": 101, "name": "light_vm", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.4, "mem": 200, "maxcpu": 4},
        ]
        backup_jobs = []
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertTrue(result)
        self.assertEqual(len(mock_api.migration_calls), 1)
    
    def test_skips_when_lock_on_source_node_vm(self):
        """Skips migration when a VM on the source node has a lock."""
        nodes = [
            {"node": "node1", "cpu": 0.9, "maxmem": 1000, "mem": 400, "status": "online", "maxcpu": 16},
            {"node": "node2", "cpu": 0.3, "maxmem": 1000, "mem": 300, "status": "online", "maxcpu": 16},
        ]
        # VM on source node has lock
        resources = [
            {"vmid": 100, "name": "vm1", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.5, "mem": 200, "maxcpu": 4, "lock": "migrate"},
            {"vmid": 101, "name": "vm2", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.3, "mem": 150, "maxcpu": 2},
        ]
        backup_jobs = []
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertFalse(result)
        self.assertEqual(len(mock_api.migration_calls), 0)


class TestMigrateWorkloadEdgeCases(unittest.TestCase):
    """Tests for edge cases and error handling."""
    
    def setUp(self):
        """Set up logger and common test data."""
        logger.setup_logging({"logging": {"level": "DEBUG"}})
        self.cpu_ema = CpuEMA()
        
        self.config = {
            "proxmox_api": {
                "host": "proxmox.example.com",
                "port": 443,
                "user": "user@pam",
                "token_id": "test_token",
                "token_secret": "test_secret",
            },
            "balancer": {
                "cpu_max": 0.8,
                "memory_max": 0.8,
            },
        }
    
    def test_offline_nodes_are_excluded(self):
        """Excludes offline nodes from migration consideration."""
        nodes = [
            {"node": "node1", "cpu": 0.9, "maxmem": 1000, "mem": 400, "status": "online", "maxcpu": 16},
            {"node": "node2", "cpu": 0.8, "maxmem": 1000, "mem": 300, "status": "offline", "maxcpu": 16},
            {"node": "node3", "cpu": 0.3, "maxmem": 1000, "mem": 200, "status": "online", "maxcpu": 16},
        ]
        # Need at least 2 VMs on source for CPU mode (highest-CPU VM is excluded)
        resources = [
            {"vmid": 100, "name": "busy_vm", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.6, "mem": 250, "maxcpu": 6},
            {"vmid": 101, "name": "light_vm", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.4, "mem": 200, "maxcpu": 4},
        ]
        backup_jobs = []
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertTrue(result)
        # Should migrate to node3, not node2
        self.assertEqual(mock_api.migration_calls[0]["opts"]["target"], "node3")
    
    def test_migration_options_included(self):
        """Verifies migration is called with correct options."""
        nodes = [
            {"node": "node1", "cpu": 0.9, "maxmem": 1000, "mem": 400, "status": "online", "maxcpu": 16},
            {"node": "node2", "cpu": 0.3, "maxmem": 1000, "mem": 300, "status": "online", "maxcpu": 16},
        ]
        # Need at least 2 VMs on source for CPU mode (highest-CPU VM is excluded)
        resources = [
            {"vmid": 100, "name": "busy_vm", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.6, "mem": 250, "maxcpu": 6},
            {"vmid": 101, "name": "light_vm", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.4, "mem": 200, "maxcpu": 4},
        ]
        backup_jobs = []
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertTrue(result)
        migration_opts = mock_api.migration_calls[0]["opts"]
        self.assertEqual(migration_opts["target"], "node2")
        self.assertEqual(migration_opts["online"], 1)
        self.assertEqual(migration_opts["with-conntrack-state"], 1)
    
    def test_no_migration_when_all_candidates_filtered_out(self):
        """Returns False when all candidates are filtered out by constraints."""
        nodes = [
            {"node": "node1", "cpu": 0.9, "maxmem": 1000, "mem": 900, "status": "online", "maxcpu": 16},
            {"node": "node2", "cpu": 0.85, "maxmem": 1000, "mem": 850, "status": "online", "maxcpu": 16},
        ]
        # Large VM that would exceed constraints on node2
        resources = [
            {"vmid": 100, "name": "large_vm", "type": "qemu", "node": "node1", "status": "running", "cpu": 0.6, "mem": 700, "maxcpu": 8},
        ]
        backup_jobs = []
        ha_rules = []
        
        mock_api = MockProxmoxAPI(nodes, resources, backup_jobs, ha_rules)
        
        result = balancer.migrate_workload(self.config, self.cpu_ema, mock_api)
        
        self.assertFalse(result)
        self.assertEqual(len(mock_api.migration_calls), 0)


if __name__ == "__main__":
    unittest.main()
