"""Unit tests for the calculations module."""

import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from balancer import calculations


class TestClamp(unittest.TestCase):
    """Tests for clamp function."""

    def test_value_within_range(self):
        """Should return value unchanged when within range."""
        result = calculations.clamp(5, 0, 10)
        self.assertEqual(result, 5)

    def test_value_below_min(self):
        """Should return min when value is below range."""
        result = calculations.clamp(-5, 0, 10)
        self.assertEqual(result, 0)

    def test_value_above_max(self):
        """Should return max when value is above range."""
        result = calculations.clamp(15, 0, 10)
        self.assertEqual(result, 10)

    def test_value_equal_to_min(self):
        """Should return value when equal to min."""
        result = calculations.clamp(0, 0, 10)
        self.assertEqual(result, 0)

    def test_value_equal_to_max(self):
        """Should return value when equal to max."""
        result = calculations.clamp(10, 0, 10)
        self.assertEqual(result, 10)

    def test_float_values(self):
        """Should work with float values."""
        result = calculations.clamp(0.75, 0.5, 0.9)
        self.assertEqual(result, 0.75)

    def test_float_clamped(self):
        """Should clamp float values correctly."""
        result = calculations.clamp(0.95, 0.5, 0.9)
        self.assertEqual(result, 0.9)


class TestWorkloadCpuAsHostPct(unittest.TestCase):
    """Tests for workload_cpu_as_host_pct function."""

    def test_basic_calculation(self):
        """Should calculate CPU percentage correctly."""
        workload = {"cpu": 0.5, "maxcpu": 4}  # 50% of 4 vCPUs = 2 cores worth
        node = {"maxcpu": 16}  # 16 cores total
        result = calculations.workload_cpu_as_host_pct(workload, node)
        # 0.5 * 4 / 16 = 0.125 (12.5% of host CPU)
        self.assertEqual(result, 0.125)

    def test_full_workload_cpu(self):
        """Should handle 100% workload CPU usage."""
        workload = {"cpu": 1.0, "maxcpu": 8}
        node = {"maxcpu": 16}
        result = calculations.workload_cpu_as_host_pct(workload, node)
        # 1.0 * 8 / 16 = 0.5 (50% of host CPU)
        self.assertEqual(result, 0.5)

    def test_workload_larger_than_host(self):
        """Should handle workload with more vCPUs than host cores."""
        workload = {"cpu": 1.0, "maxcpu": 32}
        node = {"maxcpu": 16}
        result = calculations.workload_cpu_as_host_pct(workload, node)
        # 1.0 * 32 / 16 = 2.0 (200% of host CPU - oversubscribed)
        self.assertEqual(result, 2.0)

    def test_small_workload(self):
        """Should handle small workload."""
        workload = {"cpu": 0.1, "maxcpu": 2}
        node = {"maxcpu": 64}
        result = calculations.workload_cpu_as_host_pct(workload, node)
        # 0.1 * 2 / 64 = 0.003125
        self.assertEqual(result, 0.003125)


class TestNodeCpuFactor(unittest.TestCase):
    """Tests for node_cpu_factor function."""

    def test_equal_nodes(self):
        """Should return 1.0 for nodes with same CPU count."""
        source = {"maxcpu": 16}
        target = {"maxcpu": 16}
        result = calculations.node_cpu_factor(source, target)
        self.assertEqual(result, 1.0)

    def test_source_larger(self):
        """Should return > 1.0 when source has more cores."""
        source = {"maxcpu": 32}
        target = {"maxcpu": 16}
        result = calculations.node_cpu_factor(source, target)
        self.assertEqual(result, 2.0)

    def test_source_smaller(self):
        """Should return < 1.0 when source has fewer cores."""
        source = {"maxcpu": 8}
        target = {"maxcpu": 16}
        result = calculations.node_cpu_factor(source, target)
        self.assertEqual(result, 0.5)

    def test_uneven_ratio(self):
        """Should handle uneven CPU ratios."""
        source = {"maxcpu": 24}
        target = {"maxcpu": 16}
        result = calculations.node_cpu_factor(source, target)
        self.assertEqual(result, 1.5)


class TestNodeMemoryPct(unittest.TestCase):
    """Tests for node_memory_pct function."""

    def test_half_used(self):
        """Should return 0.5 for half-used memory."""
        node = {"mem": 8000, "maxmem": 16000}
        result = calculations.node_memory_pct(node)
        self.assertEqual(result, 0.5)

    def test_quarter_used(self):
        """Should return 0.25 for quarter-used memory."""
        node = {"mem": 4000, "maxmem": 16000}
        result = calculations.node_memory_pct(node)
        self.assertEqual(result, 0.25)

    def test_high_usage(self):
        """Should return high percentage for near-full memory."""
        node = {"mem": 15000, "maxmem": 16000}
        result = calculations.node_memory_pct(node)
        self.assertAlmostEqual(result, 0.9375, places=4)

    def test_zero_usage(self):
        """Should return 0.0 for unused memory."""
        node = {"mem": 0, "maxmem": 16000}
        result = calculations.node_memory_pct(node)
        self.assertEqual(result, 0.0)

    def test_full_usage(self):
        """Should return 1.0 for fully used memory."""
        node = {"mem": 16000, "maxmem": 16000}
        result = calculations.node_memory_pct(node)
        self.assertEqual(result, 1.0)


if __name__ == "__main__":
    unittest.main()
