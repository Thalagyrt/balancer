"""Unit tests for the ema module."""

import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from balancer.ema import CpuEMA


class TestCpuEMA(unittest.TestCase):
    """Tests for CpuEMA class."""

    def test_first_value_returns_itself(self):
        """Should return the first value as-is."""
        cpu_ema = CpuEMA()
        result = cpu_ema.update("test_key", 50.0)
        self.assertEqual(result, 50.0)

    def test_multiple_values_compute_ema(self):
        """Should compute EMA for multiple values."""
        cpu_ema = CpuEMA()
        # Add 10 values of 50, then one value of 100
        for _ in range(10):
            cpu_ema.update("test_key", 50.0)
        result = cpu_ema.update("test_key", 100.0)
        # EMA should be closer to 50 than 100 due to smoothing
        self.assertGreater(result, 50.0)
        self.assertLess(result, 100.0)

    def test_maintains_last_10_values(self):
        """Should only keep last 10 values in history."""
        cpu_ema = CpuEMA()
        for i in range(15):
            cpu_ema.update("test_key", float(i))
        # Should only have last 10 values
        self.assertEqual(len(cpu_ema._usage["test_key"]), 10)

    def test_different_keys_independent(self):
        """Should maintain separate history for different keys."""
        cpu_ema = CpuEMA()
        cpu_ema.update("key1", 50.0)
        cpu_ema.update("key2", 100.0)
        self.assertNotEqual(cpu_ema._usage["key1"], cpu_ema._usage["key2"])

    def test_ema_smoothing_effect(self):
        """Should demonstrate EMA smoothing effect."""
        cpu_ema = CpuEMA()
        # Alternate between high and low values
        result = 0
        for i in range(20):
            value = 100.0 if i % 2 == 0 else 0.0
            result = cpu_ema.update("test_key", value)
        # After many alternations, EMA should stabilize near the middle
        self.assertGreater(result, 30.0)
        self.assertLess(result, 70.0)

    def test_cpu_ema_class_isolation(self):
        """Should create isolated CpuEMA instances."""
        ema1 = CpuEMA()
        ema2 = CpuEMA()
        ema1.update("key", 50.0)
        ema2.update("key", 100.0)
        # Different instances should have different state
        self.assertNotEqual(ema1._usage["key"], ema2._usage["key"])

    def test_cpu_ema_class_reset(self):
        """Should allow creating fresh CpuEMA instances for testing."""
        ema = CpuEMA()
        result = ema.update("test", 75.0)
        self.assertEqual(result, 75.0)
        # New instance has no history
        ema2 = CpuEMA()
        self.assertEqual(len(ema2._usage), 0)


if __name__ == "__main__":
    unittest.main()
