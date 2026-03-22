"""Exponential moving average calculator for CPU metrics."""

import pandas


class CpuEMA:
    """Exponential moving average calculator for CPU metrics.

    Maintains a sliding window of the last 10 measurements per key, then
    computes an exponential moving average with a span of 10 to smooth
    out transient CPU spikes before migration decisions are made.
    """

    def __init__(self):
        """Initialize the CPU EMA calculator with empty state."""
        self._usage = {}

    def update(self, key, value):
        """Add a new value and return the exponentially weighted moving average.

        Args:
            key: Identifier for the metric (e.g., 'node_mynode' or 'vm_123').
            value: The current CPU usage measurement (percentage as float).

        Returns:
            float: The smoothed CPU usage value using EMA, or 0 if no history exists.
        """
        if key not in self._usage:
            self._usage[key] = []
        self._usage[key].append(value)
        self._usage[key] = self._usage[key][-10:]
        return float(pandas.DataFrame(self._usage[key]).ewm(span=10).mean().iat[-1, -1])
