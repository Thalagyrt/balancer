__author__ = "James P. Riley"
__copyright__ = "Copyright (C) 2025 James P. Riley (@thalagyrt)"
__license__ = "GPL-3.0"

"""Constants for the balancer daemon."""

BACKUP_WINDOW_SECONDS = 60
BACKUP_PAUSE_SECONDS = 90

DEFAULT_CPU_MAX = 0.8
DEFAULT_MEMORY_MAX = 0.8

THRESHOLD_CLAMP_MIN = 0.5
THRESHOLD_CLAMP_MAX = 0.9

MEMORY_THRESHOLD_MULTIPLIER = 1.05

CONSTRAINT_SAFETY_FACTOR = 0.9
