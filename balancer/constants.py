"""Constants for the balancer daemon."""

# Backup-related constants
BACKUP_WINDOW_SECONDS = 60
BACKUP_PAUSE_SECONDS = 90

# Balancing threshold defaults
DEFAULT_CPU_MAX = 0.8
DEFAULT_MEMORY_MAX = 0.8

# Threshold clamping bounds
THRESHOLD_CLAMP_MIN = 0.5
THRESHOLD_CLAMP_MAX = 0.9

# Memory threshold calculation
MEMORY_THRESHOLD_MULTIPLIER = 1.05

# Constraint safety factor
CONSTRAINT_SAFETY_FACTOR = 0.9
