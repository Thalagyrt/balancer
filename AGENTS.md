# Proxmox Balancer - Agent Guidelines

## Project Overview

A Python daemon that actively balances workloads across Proxmox Virtual Environment (PVE) clusters by performing live VM migrations when nodes exceed CPU or memory thresholds.

**Core purpose**: Execute minimum necessary migrations to prevent resource saturation, not for aesthetic load distribution.

---

## Essential Commands

### Development

```bash
# Install dependencies
pip install -r requirements.txt
pip install -r requirements-test.txt

# Run all tests
pytest tests

# Run tests with coverage
pytest tests --cov=balancer --cov-report=term-missing

# Run specific test file
pytest tests/test_balancer.py -v

# Run the balancer directly (requires balancer.yaml)
python -m balancer
```

### Docker

```bash
# Build image
docker build -t balancer .

# Run with config
docker run -v ./balancer.yaml:/usr/src/app/balancer.yaml balancer
```

---

## Code Organization

```
balancer/
├── __init__.py      # Package init, exports constants
├── __main__.py      # Daemon entry point (main loop)
├── api.py           # Proxmox API connection utilities
├── balancer.py      # Core migration logic (migrate_workload)
├── calculations.py  # CPU/memory calculation utilities
├── config.py        # YAML config loading and validation
├── constants.py     # Configuration constants
├── ema.py           # Exponential moving average for CPU smoothing
├── filters.py       # Migration candidate/target filtering
└── logger.py        # Logging setup and wrapper functions

tests/
├── test_api.py
├── test_balancer.py
├── test_calculations.py
├── test_config.py
├── test_ema.py
├── test_filters.py
└── test_integration.py
```

---

## Architecture Patterns

### Main Loop (`__main__.py`)
```python
config = load_config()
cpu_ema = CpuEMA()
api_client = api_connect(config)
while True:
    try:
        migrate_workload(config, cpu_ema, api_client)
    except proxmoxer.core.ResourceException as e:
        logger.error(f"API error during migration cycle: {e}")
    time.sleep(5)  # Check interval
```

### Migration Decision Flow (`balancer.py`)
1. `_check_backup_window()` - Pause if backup imminent
2. `_get_online_nodes()` - Filter to online nodes only
3. `_get_balancing_config()` - Extract and clamp thresholds from config
4. `compute_dynamic_memory_threshold()` - Calculate proactive memory threshold
5. `_apply_cpu_ema_to_nodes()` - Smooth CPU metrics
6. `_determine_balancing_mode()` - Decide if/what to balance
7. `_select_source_and_targets()` - Pick overloaded node
8. `_get_vm_candidates()` - Filter VMs on source
9. `_apply_candidate_filters()` - Apply constraints
10. `_select_best_target()` - Pick least utilized target
11. `_execute_migration()` - Trigger live migration with monitoring

### Key Design Principles

- **CPU smoothing**: Uses EMA over last 10 samples to avoid reacting to transient spikes
- **Highest CPU VM protection**: Never migrate the VM with highest CPU usage on a node
- **Meet-in-the-middle**: Migrations must not simply flip imbalance (target must stay below midpoint)
- **Safety margins**: Constraint checks use 90% of thresholds (`CONSTRAINT_SAFETY_FACTOR = 0.9`)
- **Backup awareness**: Pauses 90s if backup scheduled within 60s
- **Dynamic memory threshold**: Proactive balancing triggered at mean memory usage × 1.05
- **Migration monitoring**: Waits for migration lock (60s timeout) and completion (30m timeout)

---

## Code Style & Conventions

### Naming
- **Functions**: `snake_case` with `_` prefix for private helpers (`_get_online_nodes`)
- **Classes**: `PascalCase` (`CpuEMA`)
- **Constants**: `SCREAMING_SNAKE_CASE` (`BACKUP_WINDOW_SECONDS`)
- **Files**: Descriptive, lowercase with underscores (`calculations.py`)

### Documentation
- All public functions have full docstrings with Args/Returns
- Private helpers (`_prefix`) also documented
- Module-level docstrings describe purpose

### Error Handling
- Config errors: Log critical and `sys.exit(1)`
- API errors: Exceptions propagate from `proxmoxer`
- Validation: Return `(is_valid: bool, errors: list[str])` tuples

### Logging
- Use module-level `from . import logger` then `logger.info/debug/warning/error/critical`
- Must call `logger.setup_logging(config)` before using logger functions
- Never use `logging.getLogger()` directly in modules

---

## Configuration Schema

```yaml
proxmox_api:
  host: str          # Required
  port: str          # Required (default "8006")
  user: str          # Required (e.g., "user@pam")
  token_id: str      # Required
  token_secret: str  # Required

balancer:
  memory_max: float  # Required, clamped 0.5-0.9 (default 0.8)
  cpu_max: float     # Required, clamped 0.5-0.9 (default 0.8)

logging:
  level: str         # Required: DEBUG|INFO|WARNING|ERROR|CRITICAL
```

---

## Testing Patterns

### Unit Tests
- Use `unittest.TestCase`
- Always call `logger.setup_logging()` in `setUp()`
- Mock API calls, test pure logic
- Test helper functions individually

### Integration Tests (`test_integration.py`)
- Full workflow mocking with `proxmoxer` API simulation
- Test end-to-end migration decisions
- Use realistic node/VM data structures

### Test Data Structure Examples

```python
# Node structure
{
    "node": "node1",
    "cpu": 0.75,           # Current CPU as 0-1 float
    "maxcpu": 16,          # Total CPU cores
    "mem": 8000,           # Used memory in MB
    "maxmem": 16000,       # Total memory in MB
    "status": "online"
}

# VM resource structure
{
    "vmid": 100,
    "name": "vm-name",
    "node": "node1",
    "status": "running",   # or "stopped"
    "cpu": 0.5,            # Current CPU usage
    "maxcpu": 4,           # VM's max vCPU
    "mem": 2048,           # VM memory in MB
    "lock": "migrate"      # Only present if locked
}
```

---

## Important Constants (`constants.py`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `BACKUP_WINDOW_SECONDS` | 60 | Pause if backup within this time |
| `BACKUP_PAUSE_SECONDS` | 90 | How long to pause for backup |
| `DEFAULT_CPU_MAX` | 0.8 | Default CPU threshold |
| `DEFAULT_MEMORY_MAX` | 0.8 | Default memory threshold |
| `THRESHOLD_CLAMP_MIN` | 0.5 | Minimum allowed threshold |
| `THRESHOLD_CLAMP_MAX` | 0.9 | Maximum allowed threshold |
| `MEMORY_THRESHOLD_MULTIPLIER` | 1.05 | Proactive threshold = mean × 1.05 |
| `CONSTRAINT_SAFETY_FACTOR` | 0.9 | Safety margin for constraints |

---

## Key Algorithms

### EMA Smoothing (`ema.py`)
```python
# Maintains last 10 samples per key
# Returns exponential moving average with span=10
cpu_ema = CpuEMA()
smoothed = cpu_ema.update("node_mynode", raw_cpu_value)
```

### Memory Percentage (`calculations.py`)
```python
def node_memory_pct(node):
    return node["mem"] / node["maxmem"]  # Returns 0.0-1.0
```

### CPU Scaling Across Nodes (`calculations.py`)
```python
# Scale VM CPU from source node perspective to target
scaled_cpu = workload_cpu_as_host_pct(vm, target_node)
# Adjust for different core counts
factor = node_cpu_factor(source_node, target_node)
```

### Dynamic Memory Threshold (`calculations.py`)
```python
from statistics import mean

def compute_dynamic_memory_threshold(nodes):
    return mean(node_memory_pct(node) for node in nodes) * MEMORY_THRESHOLD_MULTIPLIER
# Triggers proactive balancing when any node exceeds mean × 1.05
```

### Migration Monitoring (`balancer.py`)
```python
# Migration workflow:
# 1. _execute_migration() initiates live migration via API
# 2. _await_migration_start() waits for migration lock (60s timeout, 5s intervals)
# 3. _await_migration_complete() monitors VM status (30m timeout, 15s intervals)
#    - Checks VM disappears from source and appears on target
#    - Handles transient API errors with 5-attempt tolerance
```

---

## Gotchas & Non-Obvious Patterns

1. **Logger must be initialized first**: All modules import `from . import logger` and use `logger.setup_logging()` before any logging. Calling logger functions before setup raises `RuntimeError`.

2. **In-place mutations**: `_apply_cpu_ema_to_nodes()` and `_apply_cpu_ema_to_vms()` modify lists in place and return the same reference.

3. **Threshold clamping**: Config values are always clamped to [0.5, 0.9] range in `_get_balancing_config()`.

4. **Backup window check happens first**: If a backup is imminent, the balancer pauses immediately without evaluating any thresholds.

5. **HA rules filtering**: `filter_ha_rules()` can return empty list if VM has positive affinity (node or VM affinity), which stops migration entirely.

6. **Highest CPU VM exclusion**: In CPU mode, the VM with highest CPU usage is excluded from candidates (`candidates[1:]` after sorting).

7. **Migration lock check**: If any VM has `lock == "migrate"`, the entire cycle is skipped.

8. **Random candidate shuffle**: Candidates are shuffled before evaluation to avoid always picking the same VM.

9. **Proxmox API structure**: Uses `proxmoxer` library with chained access: `api.nodes("node1").qemu(100).migrate().post()`

10. **Only QEMU VMs**: LXC containers are never migrated (filtered by API query `type="vm"`).

11. **Migration monitoring**: `_execute_migration()` now monitors migration progress:
    - Waits for migration lock to appear (60s timeout, 12 checks at 5s intervals)
    - Waits for VM to appear on target (30m timeout, 120 checks at 15s intervals)
    - Tolerates transient API errors (5 consecutive failures aborts)
    - Returns `False` on timeout or failure, allowing balancer to continue

12. **API error handling**: Main loop catches `proxmoxer.core.ResourceException` to prevent crashes from transient API failures.

13. **Dynamic memory threshold**: Computed as mean of all node memory usage × 1.05, enabling proactive balancing before hitting hard limits.

---

## Dependencies

- `requests~=2.32.5` - HTTP client
- `proxmoxer~=2.2.0` - Proxmox API wrapper
- `PyYAML~=6.0.3` - Config parsing
- `pandas~=2.3.3` - EMA calculations
- `pytest~=8.0`, `pytest-cov~=4.1` - Testing
- `pandas~=2.3.3` - EMA calculations

---

## CI/CD

GitHub Actions workflow (`.github/workflows/build-and-push.yml`):
- Runs tests on all PRs and pushes
- Builds and pushes Docker image on main branch pushes
- Scheduled weekly build on Sundays at 4:30 UTC
- Uses Python 3.12

---

## Running Locally

1. Create `balancer.yaml` from `balancer.yaml.example`
2. Fill in Proxmox API credentials
3. Run `python -m balancer`
4. Check logs for migration decisions

For debugging, set `logging.level: DEBUG` in config to see detailed decision-making.
