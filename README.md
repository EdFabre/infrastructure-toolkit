# Infrastructure Toolkit

Standardized CLI toolkit for infrastructure management with built-in safety mechanisms.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)

## Overview

Infrastructure Toolkit provides a unified command-line interface for managing infrastructure tools with automatic safety mechanisms including:

- **Automatic Backup** - All modifications are backed up before execution
- **State Verification** - Configuration integrity is validated before and after changes
- **Dry-Run Mode** - Preview changes without applying them
- **Automatic Rollback** - Failed operations automatically restore previous state
- **Rich CLI Output** - Beautiful terminal output with tables and colors

## Motivation

This project was created to prevent critical infrastructure configuration errors. Specifically, it fixes a bug in `cloudflare-functions.sh` that caused tunnel configuration wipe-outs by:

1. **Adding automatic backups** before modifications (previously missing)
2. **Using merge-based updates** instead of full configuration replacement
3. **Validating hostname counts** to detect suspicious changes (minimum 20 threshold)
4. **Providing rollback capability** for quick recovery

## Installation

### From Source (Development)

```bash
# Clone the repository
git clone https://github.com/EdFabre/infrastructure-toolkit.git
cd infrastructure-toolkit

# Install in development mode
pip install -e core/backend/
```

### Using Python venv

```bash
# Activate your virtual environment
source /path/to/venv/bin/activate

# Install the package
pip install -e core/backend/
```

## Usage

### Cloudflare Tunnel Management

The Cloudflare tool provides safe management of Cloudflare Tunnel configurations.

#### List Hostnames

```bash
infra-toolkit cloudflare list
```

#### Add Hostname (Dry-Run)

Preview changes before applying:

```bash
infra-toolkit cloudflare add prowlarr 192.168.1.11 9696 --dry-run
```

#### Add Hostname (Execute)

Add a new hostname to the tunnel:

```bash
infra-toolkit cloudflare add prowlarr 192.168.1.11 9696
```

With HTTPS:

```bash
infra-toolkit cloudflare add nextcloud 192.168.1.66 8283 --protocol https
```

#### Validate Configuration

Check tunnel configuration integrity:

```bash
infra-toolkit cloudflare validate
```

#### Health Check

Verify API connectivity and authentication:

```bash
infra-toolkit cloudflare health-check
```

#### List Backups

Show all available backups:

```bash
infra-toolkit cloudflare backups
```

#### Restore from Backup

Restore tunnel configuration from a backup:

```bash
infra-toolkit cloudflare restore /path/to/backup.json
```

### Global Options

```bash
# Enable verbose logging
infra-toolkit --verbose cloudflare list

# List available tools
infra-toolkit --list

# Show version
infra-toolkit --version
```

## Configuration

The Cloudflare tool reads configuration from `/mnt/tank/faststorage/general/repo/ai-config/scripts/config.yaml`:

```yaml
cloudflare:
  api_token: "your-api-token"
  account_id: "your-account-id"

  haymoed:
    zone_id: "zone-id"
    tunnel_id: "tunnel-id"

  ramcyber:
    zone_id: "zone-id"
    tunnel_id: "tunnel-id"
```

You can specify which domain to manage using the `--domain` flag:

```bash
infra-toolkit cloudflare --domain ramcyber list
```

## Architecture

### BaseTool Abstract Class

All tools inherit from `BaseTool` which provides:

- `execute_with_safety()` - Wraps operations with automatic backup/rollback
- `get_current_state()` - Retrieves current configuration state
- `rollback_from_backup()` - Restores from backup file
- `verify_operation()` - Validates operation success

### Safety Mechanisms

#### BackupManager

- Automatic timestamped JSON backups
- Backup listing and cleanup
- Integrity verification
- Configurable retention (default: 10 backups)

#### VerificationManager

- State comparison (before/after)
- Structure validation
- Hash-based integrity checking
- Custom verification rules

### Tool Structure

```
infra_toolkit/
├── base_tool.py           # Abstract base class
├── cli.py                 # CLI dispatcher
├── safety/
│   ├── backup.py          # Backup management
│   └── verification.py    # State verification
└── tools/
    └── cloudflare.py      # Cloudflare tunnel tool
```

## Adding New Tools

To add a new infrastructure tool:

1. Create a new tool class in `infra_toolkit/tools/`:

```python
from ..base_tool import BaseTool

class MyTool(BaseTool):
    @classmethod
    def tool_name(cls) -> str:
        return "mytool"

    def get_current_state(self) -> Dict[str, Any]:
        # Return current state for backup
        pass

    def rollback_from_backup(self, backup_path: Path) -> bool:
        # Restore from backup
        pass

    def verify_operation(self, operation_name: str, result: Any) -> bool:
        # Verify operation success
        pass

    @classmethod
    def configure_parser(cls, parser):
        # Add CLI arguments
        super().configure_parser(parser)
        # Add subcommands...
```

2. Register the tool in `cli.py`:

```python
from .tools.mytool import MyTool

AVAILABLE_TOOLS = {
    "cloudflare": CloudflareTool,
    "mytool": MyTool,
}
```

3. Use `execute_with_safety()` for all destructive operations:

```python
def my_operation(self, param1, param2):
    return self.execute_with_safety(
        operation_name="my-operation",
        operation_func=self._do_my_operation,
        param1=param1,
        param2=param2
    )
```

## Safety Features in Detail

### Automatic Backup

Every destructive operation automatically:

1. Creates a timestamped backup of the current state
2. Stores metadata (tool name, operation, timestamp)
3. Validates backup file integrity

### Validation

Configuration changes are validated:

- Structure verification (required keys, data types)
- Count verification (minimum/maximum thresholds)
- Custom validation rules per tool
- Before and after comparisons

### Rollback

If an operation fails:

1. Validation error detected
2. Backup is automatically loaded
3. Previous state is restored
4. Error details are logged

### Dry-Run Mode

Preview changes without applying:

```bash
infra-toolkit cloudflare add service 192.168.1.10 8080 --dry-run
```

Output shows what would happen without making changes.

## Backups

Backups are stored in `core/backend/data/backups/cloudflare/`:

- Format: `cloudflare-{operation}-{timestamp}.json`
- Retention: 10 most recent backups (configurable)
- Content: Full state + metadata

## Examples

### Safe Hostname Addition

```bash
# Preview the change
infra-toolkit cloudflare add movies 192.168.1.20 8096 --dry-run

# Verify current state
infra-toolkit cloudflare validate

# Add the hostname
infra-toolkit cloudflare add movies 192.168.1.20 8096

# Verify success
infra-toolkit cloudflare list | grep movies
infra-toolkit cloudflare validate
```

### Backup and Restore

```bash
# List backups
infra-toolkit cloudflare backups

# If something goes wrong, restore from backup
infra-toolkit cloudflare restore data/backups/cloudflare/cloudflare-add-hostname-movies-20250116-120000.json

# Verify restoration
infra-toolkit cloudflare validate
```

## Comparison with cloudflare-functions.sh

### Before (Bash Script)

❌ No automatic backups
❌ Full configuration replacement
❌ No validation
❌ No rollback capability
❌ Silent failures

### After (Infrastructure Toolkit)

✅ Automatic backup before every change
✅ Merge-based updates (atomic)
✅ Comprehensive validation
✅ Automatic rollback on failure
✅ Rich error reporting
✅ Dry-run mode
✅ Health checks

## Development

### Running Tests

```bash
pytest core/backend/tests/
```

### Code Structure

- Type hints throughout
- Comprehensive docstrings
- Logging at all levels
- Error handling with context

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - See LICENSE file for details

## Author

Created by Claude Code to prevent infrastructure configuration disasters.

## Acknowledgments

- Built to fix critical bugs in `cloudflare-functions.sh`
- Inspired by the need for safer infrastructure management
- Follows patterns from `ai-manager` and `lifecycle-manager` projects
