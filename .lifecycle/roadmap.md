# Infrastructure-Toolkit Roadmap

> Expansion plan for infrastructure-toolkit to manage critical infrastructure components with safety mechanisms

**Last Updated**: 2025-11-18
**Version**: 1.0.0

## Overview

This roadmap outlines the planned expansion of infrastructure-toolkit to include management tools for:
- Docker Compose orchestration across boss servers
- UniFi Dream Machine SE (UDM) network management
- Boss server health monitoring
- ProtonMail SMTP bridge testing
- Server configuration synchronization
- Media services management

All tools will follow the established safety patterns: automatic backups, dry-run mode, verification, and rollback capabilities.

## Priority 0: Critical Infrastructure (Immediate Implementation)

### 1. Docker Compose Management Tool (`infra-toolkit docker`)

**Problem Statement**: Current `dcp` and `dclog` bash aliases lack validation and rollback capabilities. Invalid docker-compose.yml can break all services on a server.

**Target Servers**: All boss servers (boss-0 through boss-07) and king-01

**Key Features**:
- **Validate** docker-compose.yml syntax before deployment
- **Automatic timestamped backups** (improving on current dcp alias)
- **Health verification** after deployment
- **Rollback capability** on failure
- **Sync from repo** with validation
- **Cleanup old backups** with retention policy
- **Diff view** between repo and active configurations

**Proposed Commands**:
```bash
# Validate before deployment
infra-toolkit docker validate boss-02

# Deploy with safety checks
infra-toolkit docker deploy boss-02 --verify
infra-toolkit docker deploy boss-02 --service radarr --dry-run

# View logs with better formatting
infra-toolkit docker logs boss-02 radarr --tail 100 --follow

# Backup management
infra-toolkit docker backups boss-02 --list
infra-toolkit docker backups boss-02 --cleanup --keep 10

# Emergency rollback
infra-toolkit docker rollback boss-02

# Health monitoring
infra-toolkit docker health-check --all-servers
```

**Effort Estimate**: 2-3 days
**Risk Level**: HIGH (critical to all services)
**Frequency**: Daily use

---

### 2. UDM SE WiFi Management Tool (`infra-toolkit udm`)

**Problem Statement**: UniFi API accepts configuration changes but doesn't always provision them to APs. Multiple failed attempts documented in `wifi-minrate-fix-gotchas.md`. No automatic backup before changes.

**Target**: UDM SE at 192.168.1.1

**Key Features**:
- **Set minimum data rates** with automatic verification
- **Force AP provisioning** with validation
- **WiFi health monitoring** (signal strength, rates, connected clients)
- **Client management** (list/kick/block)
- **Automatic backup** before all changes
- **IPS/DPI management** for performance tuning
- **System health checks**

**Proposed Commands**:
```bash
# WiFi management
infra-toolkit udm list-wifi
infra-toolkit udm wifi-health
infra-toolkit udm set-minrate "YourSSID" --2ghz 12 --5ghz 24 --verify

# Client management
infra-toolkit udm list-clients
infra-toolkit udm kick-client MAC_ADDRESS
infra-toolkit udm block-client MAC_ADDRESS

# AP management
infra-toolkit udm list-aps
infra-toolkit udm provision-ap "AP-Name" --verify
infra-toolkit udm restart-ap "AP-Name"

# Performance tuning
infra-toolkit udm disable-ips
infra-toolkit udm disable-dpi
```

**Effort Estimate**: 3-4 days
**Risk Level**: HIGH (can disconnect all WiFi devices)
**Frequency**: Weekly when performance issues arise

## Priority 1: Core Operations

### 3. Boss Server Health Monitoring Tool (`infra-toolkit boss`)

**Problem Statement**: Manual health checks via `check-servers.py` should be automated. No alerting on failures. No trending or history.

**Target Servers**: All boss servers (9 total)

**Key Features**:
- **Unified health checks** across all servers
- **NAS mount verification** with auto-remount option
- **Docker container monitoring**
- **Resource usage tracking** (CPU, memory, disk)
- **Automated remediation** (restart failed containers)
- **SSH connectivity testing**

**Proposed Commands**:
```bash
# Health monitoring
infra-toolkit boss health-check --all
infra-toolkit boss status boss-02 --verbose

# Resource monitoring
infra-toolkit boss resources --all --summary

# Mount verification
infra-toolkit boss verify-mounts --all --auto-remount

# Service management
infra-toolkit boss restart boss-02 radarr --verify
infra-toolkit boss auto-heal --all --dry-run
```

**Effort Estimate**: 1-2 days
**Risk Level**: MEDIUM
**Frequency**: Daily

---

### 4. ProtonMail SMTP Testing Tool (`infra-toolkit protonmail`)

**Problem Statement**: Manual SMTP/IMAP testing required. No automated monitoring. Container startup issues. No email queue monitoring.

**Target**: boss-04 (192.168.1.14)

**Key Features**:
- **SMTP/IMAP health checks**
- **Send test emails** with delivery verification
- **Queue monitoring**
- **Container management** with auto-healing
- **Authentication testing**

**Proposed Commands**:
```bash
# Health monitoring
infra-toolkit protonmail health-check

# Testing
infra-toolkit protonmail test-send --to test@example.com

# Queue management
infra-toolkit protonmail queue-status

# Container management
infra-toolkit protonmail restart --verify
infra-toolkit protonmail auto-heal
```

**Effort Estimate**: 1 day
**Risk Level**: MEDIUM
**Frequency**: Weekly

## Priority 2: Workflow Enhancement

### 5. Server Configuration Sync Tool (`infra-toolkit sync`)

**Problem Statement**: Current `pullRemote`/`pushRemote` aliases lack validation and conflict detection.

**Target Servers**: All boss servers

**Key Features**:
- **Validate before sync**
- **Conflict detection**
- **Automatic backups**
- **Drift reporting**
- **Dry-run mode**

**Proposed Commands**:
```bash
# Configuration sync
infra-toolkit sync pull boss-02 --verify --dry-run
infra-toolkit sync push boss-02 --create-backup

# Drift detection
infra-toolkit sync status boss-02
infra-toolkit sync diff boss-02 --summary
```

**Effort Estimate**: 2 days
**Risk Level**: MEDIUM
**Frequency**: Weekly

---

### 6. Media Services Management Tool (`infra-toolkit media`)

**Problem Statement**: Multiple manual scripts for anime cleanup, metadata scanning. No unified interface. Manual API authentication.

**Target**: boss-01 (192.168.1.11)

**Key Features**:
- **Unified interface** for Radarr/Sonarr/Prowlarr/Bazarr
- **Automated anime cleanup**
- **Metadata scanning** with progress tracking
- **Health monitoring**

**Proposed Commands**:
```bash
# Service management
infra-toolkit media health-check

# Maintenance tasks
infra-toolkit media rescan sonarr --verify-progress
infra-toolkit media cleanup-anime --dry-run
infra-toolkit media fix-misplaced --type anime
```

**Effort Estimate**: 2-3 days
**Risk Level**: LOW
**Frequency**: Weekly

## Implementation Timeline

### Phase 1: Foundation (Week 1-2)
- [x] CloudflareTool (COMPLETED)
- [x] PterodactylTool (COMPLETED)
- [ ] Docker Compose Management
- [ ] Boss Server Health Monitoring

### Phase 2: Network & Communication (Week 3-4)
- [ ] UDM SE WiFi Management
- [ ] ProtonMail SMTP Testing

### Phase 3: Operational Excellence (Week 5-6)
- [ ] Server Configuration Sync
- [ ] Media Services Management

## Technical Architecture

All tools follow the established patterns:

### Core Patterns
1. **BaseTool inheritance** - All tools inherit common safety mechanisms
2. **Automatic backups** - Before every destructive operation
3. **Dry-run mode** - Preview changes without executing
4. **Verification** - Validate operations completed successfully
5. **Automatic rollback** - Restore from backup on failure
6. **Rich CLI output** - Clear, colored terminal output

### Configuration
- Central configuration in `/mnt/tank/faststorage/general/repo/ai-config/config.yaml`
- Tool-specific sections in YAML
- Environment variable overrides supported

### Safety Mechanisms
- Read-only operations by default
- Explicit `--execute` flag for destructive operations
- Timestamped backups with retention policies
- Health checks before and after operations
- Automatic rollback on verification failure

## Success Metrics

### Operational
- **Reduction in manual errors**: Target 90% reduction in configuration mistakes
- **Time savings**: 50% reduction in routine maintenance time
- **Incident recovery**: 75% faster recovery from misconfigurations

### Technical
- **Test coverage**: Minimum 80% for all tools
- **Backup success rate**: 100% for all destructive operations
- **Rollback reliability**: 100% successful rollbacks on failure

## Dependencies

### Existing Code to Leverage
- `/mnt/tank/faststorage/general/repo/ai-config/scripts/check-servers.py`
- `/mnt/tank/faststorage/general/repo/ai-config/scripts/test-protonmail.py`
- `/mnt/tank/faststorage/general/repo/ai-config/scripts/fix-wifi-minrate*.py`
- Various media management scripts in ai-config/scripts/

### Required Access
- SSH key-based access to all boss servers
- UniFi API credentials
- Docker API access
- Media service API keys

## Risk Mitigation

### High-Risk Operations
- **Docker deployments**: Always validate YAML, create backup, verify health
- **WiFi changes**: Test on single AP first, verify provisioning
- **Network changes**: Implement rate limiting, have rollback plan

### Monitoring
- Integrate with existing Gotify/Slack notifications
- Add health check dashboards
- Implement audit logging for all operations

## Future Enhancements

### Phase 4: Advanced Features
- Web UI for infrastructure-toolkit
- Scheduled operations with cron integration
- Multi-server orchestration
- Integration with monitoring systems

### Phase 5: Intelligence Layer
- Predictive failure detection
- Automated optimization suggestions
- Capacity planning recommendations

---

**Note**: This roadmap is a living document and will be updated as implementation progresses and new requirements are discovered.