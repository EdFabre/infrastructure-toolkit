# Infrastructure Toolkit

Standardized CLI toolkit for infrastructure management with built-in safety mechanisms.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)

## Overview

Infrastructure Toolkit provides a unified command-line interface and web dashboard for managing infrastructure tools with automatic safety mechanisms including:

- **Automatic Backup** - All modifications are backed up before execution
- **State Verification** - Configuration integrity is validated before and after changes
- **Dry-Run Mode** - Preview changes without applying them
- **Automatic Rollback** - Failed operations automatically restore previous state
- **Rich CLI Output** - Beautiful terminal output with tables and colors
- **Web Dashboard** - Real-time monitoring and management interface
- **Docker Deployment** - Self-contained containerized deployment

## Quick Start (Docker)

The recommended way to run Infrastructure Toolkit is via Docker:

```bash
# Create Docker network
docker network create infra-toolkit

# Run backend container
docker run -d \
  --name infra-toolkit-backend \
  --network infra-toolkit \
  -e TZ=America/New_York \
  -v ./data:/app/data \
  -v /path/to/config.yaml:/app/config.yaml:ro \
  -v /root/.ssh:/root/.ssh:ro \
  --restart unless-stopped \
  infra-toolkit-backend:latest

# Run frontend container
docker run -d \
  --name infra-toolkit-frontend \
  --network infra-toolkit \
  -p 5173:80 \
  --restart unless-stopped \
  infra-toolkit-frontend:latest

# Access the dashboard
open http://localhost:5173
```

### Using Docker Compose

```bash
cd projects/infrastructure-toolkit
docker-compose up -d
```

### CLI Access via Docker

All CLI commands are available via `docker exec`:

```bash
# List available tools
docker exec infra-toolkit-backend infra-toolkit --list

# Cloudflare management
docker exec infra-toolkit-backend infra-toolkit cloudflare list
docker exec infra-toolkit-backend infra-toolkit cloudflare add myservice 192.168.1.10 8080 --dry-run

# Docker management across servers
docker exec infra-toolkit-backend infra-toolkit docker list --all-servers
docker exec infra-toolkit-backend infra-toolkit docker health-check

# Performance monitoring
docker exec infra-toolkit-backend infra-toolkit performance dashboard

# Network management
docker exec infra-toolkit-backend infra-toolkit network health

# Pterodactyl game servers
docker exec infra-toolkit-backend infra-toolkit pterodactyl nodes
docker exec infra-toolkit-backend infra-toolkit pterodactyl diagnose

# NAS monitoring
docker exec infra-toolkit-backend infra-toolkit nas list

# Proxmox management
docker exec infra-toolkit-backend infra-toolkit proxmox health-check
```

## Available Tools

| Tool | Description | Commands |
|------|-------------|----------|
| **cloudflare** | Cloudflare tunnel management | `list`, `add`, `validate`, `health-check`, `backups`, `restore` |
| **docker** | Docker container management | `list`, `health-check`, `deploy`, `restart`, `logs`, `sync`, `backups`, `rollback` |
| **network** | UniFi network monitoring | `health`, `networks`, `wifi`, `devices`, `clients`, `health-check` |
| **performance** | Multi-server monitoring | `dashboard`, `metrics`, `containers`, `summary`, `export`, `health-check` |
| **pterodactyl** | Game server management | `health-check`, `nodes`, `node-status`, `diagnose`, `servers` |
| **nas** | NAS system monitoring | `list`, `metrics`, `health-check` |
| **proxmox** | Proxmox virtualization | `health-check`, `usb-status`, `usb-reset`, `usb-auto-fix` |

## Web Interface

The web dashboard provides real-time monitoring and management:

- **Dashboard** - Overview of all servers and services
- **Performance** - CPU, memory, disk metrics with charts
- **Network** - UniFi network health, devices, clients
- **Docker** - Container status across all servers
- **Pterodactyl** - Game server status and diagnostics
- **NAS** - Storage system monitoring
- **Proxmox** - VM and USB device management

### Authentication

Default credentials:
- **Username:** `admin`
- **Password:** `admin`

Change the password after first login via Settings → Change Password.

## Development Setup

For local development without Docker:

```bash
# Backend
cd core/backend
pip install -e .
uvicorn infra_toolkit.api.main:app --reload --port 8000

# Frontend (new terminal)
cd core/frontend
npm install
npm run dev
```

## Configuration

All tools read configuration from a central config file:

```yaml
# /path/to/config.yaml
cloudflare:
  api_token: "your-token"
  account_id: "your-account-id"
  haymoed:
    zone_id: "zone-id"
    tunnel_id: "tunnel-id"

pterodactyl_api:
  url: "https://games.example.com"
  key: "ptla_your-key"

servers:
  boss-01:
    hostname: "192.168.1.11"
    type: "docker-host"
  # ... more servers

unifi:
  controller_url: "https://192.168.1.1"
  username: "admin"
  password: "your-password"
```

## Architecture

### Docker Deployment

```
┌─────────────────────────────────────────────────────┐
│              Docker Network (infra-toolkit)          │
│                                                      │
│   ┌─────────────────┐    ┌─────────────────┐        │
│   │   Frontend      │    │    Backend      │        │
│   │   (Nginx)       │───▶│    (FastAPI)    │        │
│   │   static + proxy│    │    API + CLI    │        │
│   │   Port 80       │    │    Port 8000    │        │
│   └────────┬────────┘    └─────────────────┘        │
│            │                                         │
└────────────┼─────────────────────────────────────────┘
             │
      Exposed Port 5173
             │
      ┌──────▼──────┐
      │    User     │
      └─────────────┘
```

### Bind Mounts

| Mount | Purpose |
|-------|---------|
| `./data:/app/data` | Persist database and backups |
| `/path/to/config.yaml:/app/config.yaml:ro` | Application configuration |
| `/root/.ssh:/root/.ssh:ro` | SSH keys for remote server access |

### Safety Mechanisms

All tools inherit from `BaseTool` which provides:

- **Automatic backups** before destructive operations
- **Dry-run mode** to preview changes
- **State verification** before and after changes
- **Automatic rollback** on failure
- **Audit logging** of all operations

## License

MIT License - See LICENSE file for details.
