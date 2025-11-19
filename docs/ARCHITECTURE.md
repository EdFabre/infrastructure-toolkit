# Infrastructure Toolkit Architecture

## System Overview

Infrastructure Toolkit provides a unified interface for managing and monitoring infrastructure across multiple layers:

1. **CLI Interface** - Command-line tools for direct server access
2. **REST API** - FastAPI backend for programmatic access
3. **Web Frontend** - React-based dashboard (planned)

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Interfaces                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────┐         ┌──────────────────────────────┐│
│  │   CLI Interface  │         │   Web Frontend (Planned)     ││
│  │                  │         │   React + TypeScript         ││
│  │  infra-toolkit   │         │   - Dashboard                ││
│  │  perf dashboard  │         │   - Performance Monitoring   ││
│  │  net health      │         │   - Network Management       ││
│  │  docker list     │         │   - Container Management     ││
│  └────────┬─────────┘         └────────┬─────────────────────┘│
│           │                             │                       │
│           │ Python imports              │ HTTP REST            │
│           ▼                             ▼                       │
├───────────────────────────────────────────────────────────────┬─┤
│                    Application Layer                          │ │
│                                                               │ │
│  ┌────────────────────────────────────────────────────────┐  │ │
│  │                  FastAPI REST API                      │  │ │
│  │  ┌────────────┐ ┌────────────┐ ┌─────────────────┐   │  │ │
│  │  │ Performance│ │  Network   │ │     Docker      │   │  │ │
│  │  │   Router   │ │   Router   │ │     Router      │   │  │ │
│  │  └─────┬──────┘ └─────┬──────┘ └────────┬────────┘   │  │ │
│  │        │              │                  │            │  │ │
│  │  ┌────────────┐ ┌──────────────────────────────────┐ │  │ │
│  │  │ Cloudflare │ │      Pterodactyl Router          │ │  │ │
│  │  │   Router   │ │                                  │ │  │ │
│  │  └─────┬──────┘ └────────┬─────────────────────────┘ │  │ │
│  └────────┼──────────────────┼────────────────────────────┘  │ │
│           │                  │                               │ │
│           │ Python imports   │                               │ │
│           ▼                  ▼                               │ │
├───────────────────────────────────────────────────────────────┼─┤
│                      Tools Layer                              │ │
│                                                               │ │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────────────────┐│ │
│  │ Performance  │  │   Network   │  │      Docker          ││ │
│  │     Tool     │  │    Tool     │  │       Tool           ││ │
│  │              │  │             │  │                      ││ │
│  │ • Dashboard  │  │ • Health    │  │ • List containers    ││ │
│  │ • Metrics    │  │ • Networks  │  │ • Health checks      ││ │
│  │ • Summary    │  │ • WiFi      │  │ • Deployment         ││ │
│  │ • Export     │  │ • Devices   │  │ • Logs               ││ │
│  │              │  │ • Clients   │  │ • Backups            ││ │
│  └──────┬───────┘  └──────┬──────┘  └──────┬───────────────┘│ │
│         │                 │                 │                 │ │
│  ┌──────────────┐  ┌────────────────────────────────────────┐│ │
│  │  Cloudflare  │  │       Pterodactyl Tool                 ││ │
│  │     Tool     │  │                                        ││ │
│  │              │  │ • List nodes                           ││ │
│  │ • Hostnames  │  │ • Diagnose issues                      ││ │
│  │ • Validation │  │ • Health checks                        ││ │
│  │ • Add/Modify │  │                                        ││ │
│  └──────┬───────┘  └──────┬─────────────────────────────────┘│ │
│         │                 │                                   │ │
├─────────┼─────────────────┼───────────────────────────────────┼─┤
│         │  Inherits from BaseTool (Safety Layer)             │ │
│         ▼                 ▼                                   │ │
│  ┌──────────────────────────────────────────────────────────┐│ │
│  │                   BaseTool Abstract Class                ││ │
│  │                                                          ││ │
│  │  • execute_with_safety()  - Automatic backup/rollback   ││ │
│  │  • get_current_state()    - State capture               ││ │
│  │  • rollback_from_backup() - Recovery mechanism          ││ │
│  │  • verify_operation()     - Validation                  ││ │
│  └──────────────────────────────────────────────────────────┘│ │
│                                                               │ │
├───────────────────────────────────────────────────────────────┼─┤
│                   Infrastructure Layer                        │ │
│                                                               │ │
│  ┌────────────────┐  ┌───────────────┐  ┌─────────────────┐ │ │
│  │  Prometheus    │  │   UniFi API   │  │   Docker API    │ │ │
│  │ node_exporter  │  │   (UDM-SE)    │  │   (via SSH)     │ │ │
│  │   :9100        │  │ 192.168.1.1   │  │   Multi-server  │ │ │
│  └────────────────┘  └───────────────┘  └─────────────────┘ │ │
│                                                               │ │
│  ┌────────────────┐  ┌──────────────────────────────────────┐│ │
│  │ Cloudflare API │  │     Pterodactyl API                  ││ │
│  │  Tunnel Mgmt   │  │     games.haymoed.com                ││ │
│  └────────────────┘  └──────────────────────────────────────┘│ │
│                                                               │ │
└───────────────────────────────────────────────────────────────┴─┘

    ▲                              ▲                       ▲
    │                              │                       │
    │ HTTP/JSON                    │ HTTP/JSON             │ SSH
    │                              │                       │
┌───┴──────────┐         ┌─────────┴───────┐    ┌────────┴─────────┐
│   Boss        │         │  UDM-SE Network │    │    9 Boss        │
│   Servers     │         │     Router      │    │    Servers       │
│ (9 servers)   │         │                 │    │                  │
└───────────────┘         └─────────────────┘    └──────────────────┘
```

## Data Flow

### 1. Performance Monitoring Flow

```
User Request (CLI/API)
    ↓
PerformanceTool
    ↓
node_exporter HTTP Query (port 9100)
    ↓
Parse Prometheus Metrics
    ↓
Calculate Status (healthy/warning/critical)
    ↓
Return Formatted Data
```

**Fallback**: If node_exporter unavailable, uses SSH to query OS directly:
- `free -b` for memory
- `cat /proc/loadavg` for CPU
- `df -B1 /` for disk

### 2. Network Monitoring Flow

```
User Request (CLI/API)
    ↓
NetworkTool
    ↓
UniFi API Authentication (Session + CSRF token)
    ↓
API Queries:
  - /api/stat/health
  - /rest/networkconf
  - /rest/wlanconf
  - /stat/device
  - /stat/sta
    ↓
Parse JSON Responses
    ↓
Return Formatted Data
```

### 3. Docker Management Flow

```
User Request (CLI/API)
    ↓
DockerTool
    ↓
SSH to Target Server(s)
    ↓
Execute Docker Commands:
  - docker ps --format "{{json .}}"
  - docker-compose config --quiet
  - docker-compose up -d
    ↓
Parse Output
    ↓
Return Results
```

**Multi-Server**: Queries all 9 boss servers in parallel by default.

## Component Architecture

### Core Components

```
infrastructure-toolkit/
├── .lifecycle/
│   └── state.yaml              # Lifecycle manager state
├── core/
│   ├── backend/                # Python CLI + API
│   │   └── infra_toolkit/
│   │       ├── base_tool.py    # Abstract base class
│   │       ├── cli.py          # CLI dispatcher
│   │       ├── api/            # FastAPI REST API (NEW)
│   │       │   ├── main.py     # FastAPI app
│   │       │   └── routers/    # API endpoints
│   │       │       ├── performance.py
│   │       │       ├── network.py
│   │       │       ├── docker.py
│   │       │       ├── cloudflare.py
│   │       │       └── pterodactyl.py
│   │       ├── tools/          # Tool implementations
│   │       │   ├── performance.py
│   │       │   ├── network.py
│   │       │   ├── docker.py
│   │       │   ├── cloudflare.py
│   │       │   └── pterodactyl.py
│   │       └── safety/         # Safety mechanisms
│   │           ├── backup.py
│   │           └── verification.py
│   ├── specs/                  # OpenAPI specifications (NEW)
│   │   └── api.yaml            # REST API spec
│   └── frontend/               # React UI (PLANNED)
│       ├── src/
│       │   ├── components/
│       │   ├── pages/
│       │   ├── services/       # API client
│       │   └── types/          # TypeScript types
│       └── package.json
└── docs/
    └── ARCHITECTURE.md         # This file
```

### Tool Inheritance Hierarchy

```
BaseTool (Abstract)
    ├── CloudflareTool
    │   └── Methods: list, add, validate, health-check
    ├── DockerTool
    │   └── Methods: list, deploy, restart, logs, validate
    ├── PterodactylTool (Read-only)
    │   └── Methods: nodes, servers, diagnose
    ├── PerformanceTool (Read-only)
    │   └── Methods: dashboard, metrics, summary, export
    └── NetworkTool (Read-only)
        └── Methods: health, networks, wifi, devices, clients
```

## API Endpoints

### Performance API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/perf/dashboard` | GET | Multi-server health dashboard |
| `/api/perf/servers/{server}/metrics` | GET | Detailed server metrics |
| `/api/perf/summary` | GET | Aggregated statistics |

### Network API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/net/health` | GET | Network health status |
| `/api/net/networks` | GET | Network configurations |
| `/api/net/wifi` | GET | WiFi networks |
| `/api/net/devices` | GET | Network devices |
| `/api/net/clients` | GET | Active clients |

### Docker API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/docker/containers` | GET | List containers |
| `/api/docker/servers/{server}/health` | GET | Docker health check |

### Cloudflare API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/cloudflare/hostnames` | GET | List tunnel hostnames |
| `/api/cloudflare/validate` | GET | Validate configuration |

### Pterodactyl API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/pterodactyl/nodes` | GET | List game server nodes |
| `/api/pterodactyl/diagnose` | GET | Diagnose issues |

## Technology Stack

### Backend
- **Language**: Python 3.8+
- **CLI Framework**: argparse
- **API Framework**: FastAPI
- **HTTP Client**: requests
- **YAML Parsing**: PyYAML
- **Output Formatting**: rich

### Frontend (Planned)
- **Framework**: React 18 + TypeScript
- **Build Tool**: Vite
- **UI Components**: Shadcn/ui
- **Charts**: Recharts
- **State**: TanStack Query
- **Routing**: React Router v6
- **Styling**: Tailwind CSS

### Infrastructure
- **Prometheus**: node_exporter (port 9100)
- **cAdvisor**: Container metrics (port 8080)
- **UniFi**: UDM-SE API
- **Docker**: Remote via SSH
- **Cloudflare**: REST API
- **Pterodactyl**: REST API

## Safety Mechanisms

### Automatic Backup

Every destructive operation creates a timestamped backup:

```
Format: {tool}-{operation}-{timestamp}.json
Example: cloudflare-add-hostname-20250119T120000Z.json
```

### Verification

Operations are validated before and after execution:

1. **Pre-flight checks**: Validate configuration syntax
2. **State capture**: Record current state
3. **Execute operation**: Perform changes
4. **Post-flight checks**: Verify success
5. **Rollback**: Restore from backup if verification fails

### Dry-Run Mode

All modification commands support `--dry-run` to preview changes without executing.

## Deployment Architecture

### Development

```
Terminal                     Browser
   │                            │
   │ infra-toolkit perf         │ http://localhost:5173
   │ dashboard                  │
   │                            │
   ▼                            ▼
Python CLI              React Dev Server (Vite)
   │                            │
   │                            │ HTTP API calls
   │                            ▼
   └─────────────►   FastAPI (localhost:8000)
                            │
                            ▼
                    Infrastructure Tools
```

### Production (Planned)

```
User Browser
    │
    │ HTTPS
    ▼
Nginx Reverse Proxy (boss-02)
    │
    ├─► /          → React Frontend (port 80)
    │
    └─► /api/*     → FastAPI Backend (port 8000)
                         │
                         ▼
                 Infrastructure Tools
```

## Lifecycle Management

Uses lifecycle-manager for:
- Component tracking (core)
- Area management (backend, frontend, specs)
- AI workflow integration
- Automatic versioning
- Git branch management

**State File**: `.lifecycle/state.yaml`

## Next Steps

1. **Frontend Implementation**
   - Initialize React frontend with lifecycle-manager
   - Implement dashboard page
   - Add performance monitoring charts
   - Create network management interface

2. **API Enhancements**
   - Add WebSocket support for real-time metrics
   - Implement authentication/authorization
   - Add request rate limiting
   - Enhance error handling

3. **Monitoring Improvements**
   - Add cAdvisor container metrics
   - Historical data storage (TimescaleDB/InfluxDB)
   - Alert system integration
   - Custom metric thresholds per server

4. **Documentation**
   - API documentation (Swagger/ReDoc)
   - Frontend component library
   - Deployment guide
   - Troubleshooting guide
