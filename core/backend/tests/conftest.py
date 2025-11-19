"""Pytest configuration and fixtures for infrastructure-toolkit tests."""

import pytest
from unittest.mock import Mock, patch
from typing import Dict, Any

# Test data fixtures
@pytest.fixture
def mock_server_metrics() -> Dict[str, Any]:
    """Mock server metrics data."""
    return {
        "server": "boss-01",
        "status": "healthy",
        "reachable": True,
        "cpu_load": {
            "1min": 0.5,
            "5min": 0.6,
            "15min": 0.7
        },
        "memory": {
            "total_bytes": 16777216000,
            "used_bytes": 8388608000,
            "free_bytes": 8388608000,
            "used_percent": 50.0
        },
        "disk": {
            "total_bytes": 1099511627776,
            "used_bytes": 549755813888,
            "free_bytes": 549755813888,
            "used_percent": 50.0
        },
        "uptime_seconds": 86400,
        "timestamp": "2025-11-19T12:00:00Z"
    }


@pytest.fixture
def mock_network_health() -> Dict[str, Any]:
    """Mock network health data."""
    return {
        "subsystems": {
            "wan": {"status": "ok", "description": "WAN is up"},
            "lan": {"status": "ok", "description": "LAN is healthy"},
            "wlan": {"status": "ok", "description": "WLAN is active"}
        },
        "overall_status": "healthy"
    }


@pytest.fixture
def mock_docker_containers() -> list:
    """Mock Docker containers data."""
    return [
        {
            "server": "boss-01",
            "name": "radarr",
            "image": "linuxserver/radarr:latest",
            "status": "Up 2 days",
            "state": "running",
            "created_at": "2025-11-17T10:00:00Z",
            "ports": ["7878:7878"]
        },
        {
            "server": "boss-01",
            "name": "sonarr",
            "image": "linuxserver/sonarr:latest",
            "status": "Up 2 days",
            "state": "running",
            "created_at": "2025-11-17T10:00:00Z",
            "ports": ["8989:8989"]
        }
    ]


@pytest.fixture
def mock_prometheus_metrics() -> str:
    """Mock Prometheus metrics text format."""
    return """# HELP node_load1 1m load average.
# TYPE node_load1 gauge
node_load1 0.5
# HELP node_load5 5m load average.
# TYPE node_load5 gauge
node_load5 0.6
# HELP node_load15 15m load average.
# TYPE node_load15 gauge
node_load15 0.7
# HELP node_memory_MemTotal_bytes Total memory in bytes.
# TYPE node_memory_MemTotal_bytes gauge
node_memory_MemTotal_bytes 16777216000
# HELP node_memory_MemAvailable_bytes Available memory in bytes.
# TYPE node_memory_MemAvailable_bytes gauge
node_memory_MemAvailable_bytes 8388608000
# HELP node_filesystem_size_bytes Filesystem size in bytes.
# TYPE node_filesystem_size_bytes gauge
node_filesystem_size_bytes{mountpoint="/"} 1099511627776
# HELP node_filesystem_avail_bytes Filesystem available space in bytes.
# TYPE node_filesystem_avail_bytes gauge
node_filesystem_avail_bytes{mountpoint="/"} 549755813888
"""


@pytest.fixture
def mock_ssh_response() -> Dict[str, str]:
    """Mock SSH command responses."""
    return {
        "free -b": """              total        used        free      shared  buff/cache   available
Mem:    16777216000  8388608000  4194304000   104857600  4194304000  8388608000
Swap:   8589934592   104857600  8485076992""",
        "cat /proc/loadavail": "0.50 0.60 0.70 1/500 12345",
        "df -B1 /": """Filesystem     1B-blocks        Used  Available Use% Mounted on
/dev/sda1    1099511627776 549755813888 549755813888  50% /"""
    }


# Mock configuration
@pytest.fixture
def mock_config() -> Dict[str, Any]:
    """Mock configuration data."""
    return {
        "cloudflare": {
            "api_token": "test-token",
            "account_id": "test-account",
            "haymoed": {
                "zone_id": "test-zone",
                "tunnel_id": "test-tunnel"
            }
        },
        "pterodactyl_api": {
            "url": "https://games.haymoed.com",
            "key": "test-api-key"
        },
        "unifi": {
            "udm_se": {
                "host": "192.168.1.1",
                "username": "test-user",
                "password": "test-pass",
                "verify_ssl": False
            }
        }
    }
