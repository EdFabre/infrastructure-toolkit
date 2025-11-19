"""
Performance Monitoring Tool

Read-only monitoring of boss servers via Prometheus exporters and OS metrics.

Features:
- Multi-server health dashboard
- Prometheus node_exporter integration (port 9100)
- cAdvisor container metrics (port 8080)
- OS-level metrics via SSH fallback
- Configurable thresholds for warnings/critical alerts
- Export capabilities for automation
"""

import json
import logging
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml

from ..base_tool import BaseTool


logger = logging.getLogger(__name__)


class PerformanceTool(BaseTool):
    """
    Performance monitoring with Prometheus integration.

    This tool provides read-only monitoring across boss servers:
    1. Query node_exporter for system metrics
    2. Query cAdvisor for container metrics
    3. Fall back to SSH for OS-level stats
    4. Multi-server parallel queries
    5. Threshold-based alerting
    """

    # Default boss servers (hostname: IP mapping)
    DEFAULT_SERVERS = {
        "boss-0": "192.168.1.10",
        "boss-01": "192.168.1.11",
        "boss-02": "192.168.1.12",
        "boss-03": "192.168.1.13",
        "boss-04": "192.168.1.14",
        "boss-05": "192.168.1.15",
        "boss-06": "192.168.1.16",
        "boss-07": "192.168.1.17",
        "king-01": "192.168.1.71"
    }

    # Default thresholds (percentages)
    DEFAULT_THRESHOLDS = {
        "memory_warning": 80,
        "memory_critical": 90,
        "cpu_warning": 75,
        "cpu_critical": 90,
        "disk_warning": 80,
        "disk_critical": 90
    }

    def __init__(self, server: Optional[str] = None, all_servers: bool = False, **kwargs):
        """
        Initialize Performance tool.

        Args:
            server: Server hostname to monitor (None for all servers)
            all_servers: Explicitly query all configured servers
            **kwargs: Additional arguments passed to BaseTool
        """
        # Load configuration before calling super().__init__
        config = self._load_config()

        self.server = server
        # Default to all_servers=True if no specific server specified
        self.all_servers = all_servers or (server is None)
        self.is_remote = server is not None

        # Get list of servers to query (from config or defaults)
        monitoring_config = config.get("monitoring", {})
        docker_config = config.get("docker", {})
        self.servers = docker_config.get("servers", self.DEFAULT_SERVERS)

        # Get monitoring ports
        self.node_exporter_port = monitoring_config.get("node_exporter_port", 9100)
        self.cadvisor_port = monitoring_config.get("cadvisor_port", 8080)

        # Get thresholds
        self.thresholds = monitoring_config.get("thresholds", self.DEFAULT_THRESHOLDS)

        super().__init__(config, **kwargs)

    @classmethod
    def tool_name(cls) -> str:
        return "perf"

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from config.yaml."""
        import yaml

        # Look for config in multiple locations
        config_paths = [
            Path("/mnt/tank/faststorage/general/repo/ai-config/config.yaml"),
            Path.home() / ".config" / "infrastructure-toolkit" / "config.yaml",
        ]

        for config_path in config_paths:
            if config_path.exists():
                logger.debug(f"Loading config from: {config_path}")
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f) or {}

        # Return minimal config if no file found
        logger.warning(
            f"No configuration file found. "
            f"Checked: {', '.join(str(p) for p in config_paths)}"
        )
        return {}

    def validate_config(self) -> bool:
        """Validate performance monitoring configuration."""
        # Performance tool doesn't require API credentials
        return True

    def _resolve_server_address(self, server: str) -> str:
        """
        Resolve server hostname to IP address.

        Args:
            server: Server hostname or IP address

        Returns:
            IP address for the server
        """
        # If it looks like an IP address, return as-is
        if server.replace(".", "").isdigit():
            return server

        # Look up in servers mapping
        if server in self.servers:
            return self.servers[server]

        # Return as-is and let requests/SSH handle it
        return server

    def _execute_ssh_command(self, server: str, command: List[str]) -> subprocess.CompletedProcess:
        """
        Execute command via SSH.

        Args:
            server: Server hostname or IP
            command: Command to execute (as list)

        Returns:
            CompletedProcess result
        """
        server_ip = self._resolve_server_address(server)
        cmd_string = " ".join(command)

        ssh_command = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            f"root@{server_ip}",
            cmd_string
        ]

        return subprocess.run(ssh_command, capture_output=True, text=True, timeout=10)

    def _query_prometheus_exporter(self, server: str, port: int) -> Optional[str]:
        """
        Query Prometheus exporter metrics endpoint.

        Args:
            server: Server hostname or IP
            port: Exporter port number

        Returns:
            Metrics text or None if unreachable
        """
        server_ip = self._resolve_server_address(server)
        url = f"http://{server_ip}:{port}/metrics"

        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return response.text
            else:
                logger.warning(f"Failed to query {url}: HTTP {response.status_code}")
                return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to query {url}: {e}")
            return None

    def _parse_prometheus_metric(self, metrics_text: str, metric_name: str) -> Optional[float]:
        """
        Parse a specific metric from Prometheus text format.

        Args:
            metrics_text: Raw metrics text
            metric_name: Metric name to extract

        Returns:
            Metric value or None if not found
        """
        # Match metric lines (ignore comments and empty lines)
        pattern = rf'^{re.escape(metric_name)}(?:\{{[^}}]*\}})?\s+([0-9.e+-]+)'

        for line in metrics_text.split('\n'):
            match = re.match(pattern, line)
            if match:
                return float(match.group(1))

        return None

    def _get_server_metrics_via_node_exporter(self, server: str) -> Dict[str, Any]:
        """
        Get server metrics via node_exporter.

        Args:
            server: Server hostname

        Returns:
            Dictionary of metrics
        """
        metrics = {
            "server": server,
            "source": "node_exporter",
            "reachable": False
        }

        # Query node_exporter
        metrics_text = self._query_prometheus_exporter(server, self.node_exporter_port)

        if not metrics_text:
            return metrics

        metrics["reachable"] = True

        # Parse system metrics
        # Memory
        mem_total = self._parse_prometheus_metric(metrics_text, "node_memory_MemTotal_bytes")
        mem_available = self._parse_prometheus_metric(metrics_text, "node_memory_MemAvailable_bytes")

        if mem_total and mem_available:
            mem_used = mem_total - mem_available
            mem_used_percent = (mem_used / mem_total) * 100
            metrics["memory"] = {
                "total_gb": round(mem_total / (1024**3), 2),
                "used_gb": round(mem_used / (1024**3), 2),
                "available_gb": round(mem_available / (1024**3), 2),
                "used_percent": round(mem_used_percent, 2)
            }

        # CPU Load Averages
        load1 = self._parse_prometheus_metric(metrics_text, "node_load1")
        load5 = self._parse_prometheus_metric(metrics_text, "node_load5")
        load15 = self._parse_prometheus_metric(metrics_text, "node_load15")

        if load1 is not None:
            metrics["cpu_load"] = {
                "1min": round(load1, 2),
                "5min": round(load5, 2) if load5 else None,
                "15min": round(load15, 2) if load15 else None
            }

        # Disk Usage (root filesystem)
        # Look for node_filesystem_avail_bytes{mountpoint="/"}
        for line in metrics_text.split('\n'):
            if 'node_filesystem_avail_bytes' in line and 'mountpoint="/"' in line:
                match = re.search(r'\s+([0-9.e+-]+)$', line)
                if match:
                    avail_bytes = float(match.group(1))
                    metrics["disk_root_available_gb"] = round(avail_bytes / (1024**3), 2)

            if 'node_filesystem_size_bytes' in line and 'mountpoint="/"' in line:
                match = re.search(r'\s+([0-9.e+-]+)$', line)
                if match:
                    size_bytes = float(match.group(1))
                    metrics["disk_root_total_gb"] = round(size_bytes / (1024**3), 2)

        # Calculate disk usage percent if we have both
        if "disk_root_available_gb" in metrics and "disk_root_total_gb" in metrics:
            total = metrics["disk_root_total_gb"]
            avail = metrics["disk_root_available_gb"]
            used = total - avail
            metrics["disk"] = {
                "total_gb": total,
                "used_gb": round(used, 2),
                "available_gb": avail,
                "used_percent": round((used / total) * 100, 2)
            }

        return metrics

    def _get_server_metrics_via_ssh(self, server: str) -> Dict[str, Any]:
        """
        Get server metrics via SSH commands (fallback).

        Args:
            server: Server hostname

        Returns:
            Dictionary of metrics
        """
        metrics = {
            "server": server,
            "source": "ssh",
            "reachable": False
        }

        try:
            # Test SSH connectivity
            result = self._execute_ssh_command(server, ["echo", "ok"])
            if result.returncode != 0:
                return metrics

            metrics["reachable"] = True

            # Get memory info
            result = self._execute_ssh_command(server, ["free", "-b"])
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) >= 2:
                    mem_line = lines[1].split()
                    total = int(mem_line[1])
                    used = int(mem_line[2])
                    available = int(mem_line[6]) if len(mem_line) > 6 else int(mem_line[3])

                    metrics["memory"] = {
                        "total_gb": round(total / (1024**3), 2),
                        "used_gb": round(used / (1024**3), 2),
                        "available_gb": round(available / (1024**3), 2),
                        "used_percent": round((used / total) * 100, 2)
                    }

            # Get load averages
            result = self._execute_ssh_command(server, ["cat", "/proc/loadavg"])
            if result.returncode == 0:
                loads = result.stdout.strip().split()[:3]
                metrics["cpu_load"] = {
                    "1min": float(loads[0]),
                    "5min": float(loads[1]),
                    "15min": float(loads[2])
                }

            # Get disk usage for /
            result = self._execute_ssh_command(server, ["df", "-B1", "/"])
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) >= 2:
                    disk_line = lines[1].split()
                    total = int(disk_line[1])
                    used = int(disk_line[2])
                    avail = int(disk_line[3])

                    metrics["disk"] = {
                        "total_gb": round(total / (1024**3), 2),
                        "used_gb": round(used / (1024**3), 2),
                        "available_gb": round(avail / (1024**3), 2),
                        "used_percent": round((used / total) * 100, 2)
                    }

        except Exception as e:
            logger.error(f"Error getting SSH metrics from {server}: {e}")

        return metrics

    def get_server_metrics(self, server: str) -> Dict[str, Any]:
        """
        Get comprehensive server metrics.

        Tries node_exporter first, falls back to SSH if unavailable.

        Args:
            server: Server hostname

        Returns:
            Dictionary of metrics
        """
        # Try node_exporter first
        metrics = self._get_server_metrics_via_node_exporter(server)

        if not metrics.get("reachable"):
            logger.info(f"node_exporter unavailable for {server}, falling back to SSH")
            metrics = self._get_server_metrics_via_ssh(server)

        # Add status based on thresholds
        if metrics.get("reachable"):
            status = "healthy"

            if "memory" in metrics:
                mem_pct = metrics["memory"]["used_percent"]
                if mem_pct >= self.thresholds["memory_critical"]:
                    status = "critical"
                elif mem_pct >= self.thresholds["memory_warning"] and status == "healthy":
                    status = "warning"

            if "disk" in metrics:
                disk_pct = metrics["disk"]["used_percent"]
                if disk_pct >= self.thresholds["disk_critical"]:
                    status = "critical"
                elif disk_pct >= self.thresholds["disk_warning"] and status == "healthy":
                    status = "warning"

            metrics["status"] = status
        else:
            metrics["status"] = "unreachable"

        return metrics

    def get_all_servers_metrics(self) -> List[Dict[str, Any]]:
        """
        Get metrics from all configured servers.

        Returns:
            List of server metrics
        """
        all_metrics = []

        if isinstance(self.servers, dict):
            server_items = list(self.servers.keys())
        else:
            server_items = self.servers

        for server in server_items:
            logger.info(f"Querying metrics for {server}...")
            metrics = self.get_server_metrics(server)
            all_metrics.append(metrics)

        return all_metrics

    def health_check(self) -> Dict[str, Any]:
        """
        Check monitoring system health.

        Returns:
            Health check results
        """
        checks = {}

        # Check if we can reach at least one server
        test_server = "boss-0" if "boss-0" in self.servers else list(self.servers.keys())[0]
        metrics = self.get_server_metrics(test_server)

        checks["test_server"] = test_server
        checks["test_server_reachable"] = metrics.get("reachable", False)
        checks["data_source"] = metrics.get("source", "unknown")

        # Overall status
        all_healthy = checks.get("test_server_reachable", False)
        status = "healthy" if all_healthy else "unhealthy"

        return {
            "status": status,
            "checks": checks,
            "message": "Monitoring system operational" if all_healthy else "Cannot reach monitoring endpoints"
        }

    # BaseTool abstract methods (read-only tool)

    def get_current_state(self) -> Dict[str, Any]:
        """Get current monitoring state snapshot."""
        return {
            "message": "Read-only tool - monitoring snapshot",
            "timestamp": datetime.utcnow().isoformat(),
            "servers": list(self.servers.keys()) if isinstance(self.servers, dict) else self.servers
        }

    def rollback_from_backup(self, backup_path: Path) -> bool:
        """Rollback not supported (read-only tool)."""
        raise NotImplementedError("Performance tool is read-only - no rollback needed")

    def verify_operation(self, operation_name: str, result: Any) -> bool:
        """Verify operation (not used for read-only operations)."""
        return True

    @classmethod
    def configure_parser(cls, parser):
        """Configure argument parser for Performance tool."""
        super().configure_parser(parser)

        subparsers = parser.add_subparsers(dest="subcommand", help="Performance subcommands")

        # Dashboard command
        dashboard_parser = subparsers.add_parser("dashboard", help="Multi-server health dashboard")

        # Metrics command
        metrics_parser = subparsers.add_parser("metrics", help="Server metrics details")

        # Containers command
        containers_parser = subparsers.add_parser("containers", help="Container-specific metrics")

        # Summary command
        summary_parser = subparsers.add_parser("summary", help="Aggregated metrics summary")

        # Export command
        export_parser = subparsers.add_parser("export", help="Export metrics to file")
        export_parser.add_argument("--format", choices=["json", "csv"], default="json", help="Export format")
        export_parser.add_argument("--output", type=str, help="Output file path")

        # Health check command
        health_parser = subparsers.add_parser("health-check", help="Check monitoring system health")
