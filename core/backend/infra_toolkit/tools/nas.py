"""
NAS Monitoring Tool

Monitor UnRAID and TrueNAS systems via SSH.
"""

import logging
import subprocess
import re
from typing import Any, Dict, List, Optional
from pathlib import Path

from ..base_tool import BaseTool


logger = logging.getLogger(__name__)


class NASTool(BaseTool):
    """NAS monitoring for UnRAID and TrueNAS systems."""

    # Default NAS systems
    DEFAULT_NAS_SYSTEMS = {
        "unraid": {
            "name": "UnRAID",
            "ip": "192.168.1.6",
            "type": "unraid",
            "purpose": "Media Streaming & Storage"
        },
        "truenas": {
            "name": "TrueNAS",
            "ip": "192.168.1.66",
            "type": "truenas",
            "purpose": "File Storage & Backup"
        }
    }

    def __init__(self, **kwargs):
        """Initialize NAS tool."""
        config = self._load_config()
        super().__init__(config, **kwargs)

        # Get NAS systems from config or use defaults
        nas_config = config.get("nas", {})
        self.nas_systems = nas_config.get("systems", self.DEFAULT_NAS_SYSTEMS)

    @classmethod
    def tool_name(cls) -> str:
        return "nas"

    @classmethod
    def configure_parser(cls, parser):
        """Configure argument parser for NAS tool."""
        subparsers = parser.add_subparsers(dest="subcommand", help="NAS subcommands")

        # List command
        list_parser = subparsers.add_parser(
            "list",
            help="List all NAS systems with metrics"
        )

        # Metrics command
        metrics_parser = subparsers.add_parser(
            "metrics",
            help="Show detailed metrics for a specific NAS system"
        )
        metrics_parser.add_argument(
            "system",
            choices=["unraid", "truenas"],
            help="NAS system ID (unraid or truenas)"
        )

        # Health check command
        health_parser = subparsers.add_parser(
            "health-check",
            help="Check NAS systems health and connectivity"
        )

    def _load_config(self) -> Dict[str, Any]:
        """Load NAS configuration from config.yaml."""
        import yaml

        config_paths = [
            Path("/app/config.yaml"),  # Docker container mount
            Path("/mnt/tank/faststorage/general/repo/ai-config/config.yaml"),
            Path.home() / ".config" / "infrastructure-toolkit" / "config.yaml",
        ]

        for config_path in config_paths:
            if config_path.exists():
                logger.debug(f"Loading config from: {config_path}")
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f) or {}

        logger.warning(
            f"No configuration file found. "
            f"Checked: {', '.join(str(p) for p in config_paths)}"
        )
        return {}

    def validate_config(self) -> bool:
        """Validate NAS configuration."""
        return True  # No API keys required for SSH access

    def _execute_ssh_command(self, ip: str, command: str) -> Optional[str]:
        """
        Execute SSH command on remote NAS.

        Args:
            ip: IP address of NAS system
            command: Command to execute

        Returns:
            Command output or None if failed
        """
        try:
            ssh_command = [
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR",
                "-o", "ConnectTimeout=5",
                f"root@{ip}",
                command
            ]

            result = subprocess.run(
                ssh_command,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                return result.stdout
            else:
                logger.error(f"SSH command failed on {ip}: {result.stderr}")
                return None

        except Exception as e:
            logger.error(f"Error executing SSH command on {ip}: {e}")
            return None

    def get_unraid_metrics(self, ip: str) -> Dict[str, Any]:
        """
        Get metrics from UnRAID system.

        Args:
            ip: IP address of UnRAID server

        Returns:
            Dictionary of metrics
        """
        metrics = {
            "reachable": False,
            "type": "unraid",
            "ip": ip
        }

        try:
            # Get storage info
            df_output = self._execute_ssh_command(ip, "df -h / /mnt/user")
            if df_output:
                metrics["reachable"] = True
                # Parse df output for /mnt/user (main array)
                for line in df_output.strip().split('\n'):
                    if '/mnt/user' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            metrics["storage"] = {
                                "total": parts[1],
                                "used": parts[2],
                                "available": parts[3],
                                "used_percent": int(parts[4].rstrip('%'))
                            }

            # Get memory info
            mem_output = self._execute_ssh_command(ip, "free -h")
            if mem_output:
                for line in mem_output.strip().split('\n'):
                    if line.startswith('Mem:'):
                        parts = line.split()
                        if len(parts) >= 3:
                            metrics["memory"] = {
                                "total": parts[1],
                                "used": parts[2],
                                "available": parts[6] if len(parts) > 6 else parts[3]
                            }

            # Get uptime
            uptime_output = self._execute_ssh_command(ip, "uptime")
            if uptime_output:
                metrics["uptime"] = uptime_output.strip()
                # Extract load averages
                match = re.search(r'load average: ([\d.]+), ([\d.]+), ([\d.]+)', uptime_output)
                if match:
                    metrics["load"] = {
                        "1min": float(match.group(1)),
                        "5min": float(match.group(2)),
                        "15min": float(match.group(3))
                    }

            # Get array status
            array_status = self._execute_ssh_command(ip, "cat /var/local/emhttp/var.ini 2>/dev/null | grep -E '^(mdState|mdNumDisks|mdNumDisabled)'")
            if array_status:
                metrics["array"] = {}
                for line in array_status.strip().split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        metrics["array"][key.strip()] = value.strip().strip('"')

            metrics["status"] = "healthy" if metrics.get("reachable") else "unreachable"

        except Exception as e:
            logger.error(f"Error getting UnRAID metrics: {e}")
            metrics["error"] = str(e)

        return metrics

    def get_truenas_metrics(self, ip: str) -> Dict[str, Any]:
        """
        Get metrics from TrueNAS system.

        Args:
            ip: IP address of TrueNAS server

        Returns:
            Dictionary of metrics
        """
        metrics = {
            "reachable": False,
            "type": "truenas",
            "ip": ip
        }

        try:
            # Get memory info (FreeBSD)
            mem_output = self._execute_ssh_command(ip, "sysctl hw.physmem hw.realmem")
            if mem_output:
                metrics["reachable"] = True
                for line in mem_output.strip().split('\n'):
                    if 'hw.physmem' in line:
                        bytes_val = int(line.split(':')[1].strip())
                        gb_val = bytes_val / (1024**3)
                        metrics["memory"] = {
                            "total_gb": round(gb_val, 2),
                            "total_bytes": bytes_val
                        }

            # Get uptime
            uptime_output = self._execute_ssh_command(ip, "uptime")
            if uptime_output:
                metrics["uptime"] = uptime_output.strip()
                # Extract load averages
                match = re.search(r'load averages: ([\d.]+), ([\d.]+), ([\d.]+)', uptime_output)
                if match:
                    metrics["load"] = {
                        "1min": float(match.group(1)),
                        "5min": float(match.group(2)),
                        "15min": float(match.group(3))
                    }

            # Get ZFS pool status
            zpool_output = self._execute_ssh_command(ip, "zpool list -H")
            if zpool_output:
                pools = []
                for line in zpool_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 10:
                        pool = {
                            "name": parts[0],
                            "size": parts[1],
                            "alloc": parts[2],
                            "free": parts[3],
                            "frag": parts[6],
                            "cap": parts[7],
                            "health": parts[9]
                        }
                        pools.append(pool)
                metrics["pools"] = pools

                # Check for degraded pools
                degraded_pools = [p["name"] for p in pools if p["health"] != "ONLINE"]
                if degraded_pools:
                    metrics["status"] = "degraded"
                    metrics["issues"] = f"Degraded pools: {', '.join(degraded_pools)}"
                else:
                    metrics["status"] = "healthy"
            else:
                metrics["status"] = "healthy" if metrics.get("reachable") else "unreachable"

        except Exception as e:
            logger.error(f"Error getting TrueNAS metrics: {e}")
            metrics["error"] = str(e)

        return metrics

    def get_all_nas_metrics(self) -> List[Dict[str, Any]]:
        """
        Get metrics from all configured NAS systems.

        Returns:
            List of NAS metrics
        """
        all_metrics = []

        for system_id, system_info in self.nas_systems.items():
            logger.info(f"Querying NAS: {system_info['name']} ({system_info['ip']})")

            if system_info["type"] == "unraid":
                metrics = self.get_unraid_metrics(system_info["ip"])
            elif system_info["type"] == "truenas":
                metrics = self.get_truenas_metrics(system_info["ip"])
            else:
                logger.warning(f"Unknown NAS type: {system_info['type']}")
                continue

            # Add system info
            metrics["system_id"] = system_id
            metrics["name"] = system_info["name"]
            metrics["purpose"] = system_info.get("purpose", "")

            all_metrics.append(metrics)

        return all_metrics

    def health_check(self) -> Dict[str, Any]:
        """
        Check NAS health and connectivity.

        Returns:
            Health check results
        """
        checks = {}
        all_metrics = self.get_all_nas_metrics()

        for metrics in all_metrics:
            system_id = metrics["system_id"]
            checks[system_id] = {
                "reachable": metrics.get("reachable", False),
                "status": metrics.get("status", "unknown")
            }

        all_healthy = all([c["reachable"] for c in checks.values()])

        return {
            "status": "healthy" if all_healthy else "partial",
            "checks": checks,
            "message": f"{len([c for c in checks.values() if c['reachable']])} of {len(checks)} NAS systems reachable"
        }

    # BaseTool abstract methods

    def get_current_state(self) -> Dict[str, Any]:
        """Get current NAS state for backup."""
        return {
            "nas_systems": list(self.nas_systems.keys()),
            "metrics": self.get_all_nas_metrics()
        }

    def rollback_from_backup(self, backup_path: Path) -> bool:
        """NAS tool doesn't support rollback."""
        logger.warning("NAS tool does not support rollback operations")
        return False

    def verify_operation(self, operation_name: str, result: Any) -> bool:
        """Verify NAS operation completed successfully."""
        return result is not None

    # Action methods for Unraid

    def get_unraid_array_status(self, ip: str) -> Dict[str, Any]:
        """
        Get detailed Unraid array status from /proc/mdstat.

        Args:
            ip: IP address of Unraid server

        Returns:
            Dictionary with array status details
        """
        result = {
            "reachable": False,
            "array_started": False,
            "devices": []
        }

        try:
            # Get mdstat output
            mdstat_output = self._execute_ssh_command(ip, "cat /proc/mdstat")
            if mdstat_output:
                result["reachable"] = True
                result["raw_mdstat"] = mdstat_output

                # Check if array is started
                if "md" in mdstat_output:
                    result["array_started"] = True

                # Parse device info
                for line in mdstat_output.strip().split('\n'):
                    if line.startswith('md'):
                        parts = line.split(':')
                        if len(parts) >= 2:
                            md_name = parts[0].strip()
                            result["devices"].append({"name": md_name, "info": parts[1].strip()})

            return result

        except Exception as e:
            logger.error(f"Error getting Unraid array status: {e}")
            result["error"] = str(e)
            return result

    def get_unraid_parity_status(self, ip: str) -> Dict[str, Any]:
        """
        Get Unraid parity check status.

        Args:
            ip: IP address of Unraid server

        Returns:
            Dictionary with parity check status
        """
        result = {
            "reachable": False,
            "parity_check_running": False
        }

        try:
            # Check if parity check is running by looking at mdresync
            mdstat_output = self._execute_ssh_command(ip, "cat /proc/mdstat")
            if mdstat_output:
                result["reachable"] = True

                # Check for resync/check in progress
                if "resync" in mdstat_output or "check" in mdstat_output:
                    result["parity_check_running"] = True

                    # Try to extract progress
                    match = re.search(r'\[.*?(\d+\.\d+)%.*?\].*?finish=([\d.]+min|[\d.]+hr)', mdstat_output)
                    if match:
                        result["progress_percent"] = float(match.group(1))
                        result["estimated_finish"] = match.group(2)

            # Get last parity check date from syslog (if available)
            syslog_output = self._execute_ssh_command(
                ip,
                "grep -i 'parity.*complete\\|parity.*finished' /var/log/syslog 2>/dev/null | tail -1"
            )
            if syslog_output:
                result["last_check_log"] = syslog_output.strip()

            return result

        except Exception as e:
            logger.error(f"Error getting Unraid parity status: {e}")
            result["error"] = str(e)
            return result

    def get_unraid_disk_status(self, ip: str) -> Dict[str, Any]:
        """
        Get Unraid disk spin status.

        Args:
            ip: IP address of Unraid server

        Returns:
            Dictionary with disk status
        """
        result = {
            "reachable": False,
            "disks": []
        }

        try:
            # List all sd* devices and their spin status
            disk_list = self._execute_ssh_command(ip, "ls /dev/sd* 2>/dev/null | grep -E 'sd[a-z]$'")
            if disk_list:
                result["reachable"] = True

                for disk_device in disk_list.strip().split('\n'):
                    if disk_device:
                        disk_name = disk_device.split('/')[-1]

                        # Get spin status with hdparm
                        spin_output = self._execute_ssh_command(
                            ip,
                            f"hdparm -C /dev/{disk_name} 2>/dev/null"
                        )

                        disk_info = {"device": disk_name}

                        if spin_output:
                            if "active/idle" in spin_output:
                                disk_info["state"] = "active"
                            elif "standby" in spin_output:
                                disk_info["state"] = "standby"
                            else:
                                disk_info["state"] = "unknown"
                        else:
                            disk_info["state"] = "unavailable"

                        result["disks"].append(disk_info)

            return result

        except Exception as e:
            logger.error(f"Error getting Unraid disk status: {e}")
            result["error"] = str(e)
            return result

    # Action methods for TrueNAS

    def get_truenas_pool_scrub_status(self, ip: str, pool_name: str = None) -> Dict[str, Any]:
        """
        Get TrueNAS pool scrub status.

        Args:
            ip: IP address of TrueNAS server
            pool_name: Optional specific pool name to check

        Returns:
            Dictionary with scrub status
        """
        result = {
            "reachable": False,
            "pools": []
        }

        try:
            # Get detailed pool status
            if pool_name:
                status_output = self._execute_ssh_command(ip, f"zpool status {pool_name}")
            else:
                status_output = self._execute_ssh_command(ip, "zpool status")

            if status_output:
                result["reachable"] = True
                result["raw_status"] = status_output

                # Parse for scrub information
                current_pool = None
                for line in status_output.strip().split('\n'):
                    if line.strip().startswith("pool:"):
                        if current_pool:
                            result["pools"].append(current_pool)
                        current_pool = {"name": line.split(":")[-1].strip()}

                    elif current_pool and "scan:" in line:
                        scrub_info = line.split("scan:")[-1].strip()
                        current_pool["scrub_status"] = scrub_info

                        # Check if scrub is in progress
                        if "in progress" in scrub_info:
                            current_pool["scrub_running"] = True
                            # Try to extract progress
                            progress_match = re.search(r'(\d+\.\d+)% done', scrub_info)
                            if progress_match:
                                current_pool["scrub_progress"] = float(progress_match.group(1))
                        else:
                            current_pool["scrub_running"] = False

                if current_pool:
                    result["pools"].append(current_pool)

            return result

        except Exception as e:
            logger.error(f"Error getting TrueNAS scrub status: {e}")
            result["error"] = str(e)
            return result

    def get_truenas_dataset_list(self, ip: str, pool_name: str = None) -> Dict[str, Any]:
        """
        Get list of TrueNAS datasets.

        Args:
            ip: IP address of TrueNAS server
            pool_name: Optional specific pool to list datasets for

        Returns:
            Dictionary with dataset list
        """
        result = {
            "reachable": False,
            "datasets": []
        }

        try:
            # List datasets
            if pool_name:
                zfs_output = self._execute_ssh_command(ip, f"zfs list -r {pool_name}")
            else:
                zfs_output = self._execute_ssh_command(ip, "zfs list")

            if zfs_output:
                result["reachable"] = True

                # Parse zfs list output (skip header)
                lines = zfs_output.strip().split('\n')[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 5:
                        dataset = {
                            "name": parts[0],
                            "used": parts[1],
                            "avail": parts[2],
                            "refer": parts[3],
                            "mountpoint": parts[4]
                        }
                        result["datasets"].append(dataset)

            return result

        except Exception as e:
            logger.error(f"Error getting TrueNAS datasets: {e}")
            result["error"] = str(e)
            return result

    def get_truenas_service_status(self, ip: str, service_name: str = None) -> Dict[str, Any]:
        """
        Get TrueNAS service status.

        Args:
            ip: IP address of TrueNAS server
            service_name: Optional specific service name (e.g., 'smb', 'nfs')

        Returns:
            Dictionary with service status
        """
        result = {
            "reachable": False,
            "services": []
        }

        try:
            # Map friendly names to service process patterns
            service_patterns = {
                'smb': 'smbd',
                'nfs': 'nfsd',
                'ssh': 'sshd',
                'snmp': 'snmpd'
            }

            # Common TrueNAS services
            services_to_check = [service_name] if service_name else ['smb', 'nfs', 'ssh', 'snmp']

            for service in services_to_check:
                # Get the process pattern to check
                process_name = service_patterns.get(service, service)

                # Check if process is running using ps
                ps_output = self._execute_ssh_command(
                    ip,
                    f"ps aux | grep -v grep | grep -i {process_name} | wc -l"
                )

                result["reachable"] = True
                service_info = {"name": service}

                if ps_output:
                    process_count = ps_output.strip()
                    logger.info(f"Service {service} ({process_name}): {process_count} processes")

                    try:
                        if int(process_count) > 0:
                            service_info["status"] = "active"
                        else:
                            service_info["status"] = "inactive"
                    except ValueError:
                        logger.warning(f"Invalid process count for {service}: {process_count}")
                        service_info["status"] = "unknown"
                else:
                    # Service check failed, mark as unknown
                    logger.warning(f"No output for service {service} ({process_name})")
                    service_info["status"] = "unknown"

                result["services"].append(service_info)

            return result

        except Exception as e:
            logger.error(f"Error getting TrueNAS service status: {e}")
            result["error"] = str(e)
            return result
