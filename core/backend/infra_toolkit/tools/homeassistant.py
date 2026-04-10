"""
Home Assistant Management Tool

Provides health monitoring, VM control, and Cloudflare tunnel status
for Home Assistant OS running on Proxmox VE.
"""

import logging
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from ..base_tool import BaseTool


logger = logging.getLogger(__name__)


@dataclass
class HAConfig:
    """Home Assistant VM configuration."""
    vm_id: int
    vm_name: str
    proxmox_host: str
    proxmox_ip: str
    ha_ip: str
    ha_port: int
    cloudflare_hostname: str
    vlan: int
    network_name: str


class HomeAssistantTool(BaseTool):
    """
    Home Assistant management tool with VM control and health monitoring.

    Features:
    - Health checks (port 8123, HTTP response, Cloudflare tunnel)
    - VM control (start, stop, restart, status)
    - Uptime monitoring with long-uptime warnings
    - Cloudflare tunnel status verification
    - Automatic recovery procedures
    """

    # Home Assistant configuration
    HA_CONFIG = HAConfig(
        vm_id=108,
        vm_name="haos9.5",
        proxmox_host="pve-2",
        proxmox_ip="192.168.1.7",
        ha_ip="192.168.4.5",
        ha_port=8123,
        cloudflare_hostname="hass.haymoed.com",
        vlan=3,
        network_name="IoT Network",
    )

    # Cloudflare tunnel configuration
    CLOUDFLARE_TUNNEL = {
        "container": "cloudflared-haymoed",
        "host": "boss-01",
        "host_ip": "192.168.1.11",
    }

    # Health thresholds
    UPTIME_WARNING_WEEKS = 8  # Warn if uptime > 8 weeks
    HTTP_TIMEOUT = 10
    PORT_TIMEOUT = 5

    def __init__(
        self,
        dry_run: bool = False,
        verbose: bool = False,
        no_verify: bool = False,
    ):
        """
        Initialize Home Assistant tool.

        Args:
            dry_run: If True, preview changes without executing
            verbose: Enable verbose logging
            no_verify: Skip verification checks
        """
        config = {
            "vm_id": self.HA_CONFIG.vm_id,
            "ha_ip": self.HA_CONFIG.ha_ip,
            "ha_port": self.HA_CONFIG.ha_port,
        }
        super().__init__(config, dry_run, verbose, no_verify)

    @classmethod
    def tool_name(cls) -> str:
        return "homeassistant"

    def validate_config(self) -> bool:
        """Validate Home Assistant configuration."""
        return (
            self.HA_CONFIG.vm_id > 0 and
            self.HA_CONFIG.ha_ip and
            self.HA_CONFIG.ha_port > 0
        )

    def _ssh_command(self, host_ip: str, command: str, timeout: int = 30) -> subprocess.CompletedProcess:
        """
        Execute SSH command on remote host.

        Args:
            host_ip: Target host IP address
            command: Command to execute
            timeout: Timeout in seconds

        Returns:
            CompletedProcess result
        """
        from infra_toolkit.utils.ssh import run_ssh_command

        return run_ssh_command(
            host=host_ip,
            command=command,
            timeout=timeout,
        )

    def _check_port(self, ip: str, port: int, timeout: float = None) -> bool:
        """
        Check if a port is open and responding.

        Args:
            ip: Target IP address
            port: Target port
            timeout: Connection timeout

        Returns:
            True if port is open
        """
        timeout = timeout or self.PORT_TIMEOUT
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception as e:
            logger.debug(f"Port check failed: {e}")
            return False

    def _check_http(self, url: str, timeout: float = None) -> Tuple[bool, int, str]:
        """
        Check HTTP endpoint.

        Args:
            url: URL to check
            timeout: Request timeout

        Returns:
            Tuple of (success, status_code, message)
        """
        timeout = timeout or self.HTTP_TIMEOUT
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True)
            return True, response.status_code, "OK"
        except requests.exceptions.Timeout:
            return False, 0, "Timeout"
        except requests.exceptions.ConnectionError as e:
            return False, 0, f"Connection error: {e}"
        except Exception as e:
            return False, 0, f"Error: {e}"

    def get_vm_status(self) -> Dict[str, Any]:
        """
        Get Home Assistant VM status from Proxmox.

        Returns:
            VM status dictionary
        """
        config = self.HA_CONFIG

        try:
            # Get basic status
            result = self._ssh_command(
                config.proxmox_ip,
                f"qm status {config.vm_id}"
            )

            if result.returncode != 0:
                return {
                    "status": "unknown",
                    "error": result.stderr.strip(),
                    "reachable": False,
                }

            status = result.stdout.strip().replace("status: ", "")

            # Get verbose status for uptime
            verbose_result = self._ssh_command(
                config.proxmox_ip,
                f"qm status {config.vm_id} -verbose"
            )

            uptime_seconds = 0
            if verbose_result.returncode == 0:
                for line in verbose_result.stdout.split('\n'):
                    if 'uptime' in line:
                        try:
                            uptime_seconds = int(line.split(':')[1].strip())
                        except (IndexError, ValueError):
                            pass

            # Format uptime
            uptime_str = self._format_uptime(uptime_seconds)

            # Check for long uptime warning
            uptime_weeks = uptime_seconds / (7 * 24 * 3600)
            long_uptime_warning = uptime_weeks > self.UPTIME_WARNING_WEEKS

            return {
                "status": status,
                "vm_id": config.vm_id,
                "vm_name": config.vm_name,
                "proxmox_host": config.proxmox_host,
                "uptime_seconds": uptime_seconds,
                "uptime": uptime_str,
                "uptime_weeks": round(uptime_weeks, 1),
                "long_uptime_warning": long_uptime_warning,
                "reachable": True,
            }

        except subprocess.TimeoutExpired:
            return {
                "status": "unknown",
                "error": "SSH timeout",
                "reachable": False,
            }
        except Exception as e:
            return {
                "status": "unknown",
                "error": str(e),
                "reachable": False,
            }

    def _format_uptime(self, seconds: int) -> str:
        """Format uptime seconds to human readable string."""
        if seconds == 0:
            return "unknown"

        weeks = seconds // (7 * 24 * 3600)
        days = (seconds % (7 * 24 * 3600)) // (24 * 3600)
        hours = (seconds % (24 * 3600)) // 3600

        parts = []
        if weeks > 0:
            parts.append(f"{weeks}w")
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")

        return " ".join(parts) if parts else "<1h"

    def check_service_health(self) -> Dict[str, Any]:
        """
        Check Home Assistant service health.

        Returns:
            Service health dictionary
        """
        config = self.HA_CONFIG

        checks = {
            "port_8123": False,
            "http_response": False,
            "http_status_code": 0,
        }

        # Check port 8123
        checks["port_8123"] = self._check_port(config.ha_ip, config.ha_port)

        # Check HTTP response
        if checks["port_8123"]:
            url = f"http://{config.ha_ip}:{config.ha_port}/"
            success, status_code, message = self._check_http(url)
            checks["http_response"] = success
            checks["http_status_code"] = status_code
            checks["http_message"] = message

        # Determine overall status
        if checks["port_8123"] and checks["http_response"]:
            status = "healthy"
        elif checks["port_8123"]:
            status = "degraded"
        else:
            status = "unhealthy"

        return {
            "status": status,
            "checks": checks,
            "ip": config.ha_ip,
            "port": config.ha_port,
            "url": f"http://{config.ha_ip}:{config.ha_port}/",
        }

    def check_cloudflare_tunnel(self) -> Dict[str, Any]:
        """
        Check Cloudflare tunnel status for Home Assistant.

        Returns:
            Tunnel status dictionary
        """
        config = self.HA_CONFIG
        tunnel = self.CLOUDFLARE_TUNNEL

        checks = {
            "external_accessible": False,
            "external_status_code": 0,
            "tunnel_container_running": False,
        }

        # Check external access via Cloudflare
        url = f"https://{config.cloudflare_hostname}/"
        success, status_code, message = self._check_http(url, timeout=15)
        checks["external_accessible"] = success
        checks["external_status_code"] = status_code
        checks["external_message"] = message

        # Check tunnel container status
        try:
            result = self._ssh_command(
                tunnel["host_ip"],
                f"docker inspect -f '{{{{.State.Running}}}}' {tunnel['container']} 2>/dev/null"
            )
            checks["tunnel_container_running"] = result.stdout.strip().lower() == "true"
        except Exception as e:
            logger.debug(f"Failed to check tunnel container: {e}")
            checks["tunnel_container_running"] = False

        # Determine status
        if checks["external_accessible"] and checks["tunnel_container_running"]:
            status = "healthy"
        elif checks["tunnel_container_running"]:
            status = "degraded"
        else:
            status = "unhealthy"

        return {
            "status": status,
            "checks": checks,
            "hostname": config.cloudflare_hostname,
            "tunnel_host": tunnel["host"],
            "tunnel_container": tunnel["container"],
        }

    def health_check(self) -> Dict[str, Any]:
        """
        Comprehensive health check for Home Assistant.

        Returns:
            Complete health check results
        """
        # Get all health data
        vm_status = self.get_vm_status()
        service_health = self.check_service_health()
        tunnel_status = self.check_cloudflare_tunnel()

        # Compile checks
        checks = {
            "vm_running": vm_status.get("status") == "running",
            "proxmox_reachable": vm_status.get("reachable", False),
            "port_8123_open": service_health["checks"].get("port_8123", False),
            "http_responding": service_health["checks"].get("http_response", False),
            "cloudflare_accessible": tunnel_status["checks"].get("external_accessible", False),
            "tunnel_container_running": tunnel_status["checks"].get("tunnel_container_running", False),
        }

        # Determine overall status
        critical_checks = ["vm_running", "port_8123_open", "http_responding"]
        important_checks = ["cloudflare_accessible", "tunnel_container_running"]

        critical_passed = all(checks.get(c, False) for c in critical_checks)
        important_passed = all(checks.get(c, False) for c in important_checks)

        if critical_passed and important_passed:
            status = "healthy"
            message = "All systems operational"
        elif critical_passed:
            status = "degraded"
            message = "Core service healthy, external access issues"
        else:
            status = "unhealthy"
            failed = [c for c in critical_checks if not checks.get(c, False)]
            message = f"Critical checks failed: {', '.join(failed)}"

        return {
            "status": status,
            "message": message,
            "checks": checks,
            "vm": vm_status,
            "service": service_health,
            "tunnel": tunnel_status,
        }

    def start_vm(self) -> Dict[str, Any]:
        """
        Start Home Assistant VM.

        Returns:
            Operation result
        """
        config = self.HA_CONFIG

        if self.dry_run:
            logger.info(f"[DRY-RUN] Would start VM {config.vm_id}")
            return {"status": "dry_run", "message": "Would start VM"}

        try:
            result = self._ssh_command(
                config.proxmox_ip,
                f"qm start {config.vm_id}"
            )

            if result.returncode == 0:
                logger.info(f"VM {config.vm_id} started successfully")
                return {"status": "success", "message": "VM started"}
            else:
                return {"status": "error", "message": result.stderr.strip()}

        except Exception as e:
            return {"status": "error", "message": str(e)}

    def stop_vm(self, force: bool = False) -> Dict[str, Any]:
        """
        Stop Home Assistant VM.

        Args:
            force: If True, force stop without graceful shutdown

        Returns:
            Operation result
        """
        config = self.HA_CONFIG

        if self.dry_run:
            logger.info(f"[DRY-RUN] Would stop VM {config.vm_id}")
            return {"status": "dry_run", "message": "Would stop VM"}

        try:
            if force:
                # Kill any stuck processes first
                self._ssh_command(
                    config.proxmox_ip,
                    f"pkill -9 -f 'qm.*{config.vm_id}' 2>/dev/null || true"
                )
                time.sleep(1)

                result = self._ssh_command(
                    config.proxmox_ip,
                    f"qm stop {config.vm_id}"
                )
            else:
                result = self._ssh_command(
                    config.proxmox_ip,
                    f"qm shutdown {config.vm_id}"
                )

            if result.returncode == 0:
                logger.info(f"VM {config.vm_id} stopped successfully")
                return {"status": "success", "message": "VM stopped"}
            else:
                return {"status": "error", "message": result.stderr.strip()}

        except Exception as e:
            return {"status": "error", "message": str(e)}

    def restart_vm(self, force: bool = False, wait_for_service: bool = True) -> Dict[str, Any]:
        """
        Restart Home Assistant VM.

        Args:
            force: If True, force stop before restart
            wait_for_service: If True, wait for service to come up

        Returns:
            Operation result with timing info
        """
        config = self.HA_CONFIG
        start_time = time.time()

        if self.dry_run:
            logger.info(f"[DRY-RUN] Would restart VM {config.vm_id}")
            return {"status": "dry_run", "message": "Would restart VM"}

        # Stop VM
        logger.info("Stopping VM...")
        stop_result = self.stop_vm(force=force)

        if stop_result["status"] != "success":
            # Try force stop if graceful failed
            if not force:
                logger.warning("Graceful shutdown failed, trying force stop...")
                stop_result = self.stop_vm(force=True)

        if stop_result["status"] != "success":
            return {"status": "error", "message": f"Failed to stop VM: {stop_result['message']}"}

        # Wait for VM to fully stop
        for _ in range(30):
            status = self.get_vm_status()
            if status.get("status") == "stopped":
                break
            time.sleep(1)
        else:
            return {"status": "error", "message": "VM did not stop within 30 seconds"}

        # Start VM
        logger.info("Starting VM...")
        start_result = self.start_vm()

        if start_result["status"] != "success":
            return {"status": "error", "message": f"Failed to start VM: {start_result['message']}"}

        # Wait for service if requested
        if wait_for_service:
            logger.info("Waiting for Home Assistant service...")

            # Wait for network (up to 2 minutes)
            network_up = False
            for _ in range(24):
                if self._check_port(config.ha_ip, 22, timeout=2):
                    network_up = True
                    break
                time.sleep(5)

            if not network_up:
                logger.warning("Network did not come up within 2 minutes")

            # Wait for service (up to 4 minutes)
            service_up = False
            for _ in range(24):
                if self._check_port(config.ha_ip, config.ha_port, timeout=2):
                    service_up = True
                    break
                time.sleep(10)

            elapsed = time.time() - start_time

            if service_up:
                return {
                    "status": "success",
                    "message": "VM restarted and service is up",
                    "elapsed_seconds": round(elapsed, 1),
                    "service_up": True,
                }
            else:
                return {
                    "status": "partial",
                    "message": "VM restarted but service not yet responding",
                    "elapsed_seconds": round(elapsed, 1),
                    "service_up": False,
                }

        elapsed = time.time() - start_time
        return {
            "status": "success",
            "message": "VM restarted (not waiting for service)",
            "elapsed_seconds": round(elapsed, 1),
        }

    def get_current_state(self) -> Dict[str, Any]:
        """Get current state for backup purposes."""
        return {
            "vm_status": self.get_vm_status(),
            "service_health": self.check_service_health(),
            "timestamp": __import__("datetime").datetime.now().isoformat(),
        }

    def rollback_from_backup(self, backup_path: Path) -> bool:
        """VM operations don't need rollback - restart is idempotent."""
        logger.warning("VM operations don't support rollback")
        return True

    @classmethod
    def configure_parser(cls, parser):
        """Configure argument parser for Home Assistant tool."""
        # Common options
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview changes without executing"
        )
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Enable verbose logging"
        )
        parser.add_argument(
            "--no-verify",
            action="store_true",
            help="Skip verification checks"
        )

        # Subcommands
        subparsers = parser.add_subparsers(dest="subcommand", help="Home Assistant operations")

        # status
        subparsers.add_parser("status", help="Show VM and service status")

        # health-check
        subparsers.add_parser("health-check", help="Run comprehensive health check")

        # start
        subparsers.add_parser("start", help="Start Home Assistant VM")

        # stop
        stop_parser = subparsers.add_parser("stop", help="Stop Home Assistant VM")
        stop_parser.add_argument(
            "--force",
            action="store_true",
            help="Force stop (no graceful shutdown)"
        )

        # restart
        restart_parser = subparsers.add_parser("restart", help="Restart Home Assistant VM")
        restart_parser.add_argument(
            "--force",
            action="store_true",
            help="Force restart (no graceful shutdown)"
        )
        restart_parser.add_argument(
            "--no-wait",
            action="store_true",
            help="Don't wait for service to come up"
        )

        # tunnel-status
        subparsers.add_parser("tunnel-status", help="Check Cloudflare tunnel status")
