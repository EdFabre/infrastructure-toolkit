"""
Proxmox VE Management Tool

Provides USB passthrough management and monitoring for Proxmox VE VMs.
Supports automatic detection and recovery of failed USB devices.
"""

import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..base_tool import BaseTool


logger = logging.getLogger(__name__)


@dataclass
class USBDevice:
    """Represents a USB device configuration."""
    device_id: str  # e.g., "usb0"
    vendor_id: int
    product_id: int
    product_name: str
    speed: str  # e.g., "12 Mb/s"
    port: int
    host_bus: Optional[int] = None
    host_port: Optional[str] = None

    @property
    def is_healthy(self) -> bool:
        """Check if device appears healthy based on speed."""
        # Logitech receivers should be 12 Mb/s, not 1.5 Mb/s
        if "logitech" in self.product_name.lower() or "receiver" in self.product_name.lower():
            return "12" in self.speed or "480" in self.speed
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "vendor_id": hex(self.vendor_id),
            "product_id": hex(self.product_id),
            "product_name": self.product_name,
            "speed": self.speed,
            "port": self.port,
            "host_bus": self.host_bus,
            "host_port": self.host_port,
            "is_healthy": self.is_healthy,
        }


class ProxmoxTool(BaseTool):
    """
    Proxmox VE management tool with USB passthrough support.

    Features:
    - USB device status monitoring
    - Automatic USB device recovery (hotplug reset)
    - VM USB configuration management
    - Health monitoring for USB passthrough
    """

    # Known Proxmox hosts
    PROXMOX_HOSTS = {
        "pve3": {
            "ip": "192.168.1.9",
            "ssh_user": "root",
        },
    }

    # Known USB devices that need monitoring
    MONITORED_USB_DEVICES = {
        "logitech_unifying": {
            "vendor_id": 0x046d,
            "product_id": 0xc52b,
            "name": "Logitech Unifying Receiver",
            "expected_speed": "12 Mb/s",
            "host_port": "4.1.1.3.3.3",  # Physical USB path
            "host_bus": 3,
        },
    }

    def __init__(
        self,
        host: str = "pve3",
        dry_run: bool = False,
        verbose: bool = False,
        no_verify: bool = False,
    ):
        """
        Initialize Proxmox tool.

        Args:
            host: Proxmox host identifier (e.g., "pve3")
            dry_run: If True, preview changes without executing
            verbose: Enable verbose logging
            no_verify: Skip verification checks
        """
        if host not in self.PROXMOX_HOSTS:
            raise ValueError(f"Unknown Proxmox host: {host}. Known hosts: {list(self.PROXMOX_HOSTS.keys())}")

        self.host = host
        self.host_config = self.PROXMOX_HOSTS[host]

        # Initialize base tool
        config = {
            "host": host,
            "ip": self.host_config["ip"],
        }
        super().__init__(config, dry_run, verbose, no_verify)

    @classmethod
    def tool_name(cls) -> str:
        return "proxmox"

    def validate_config(self) -> bool:
        """Validate Proxmox configuration."""
        return self.host in self.PROXMOX_HOSTS

    def _ssh_command(self, command: str, timeout: int = 30) -> subprocess.CompletedProcess:
        """
        Execute SSH command on Proxmox host.

        Args:
            command: Command to execute
            timeout: Timeout in seconds

        Returns:
            CompletedProcess result
        """
        ssh_cmd = [
            "ssh",
            "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no",
            f"{self.host_config['ssh_user']}@{self.host_config['ip']}",
            command
        ]

        logger.debug(f"SSH: {command}")

        return subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

    def _qmp_command(self, vm_id: int, command: str, arguments: Optional[Dict] = None) -> Dict:
        """
        Execute QMP command on VM.

        Args:
            vm_id: VM ID
            command: QMP command name
            arguments: Optional command arguments

        Returns:
            QMP response dictionary
        """
        qmp_socket = f"/var/run/qemu-server/{vm_id}.qmp"

        # Build QMP messages as proper JSON
        messages = ['{"execute": "qmp_capabilities"}']

        if arguments:
            cmd = {"execute": command, "arguments": arguments}
        else:
            cmd = {"execute": command}
        messages.append(json.dumps(cmd))

        # Use printf with proper escaping instead of echo -e
        # Join with literal newline and escape for shell
        qmp_payload = "\n".join(messages)
        # Escape single quotes for shell
        qmp_payload_escaped = qmp_payload.replace("'", "'\"'\"'")

        ssh_cmd = f"printf '%s\\n' '{qmp_payload_escaped}' | socat - UNIX-CONNECT:{qmp_socket} 2>/dev/null"

        result = self._ssh_command(ssh_cmd)

        if result.returncode != 0:
            raise RuntimeError(f"QMP command failed: {result.stderr}")

        # Parse responses (multiple JSON objects on separate lines)
        responses = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                try:
                    responses.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        # Return last response (command result)
        return responses[-1] if responses else {}

    def _hmp_command(self, vm_id: int, command: str) -> str:
        """
        Execute HMP (Human Monitor Protocol) command via QMP.

        Args:
            vm_id: VM ID
            command: HMP command string

        Returns:
            Command output string
        """
        result = self._qmp_command(
            vm_id,
            "human-monitor-command",
            {"command-line": command}
        )
        output = result.get("return", "")
        # Replace escaped newlines with actual newlines
        output = output.replace("\\r\\n", "\n").replace("\\n", "\n")
        return output

    def get_vm_usb_devices(self, vm_id: int) -> List[USBDevice]:
        """
        Get list of USB devices attached to VM.

        Args:
            vm_id: VM ID

        Returns:
            List of USBDevice objects
        """
        output = self._hmp_command(vm_id, "info usb")

        devices = []
        for line in output.replace("\\r\\n", "\n").split("\n"):
            line = line.strip()
            if not line or "Device" not in line:
                continue

            # Parse line like: "Device 2.1, Port 1, Speed 12 Mb/s, Product USB Receiver, ID: usb0"
            try:
                parts = line.split(", ")
                port = int(parts[1].replace("Port ", ""))
                speed = parts[2].replace("Speed ", "")
                product = parts[3].replace("Product ", "")
                device_id = parts[4].replace("ID: ", "")

                devices.append(USBDevice(
                    device_id=device_id,
                    vendor_id=0,  # Not available from info usb
                    product_id=0,
                    product_name=product,
                    speed=speed,
                    port=port,
                ))
            except (IndexError, ValueError) as e:
                logger.debug(f"Failed to parse USB line: {line} - {e}")
                continue

        return devices

    def get_vm_config(self, vm_id: int) -> Dict[str, Any]:
        """
        Get VM configuration.

        Args:
            vm_id: VM ID

        Returns:
            VM configuration dictionary
        """
        result = self._ssh_command(f"qm config {vm_id}")

        if result.returncode != 0:
            raise RuntimeError(f"Failed to get VM config: {result.stderr}")

        config = {}
        for line in result.stdout.strip().split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                config[key.strip()] = value.strip()

        return config

    def check_usb_health(self, vm_id: int) -> Dict[str, Any]:
        """
        Check health of USB devices attached to VM.

        Args:
            vm_id: VM ID

        Returns:
            Health check results
        """
        devices = self.get_vm_usb_devices(vm_id)

        issues = []
        for device in devices:
            if not device.is_healthy:
                issues.append({
                    "device_id": device.device_id,
                    "product": device.product_name,
                    "issue": f"Unexpected speed: {device.speed}",
                    "expected": "12 Mb/s or higher",
                })

        return {
            "vm_id": vm_id,
            "total_devices": len(devices),
            "healthy_devices": len([d for d in devices if d.is_healthy]),
            "unhealthy_devices": len(issues),
            "issues": issues,
            "devices": [d.to_dict() for d in devices],
            "status": "healthy" if not issues else "unhealthy",
        }

    def reset_usb_device(
        self,
        vm_id: int,
        device_id: str,
        use_hostport: bool = True,
        device_config: Optional[Dict] = None,
    ) -> bool:
        """
        Reset a USB device by removing and re-adding it to the VM.

        Args:
            vm_id: VM ID
            device_id: USB device ID (e.g., "usb0")
            use_hostport: If True, use hostbus/hostport for re-attachment
            device_config: Optional device configuration override

        Returns:
            True if reset successful
        """
        logger.info(f"Resetting USB device {device_id} on VM {vm_id}")

        # Get current VM config to find USB device settings
        vm_config = self.get_vm_config(vm_id)
        usb_config = vm_config.get(device_id, "")

        # Parse existing config or use provided/default
        if device_config:
            config = device_config
        elif "host=" in usb_config:
            # Parse existing: host=046d:c52b or host=3-4.1.1.3.3.4
            host_value = usb_config.split("host=")[1].split(",")[0]
            if ":" in host_value and len(host_value) == 9:  # vendor:product format
                vendor, product = host_value.split(":")
                config = {
                    "vendor_id": int(vendor, 16),
                    "product_id": int(product, 16),
                }
            else:
                # It's a host port
                config = {"host_port": host_value}
        else:
            # Use monitored device config as fallback
            config = self.MONITORED_USB_DEVICES.get("logitech_unifying", {})

        if self.dry_run:
            logger.info(f"[DRY-RUN] Would reset {device_id} with config: {config}")
            return True

        # Step 1: Remove device
        logger.info(f"Removing {device_id}...")
        try:
            result = self._qmp_command(vm_id, "device_del", {"id": device_id})
            if "error" in result:
                logger.warning(f"Remove warning: {result['error']}")
        except Exception as e:
            logger.warning(f"Remove failed (may not exist): {e}")

        # Wait for device to be fully removed
        import time
        time.sleep(1)

        # Step 2: Reset on host side (optional but recommended)
        if "host_port" in config:
            host_port = config["host_port"]
            logger.info(f"Unbinding/rebinding USB on host port {host_port}...")

            unbind_cmd = f'echo "{host_port}" > /sys/bus/usb/drivers/usb/unbind 2>/dev/null || true'
            self._ssh_command(unbind_cmd)
            time.sleep(1)

            bind_cmd = f'echo "{host_port}" > /sys/bus/usb/drivers/usb/bind 2>/dev/null || true'
            self._ssh_command(bind_cmd)
            time.sleep(2)

        # Step 3: Re-add device using hostbus/hostport (more reliable)
        logger.info(f"Re-adding {device_id}...")

        add_args = {
            "driver": "usb-host",
            "id": device_id,
            "bus": "xhci.0",
            "port": str(config.get("port", 1)),
        }

        if use_hostport and "host_bus" in config and "host_port" in config:
            add_args["hostbus"] = config["host_bus"]
            add_args["hostport"] = config["host_port"]
        else:
            add_args["vendorid"] = config.get("vendor_id", 0x046d)
            add_args["productid"] = config.get("product_id", 0xc52b)

        result = self._qmp_command(vm_id, "device_add", add_args)

        if "error" in result:
            logger.error(f"Failed to add device: {result['error']}")
            return False

        logger.info(f"✓ USB device {device_id} reset successfully")
        return True

    def auto_fix_usb(self, vm_id: int) -> Dict[str, Any]:
        """
        Automatically detect and fix unhealthy USB devices.

        Args:
            vm_id: VM ID

        Returns:
            Results of auto-fix operation
        """
        logger.info(f"Running auto-fix for VM {vm_id}...")

        health = self.check_usb_health(vm_id)

        if health["status"] == "healthy":
            return {
                "status": "no_action_needed",
                "message": "All USB devices are healthy",
                "devices_checked": health["total_devices"],
            }

        fixed = []
        failed = []

        for issue in health["issues"]:
            device_id = issue["device_id"]
            logger.info(f"Attempting to fix {device_id}: {issue['issue']}")

            # Try to find matching monitored device config
            device_config = None
            for name, config in self.MONITORED_USB_DEVICES.items():
                if config["name"].lower() in issue["product"].lower():
                    device_config = config
                    device_config["port"] = 1  # Default port
                    break

            if self.reset_usb_device(vm_id, device_id, device_config=device_config):
                fixed.append(device_id)
            else:
                failed.append(device_id)

        # Re-check health
        new_health = self.check_usb_health(vm_id)

        return {
            "status": "fixed" if not failed else "partial",
            "fixed_devices": fixed,
            "failed_devices": failed,
            "new_health": new_health,
        }

    def health_check(self) -> Dict[str, Any]:
        """
        Check overall Proxmox tool health.

        Returns:
            Health check results
        """
        checks = {}

        # Check SSH connectivity
        try:
            result = self._ssh_command("echo ok")
            checks["ssh_connectivity"] = result.returncode == 0
        except Exception as e:
            checks["ssh_connectivity"] = False
            checks["ssh_error"] = str(e)

        # Check if socat is available
        try:
            result = self._ssh_command("which socat")
            checks["socat_available"] = result.returncode == 0
        except Exception:
            checks["socat_available"] = False

        # Check PVE version
        try:
            result = self._ssh_command("pveversion")
            checks["pve_version"] = result.stdout.strip() if result.returncode == 0 else "unknown"
        except Exception:
            checks["pve_version"] = "unknown"

        status = "healthy" if all([
            checks.get("ssh_connectivity"),
            checks.get("socat_available"),
        ]) else "unhealthy"

        return {
            "status": status,
            "checks": checks,
            "host": self.host,
            "ip": self.host_config["ip"],
        }

    def get_current_state(self) -> Dict[str, Any]:
        """Get current state for backup purposes."""
        return {
            "host": self.host,
            "timestamp": __import__("datetime").datetime.now().isoformat(),
        }

    def rollback_from_backup(self, backup_path: Path) -> bool:
        """USB operations don't need rollback - just re-run fix."""
        logger.warning("USB operations don't support rollback - run auto-fix instead")
        return True

    @classmethod
    def configure_parser(cls, parser):
        """Configure argument parser for Proxmox tool."""
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
        parser.add_argument(
            "--host",
            default="pve3",
            help="Proxmox host (default: pve3)"
        )

        # Subcommands
        subparsers = parser.add_subparsers(dest="subcommand", help="Proxmox operations")

        # health-check
        subparsers.add_parser("health-check", help="Check Proxmox tool health")

        # usb-status
        usb_status = subparsers.add_parser("usb-status", help="Check USB device status for a VM")
        usb_status.add_argument("vm_id", type=int, help="VM ID")

        # usb-reset
        usb_reset = subparsers.add_parser("usb-reset", help="Reset a USB device")
        usb_reset.add_argument("vm_id", type=int, help="VM ID")
        usb_reset.add_argument("device_id", help="USB device ID (e.g., usb0)")

        # usb-auto-fix
        usb_autofix = subparsers.add_parser("usb-auto-fix", help="Auto-detect and fix USB issues")
        usb_autofix.add_argument("vm_id", type=int, help="VM ID")
