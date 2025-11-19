"""
Network Monitoring Tool

Read-only monitoring of UniFi Dream Machine SE network infrastructure.

Features:
- UniFi API integration with session management
- Network configuration inventory
- WAN/LAN health monitoring
- WiFi network status
- Device inventory (APs, switches, gateway)
- Active client monitoring with bandwidth usage
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import yaml
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from ..base_tool import BaseTool


# Suppress SSL warnings for UDM-SE (self-signed cert)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)


class NetworkTool(BaseTool):
    """
    Network monitoring via UniFi API.

    This tool provides read-only network monitoring:
    1. System health (WAN/LAN connectivity)
    2. Network configurations (networks, VLANs, subnets)
    3. WiFi status (SSIDs, clients, signal strength)
    4. Device inventory (APs, switches, gateway)
    5. Active client monitoring
    """

    def __init__(self, **kwargs):
        """
        Initialize Network tool.

        Args:
            **kwargs: Additional arguments passed to BaseTool
        """
        # Load configuration before calling super().__init__
        config = self._load_config()

        if "unifi" not in config or "udm_se" not in config["unifi"]:
            raise ValueError("unifi.udm_se configuration not found in config.yaml")

        unifi_config = config["unifi"]["udm_se"]
        self.host = unifi_config["host"]
        self.username = unifi_config["username"]
        self.password = unifi_config["password"]
        self.site = unifi_config.get("site", "default")
        self.verify_ssl = unifi_config.get("verify_ssl", False)

        # API base URLs
        self.system_api = unifi_config.get("system_api", f"https://{self.host}/api")
        self.api_base = unifi_config.get("api_base", f"https://{self.host}/proxy/network/api/s/{self.site}")

        super().__init__(config, **kwargs)

        # Setup HTTP session
        self.session = None
        self.csrf_token = None

    @classmethod
    def tool_name(cls) -> str:
        return "net"

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
                    return yaml.safe_load(f)

        raise FileNotFoundError(
            f"No configuration file found. "
            f"Checked: {', '.join(str(p) for p in config_paths)}"
        )

    def validate_config(self) -> bool:
        """Validate UniFi configuration."""
        if not self.host:
            raise ValueError("Missing host in UniFi configuration")

        if not self.username or not self.password:
            raise ValueError("Missing username or password in UniFi configuration")

        return True

    def _authenticate(self) -> bool:
        """
        Authenticate with UniFi API.

        Returns:
            True if authentication successful
        """
        if self.session is not None:
            # Already authenticated
            return True

        try:
            self.session = requests.Session()
            self.session.verify = self.verify_ssl

            # Login
            login_url = f"{self.system_api}/auth/login"
            response = self.session.post(
                login_url,
                json={"username": self.username, "password": self.password},
                timeout=10
            )

            if response.status_code == 200:
                # Get CSRF token from response headers
                self.csrf_token = response.headers.get('X-CSRF-Token')
                if self.csrf_token:
                    self.session.headers.update({'X-CSRF-Token': self.csrf_token})

                logger.info("Successfully authenticated with UniFi API")
                return True
            else:
                logger.error(f"Authentication failed: HTTP {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False

    def _api_get(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """
        Make authenticated GET request to UniFi API.

        Args:
            endpoint: API endpoint (without base URL)

        Returns:
            Response JSON data or None if failed
        """
        if not self._authenticate():
            return None

        try:
            url = f"{self.api_base}/{endpoint}"
            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"API request failed: {url} - HTTP {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"API request error for {endpoint}: {e}")
            return None

    def get_system_health(self) -> Dict[str, Any]:
        """
        Get system health status.

        Returns:
            Health status information
        """
        data = self._api_get("stat/health")

        if not data or "data" not in data:
            return {"status": "unknown", "subsystems": []}

        subsystems = data["data"]
        health_info = {
            "status": "healthy",
            "subsystems": []
        }

        for subsystem in subsystems:
            subsys_info = {
                "name": subsystem.get("subsystem", "unknown"),
                "status": subsystem.get("status", "unknown"),
                "num_adopted": subsystem.get("num_adopted", 0),
                "num_disabled": subsystem.get("num_disabled", 0),
                "num_disconnected": subsystem.get("num_disconnected", 0),
                "num_pending": subsystem.get("num_pending", 0)
            }

            # If any subsystem is not OK, mark overall as unhealthy
            if subsystem.get("status") != "ok":
                health_info["status"] = "unhealthy"

            health_info["subsystems"].append(subsys_info)

        return health_info

    def get_networks(self) -> List[Dict[str, Any]]:
        """
        Get network configurations.

        Returns:
            List of network configurations
        """
        # Use REST endpoint for network configs
        if not self._authenticate():
            return []

        try:
            # Use proxy/network API for REST endpoints
            url = f"https://{self.host}/proxy/network/api/s/{self.site}/rest/networkconf"
            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                networks = []

                for network in data.get("data", []):
                    net_info = {
                        "id": network.get("_id"),
                        "name": network.get("name"),
                        "purpose": network.get("purpose"),
                        "vlan": network.get("vlan"),
                        "ip_subnet": network.get("ip_subnet"),
                        "gateway": network.get("gateway_ip"),
                        "dhcp_enabled": network.get("dhcpd_enabled", False),
                        "dhcp_start": network.get("dhcpd_start"),
                        "dhcp_stop": network.get("dhcpd_stop"),
                        "domain_name": network.get("domain_name")
                    }
                    networks.append(net_info)

                return networks
            else:
                logger.error(f"Failed to get networks: HTTP {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"Error getting networks: {e}")
            return []

    def get_wifi_networks(self) -> List[Dict[str, Any]]:
        """
        Get WiFi (WLAN) configurations.

        Returns:
            List of WLAN configurations
        """
        if not self._authenticate():
            return []

        try:
            # Use proxy/network API for REST endpoints
            url = f"https://{self.host}/proxy/network/api/s/{self.site}/rest/wlanconf"
            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                wlans = []

                for wlan in data.get("data", []):
                    wlan_info = {
                        "id": wlan.get("_id"),
                        "name": wlan.get("name"),
                        "enabled": wlan.get("enabled", False),
                        "security": wlan.get("security"),
                        "wpa_mode": wlan.get("wpa_mode"),
                        "wpa_enc": wlan.get("wpa_enc"),
                        "usergroup_id": wlan.get("usergroup_id"),
                        "is_guest": wlan.get("is_guest", False),
                        "minrate_ng_enabled": wlan.get("minrate_ng_enabled"),
                        "minrate_ng_data_rate_kbps": wlan.get("minrate_ng_data_rate_kbps"),
                        "minrate_na_enabled": wlan.get("minrate_na_enabled"),
                        "minrate_na_data_rate_kbps": wlan.get("minrate_na_data_rate_kbps")
                    }
                    wlans.append(wlan_info)

                return wlans
            else:
                logger.error(f"Failed to get WLANs: HTTP {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"Error getting WLANs: {e}")
            return []

    def get_devices(self) -> List[Dict[str, Any]]:
        """
        Get network devices (APs, switches, gateway).

        Returns:
            List of device information
        """
        data = self._api_get("stat/device")

        if not data or "data" not in data:
            return []

        devices = []

        for device in data["data"]:
            dev_info = {
                "id": device.get("_id"),
                "mac": device.get("mac"),
                "name": device.get("name"),
                "model": device.get("model"),
                "type": device.get("type"),
                "ip": device.get("ip"),
                "state": device.get("state"),
                "adopted": device.get("adopted", False),
                "uptime": device.get("uptime", 0),
                "version": device.get("version"),
                "upgradable": device.get("upgradable", False),
                "uplink": device.get("uplink", {})
            }

            # For APs, add client count
            if device.get("type") == "uap":
                dev_info["num_sta"] = device.get("num_sta", 0)
                dev_info["user-num_sta"] = device.get("user-num_sta", 0)

            devices.append(dev_info)

        return devices

    def get_clients(self) -> List[Dict[str, Any]]:
        """
        Get active clients.

        Returns:
            List of client information
        """
        data = self._api_get("stat/sta")

        if not data or "data" not in data:
            return []

        clients = []

        for client in data["data"]:
            client_info = {
                "mac": client.get("mac"),
                "hostname": client.get("hostname", client.get("name", "Unknown")),
                "ip": client.get("ip"),
                "network": client.get("network"),
                "is_wired": client.get("is_wired", False),
                "is_guest": client.get("is_guest", False),
                "ap_mac": client.get("ap_mac"),
                "essid": client.get("essid"),
                "channel": client.get("channel"),
                "radio": client.get("radio"),
                "signal": client.get("signal"),
                "rssi": client.get("rssi"),
                "tx_bytes": client.get("tx_bytes", 0),
                "rx_bytes": client.get("rx_bytes", 0),
                "uptime": client.get("uptime", 0)
            }

            # Calculate total bandwidth
            client_info["total_bytes"] = client_info["tx_bytes"] + client_info["rx_bytes"]

            clients.append(client_info)

        return clients

    def health_check(self) -> Dict[str, Any]:
        """
        Check UniFi API connectivity and authentication.

        Returns:
            Health check results
        """
        checks = {}

        # Test authentication
        auth_success = self._authenticate()
        checks["api_authentication"] = auth_success

        if auth_success:
            # Test basic API query
            health_data = self.get_system_health()
            checks["api_query"] = health_data.get("status") != "unknown"
            checks["system_health"] = health_data.get("status")
        else:
            checks["api_query"] = False

        # Overall status
        all_healthy = checks.get("api_authentication", False) and checks.get("api_query", False)
        status = "healthy" if all_healthy else "unhealthy"

        return {
            "status": status,
            "checks": checks,
            "message": "UniFi API accessible" if all_healthy else "Cannot access UniFi API"
        }

    # BaseTool abstract methods (read-only tool)

    def get_current_state(self) -> Dict[str, Any]:
        """Get current network state snapshot."""
        return {
            "message": "Read-only tool - network snapshot",
            "timestamp": datetime.utcnow().isoformat(),
            "host": self.host
        }

    def rollback_from_backup(self, backup_path: Path) -> bool:
        """Rollback not supported (read-only tool)."""
        raise NotImplementedError("Network tool is read-only - no rollback needed")

    def verify_operation(self, operation_name: str, result: Any) -> bool:
        """Verify operation (not used for read-only operations)."""
        return True

    @classmethod
    def configure_parser(cls, parser):
        """Configure argument parser for Network tool."""
        super().configure_parser(parser)

        subparsers = parser.add_subparsers(dest="subcommand", help="Network subcommands")

        # Health command
        health_parser = subparsers.add_parser("health", help="System and WAN/LAN health status")

        # Networks command
        networks_parser = subparsers.add_parser("networks", help="Network configurations")

        # WiFi command
        wifi_parser = subparsers.add_parser("wifi", help="WiFi network status")

        # Devices command
        devices_parser = subparsers.add_parser("devices", help="Network devices (APs, switches, gateway)")

        # Clients command
        clients_parser = subparsers.add_parser("clients", help="Active client list")
        clients_parser.add_argument("--top", type=int, help="Show top N clients by bandwidth")
        clients_parser.add_argument("--sort-by", choices=["bandwidth", "signal", "name"], default="bandwidth",
                                   help="Sort clients by field")

        # Health check command
        health_check_parser = subparsers.add_parser("health-check", help="Check UniFi API connectivity")
