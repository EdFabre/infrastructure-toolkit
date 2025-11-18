"""
Pterodactyl Panel Monitoring Tool

Safe read-only monitoring for Pterodactyl game server infrastructure.

Features:
- Panel health checks
- Wings (nodes) status monitoring
- Server inventory
- Cloudflare tunnel configuration detection
- Common issue diagnosis (hollow hearts / 502 errors)
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from ..base_tool import BaseTool


logger = logging.getLogger(__name__)


class PterodactylTool(BaseTool):
    """
    Pterodactyl Panel monitoring with read-only operations.

    This tool provides safe inspection of Pterodactyl infrastructure:
    1. Panel health and version
    2. Wings (nodes) status and connectivity
    3. Game server inventory
    4. Common issue detection (tunnel misconfigurations)

    All operations are READ-ONLY for safety.
    """

    def __init__(self, **kwargs):
        """
        Initialize Pterodactyl tool.

        Args:
            **kwargs: Additional arguments passed to BaseTool
        """
        # Load configuration before calling super().__init__
        config = self._load_config()

        if "pterodactyl_api" not in config:
            raise ValueError("pterodactyl_api configuration not found in config.yaml")

        self.panel_url = config["pterodactyl_api"]["url"]
        self.api_key = config["pterodactyl_api"]["key"]

        super().__init__(config, **kwargs)

        # Setup HTTP session with authentication
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        })

        # Known node configurations (for validation)
        self.expected_nodes = {
            "games-node-1.haymoed.com": {
                "ip": "192.168.1.71",
                "port": 48080,
                "protocol": "http",
                "server": "masteryi-king-01",
                "purpose": "High-performance wing"
            },
            "games-node-2.haymoed.com": {
                "ip": "192.168.1.17",
                "port": 48080,
                "protocol": "http",
                "server": "masteryi-boss-07",
                "purpose": "Standard wing"
            }
        }

    @classmethod
    def tool_name(cls) -> str:
        return "pterodactyl"

    def _load_config(self) -> Dict[str, Any]:
        """
        Load Pterodactyl configuration from config.yaml.

        Returns:
            Configuration dictionary

        Raises:
            FileNotFoundError: If config file doesn't exist
        """
        import yaml

        config_path = Path("/mnt/tank/faststorage/general/repo/ai-config/config.yaml")

        if not config_path.exists():
            raise FileNotFoundError(f"Configuration not found: {config_path}")

        with open(config_path, 'r') as f:
            return yaml.safe_load(f)

    def validate_config(self) -> bool:
        """Validate Pterodactyl configuration."""
        if not self.panel_url:
            raise ValueError("Missing panel_url in configuration")

        if not self.api_key:
            raise ValueError("Missing api_key in configuration")

        return True

    def health_check(self) -> Dict[str, Any]:
        """
        Check Pterodactyl panel health and connectivity.

        Returns:
            Health check results with panel status
        """
        checks = {}

        # Test application API access (confirms panel connectivity, auth, and API access)
        try:
            response = self.session.get(
                f"{self.panel_url}/api/application/nodes",
                timeout=10
            )

            checks["panel_connectivity"] = response.status_code == 200
            checks["api_authentication"] = response.status_code != 401
            checks["api_access"] = response.status_code == 200

            if response.status_code == 200:
                data = response.json()
                node_count = len(data.get("data", []))
                checks["node_count"] = node_count
            elif response.status_code == 401:
                checks["auth_error"] = "Invalid API token"
            else:
                checks["api_error"] = f"Unexpected status code: {response.status_code}"

        except requests.exceptions.ConnectionError as e:
            checks["panel_connectivity"] = False
            checks["api_authentication"] = False
            checks["api_access"] = False
            checks["error"] = f"Connection failed: {str(e)}"
        except requests.exceptions.Timeout as e:
            checks["panel_connectivity"] = False
            checks["api_authentication"] = False
            checks["api_access"] = False
            checks["error"] = f"Request timeout: {str(e)}"
        except Exception as e:
            checks["panel_connectivity"] = False
            checks["api_authentication"] = False
            checks["api_access"] = False
            checks["error"] = str(e)

        # Determine overall status
        all_healthy = checks.get("panel_connectivity", False) and \
                     checks.get("api_authentication", False) and \
                     checks.get("api_access", False)

        status = "healthy" if all_healthy else "unhealthy"

        return {
            "status": status,
            "checks": checks,
            "message": "All checks passed" if all_healthy else "One or more checks failed"
        }

    def list_nodes(self) -> List[Dict[str, Any]]:
        """
        List all wings (nodes) configured in the panel.

        Returns:
            List of node information dictionaries
        """
        try:
            response = self.session.get(
                f"{self.panel_url}/api/application/nodes",
                timeout=30
            )
            response.raise_for_status()

            data = response.json()
            nodes = []

            for node_data in data.get("data", []):
                attrs = node_data.get("attributes", {})

                # Check if node is expected
                fqdn = attrs.get("fqdn", "")
                is_expected = fqdn in self.expected_nodes
                expected_config = self.expected_nodes.get(fqdn, {})

                node_info = {
                    "id": attrs.get("id"),
                    "name": attrs.get("name"),
                    "fqdn": fqdn,
                    "scheme": attrs.get("scheme", "https"),
                    "daemon_listen": attrs.get("daemon_listen", 8080),
                    "daemon_sftp": attrs.get("daemon_sftp", 2022),
                    "memory": attrs.get("memory", 0),
                    "disk": attrs.get("disk", 0),
                    "daemon_base": attrs.get("daemon_base"),
                    "is_expected": is_expected,
                    "expected_config": expected_config if is_expected else None
                }

                # Detect potential misconfigurations
                if is_expected:
                    expected_port = expected_config.get("port", 48080)
                    expected_scheme = expected_config.get("protocol", "http")

                    # Check if tunnel is pointing to wrong port
                    if attrs.get("daemon_listen") != expected_port:
                        node_info["warning"] = f"Node configured for port {attrs.get('daemon_listen')}, expected {expected_port}"

                    if attrs.get("scheme") != expected_scheme:
                        node_info["warning"] = f"Node configured for {attrs.get('scheme')}, expected {expected_scheme}"

                nodes.append(node_info)

            logger.info(f"Found {len(nodes)} node(s) in panel")
            return nodes

        except requests.HTTPError as e:
            logger.error(f"HTTP error fetching nodes: {e}")
            raise
        except Exception as e:
            logger.error(f"Error fetching nodes: {e}")
            raise

    def get_node_status(self, node_id: int) -> Dict[str, Any]:
        """
        Get detailed status for a specific node.

        Args:
            node_id: Node ID from panel

        Returns:
            Node status information
        """
        try:
            response = self.session.get(
                f"{self.panel_url}/api/application/nodes/{node_id}",
                timeout=30
            )
            response.raise_for_status()

            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})

            return {
                "id": attrs.get("id"),
                "name": attrs.get("name"),
                "fqdn": attrs.get("fqdn"),
                "is_maintenance": attrs.get("maintenance_mode", False),
                "allocated_memory": attrs.get("allocated_memory", 0),
                "allocated_disk": attrs.get("allocated_disk", 0),
                "memory_overallocate": attrs.get("memory_overallocate", 0),
                "disk_overallocate": attrs.get("disk_overallocate", 0),
            }

        except Exception as e:
            logger.error(f"Error fetching node {node_id} status: {e}")
            raise

    def diagnose_tunnel_config(self) -> Dict[str, Any]:
        """
        Diagnose Cloudflare tunnel configuration issues.

        Checks if wings are configured with correct ports to avoid the
        "hollow heart" issue caused by tunnel pointing to 443 instead of 48080.

        Returns:
            Diagnosis results with warnings and recommendations
        """
        diagnosis = {
            "status": "unknown",
            "issues": [],
            "warnings": [],
            "recommendations": []
        }

        try:
            nodes = self.list_nodes()

            for node in nodes:
                if not node.get("is_expected"):
                    continue

                fqdn = node.get("fqdn")
                expected_config = node.get("expected_config", {})
                expected_port = expected_config.get("port", 48080)
                expected_scheme = expected_config.get("protocol", "http")

                # Check scheme mismatch (common issue)
                if node.get("scheme") == "https" and expected_scheme == "http":
                    diagnosis["issues"].append({
                        "node": fqdn,
                        "issue": "Scheme mismatch",
                        "current": "https",
                        "expected": "http",
                        "impact": "Browser heartbeat will fail (hollow hearts)",
                        "fix": f"Update Cloudflare tunnel to point {fqdn} → http://{expected_config.get('ip')}:{expected_port}"
                    })

                # Check port mismatch
                daemon_listen = node.get("daemon_listen", 8080)
                if daemon_listen == 443 and expected_port == 48080:
                    diagnosis["issues"].append({
                        "node": fqdn,
                        "issue": "Port mismatch",
                        "current": daemon_listen,
                        "expected": expected_port,
                        "impact": "Wing unreachable via Cloudflare tunnel",
                        "fix": f"Update panel database: daemon_listen={expected_port}"
                    })

            # Set overall status
            if diagnosis["issues"]:
                diagnosis["status"] = "issues_found"
                diagnosis["recommendations"].append(
                    "Run: infra-toolkit cloudflare list to verify tunnel configuration"
                )
                diagnosis["recommendations"].append(
                    "Ensure games-node-*.haymoed.com points to http://192.168.1.{71,17}:48080"
                )
            else:
                diagnosis["status"] = "healthy"
                diagnosis["recommendations"].append("Configuration looks correct")

        except Exception as e:
            diagnosis["status"] = "error"
            diagnosis["error"] = str(e)

        return diagnosis

    def list_servers(self, node_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        List game servers (optionally filtered by node).

        Args:
            node_id: Optional node ID to filter servers

        Returns:
            List of server information
        """
        try:
            url = f"{self.panel_url}/api/application/servers"
            if node_id:
                url += f"?filter[node]={node_id}"

            response = self.session.get(url, timeout=30)
            response.raise_for_status()

            data = response.json()
            servers = []

            for server_data in data.get("data", []):
                attrs = server_data.get("attributes", {})
                servers.append({
                    "id": attrs.get("id"),
                    "uuid": attrs.get("uuid"),
                    "name": attrs.get("name"),
                    "node": attrs.get("node"),
                    "status": attrs.get("status"),
                    "is_suspended": attrs.get("suspended", False),
                    "limits": {
                        "memory": attrs.get("limits", {}).get("memory", 0),
                        "disk": attrs.get("limits", {}).get("disk", 0),
                        "cpu": attrs.get("limits", {}).get("cpu", 0),
                    }
                })

            logger.info(f"Found {len(servers)} server(s)")
            return servers

        except Exception as e:
            logger.error(f"Error fetching servers: {e}")
            raise

    # BaseTool abstract methods (not used for read-only tool)

    def get_current_state(self) -> Dict[str, Any]:
        """Get current state (not used for read-only operations)."""
        return {"message": "Read-only tool - no state tracking needed"}

    def rollback_from_backup(self, backup_path: Path) -> bool:
        """Rollback not supported (read-only tool)."""
        raise NotImplementedError("Pterodactyl tool is read-only - no rollback needed")

    def verify_operation(self, operation_name: str, result: Any) -> bool:
        """Verify operation (not used for read-only operations)."""
        return True

    @classmethod
    def configure_parser(cls, parser):
        """Configure argument parser for Pterodactyl tool."""
        super().configure_parser(parser)

        subparsers = parser.add_subparsers(dest="subcommand", help="Pterodactyl subcommands")

        # Health check command
        health_parser = subparsers.add_parser("health-check", help="Check panel and API health")

        # List nodes command
        nodes_parser = subparsers.add_parser("nodes", help="List all wings (nodes)")

        # Node status command
        node_status_parser = subparsers.add_parser("node-status", help="Get status for specific node")
        node_status_parser.add_argument("node_id", type=int, help="Node ID")

        # Diagnose tunnel config
        diagnose_parser = subparsers.add_parser("diagnose", help="Diagnose tunnel configuration issues")

        # List servers command
        servers_parser = subparsers.add_parser("servers", help="List game servers")
        servers_parser.add_argument("--node", type=int, help="Filter by node ID")
