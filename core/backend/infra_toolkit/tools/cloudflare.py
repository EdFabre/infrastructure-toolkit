"""
Cloudflare Tunnel Management Tool

Manages Cloudflare Tunnel configurations with automatic safety mechanisms.

Features:
- Add/remove hostnames to tunnel ingress rules
- List current tunnel configuration
- Validate tunnel configuration integrity
- Automatic backup before ALL modifications
- Rollback on failure
- Merge-based updates (not full replacement)
"""

import copy
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import yaml

from ..base_tool import BaseTool


logger = logging.getLogger(__name__)


class CloudflareTool(BaseTool):
    """
    Cloudflare Tunnel management with built-in safety.

    This tool fixes the critical bugs in cloudflare-functions.sh:
    1. Automatic backup before every modification
    2. Merge (not replace) tunnel configuration
    3. Verification of hostname count and structure
    4. Dry-run mode for preview
    5. Rollback on failure
    """

    # API endpoints
    CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"

    # Domains with small tunnel configs (fewer hostnames expected)
    SMALL_DOMAINS = {"ramcyber": 3, "cipherhq": 1, "eureked": 1,
                     "luckyjadejewelry": 0, "fancierboutiq": 0}

    def __init__(self, domain: str = "haymoed", **kwargs):
        """
        Initialize Cloudflare tool.

        Args:
            domain: Domain to manage (any domain configured in config.yaml)
            **kwargs: Additional arguments passed to BaseTool
        """
        # Load configuration before calling super().__init__
        config = self._load_config()

        # Extract domain-specific configuration
        cf_config = config.get("cloudflare", {})
        if domain not in cf_config:
            available = [k for k in cf_config if k not in ("api_token", "account_id")]
            raise ValueError(f"Domain '{domain}' not found. Available: {available}")

        self.domain = domain
        self.api_token = cf_config["api_token"]
        self.account_id = cf_config["account_id"]
        self.zone_id = cf_config[domain]["zone_id"]
        self.tunnel_id = cf_config[domain]["tunnel_id"]

        # Domain suffix for hostname construction
        # cipherhq uses .dev TLD, others use .com
        self.domain_fqdn = f"{domain}.dev" if domain == "cipherhq" else f"{domain}.com"

        super().__init__(config, **kwargs)

        # Setup HTTP session with authentication
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        })

        # Minimum hostname count threshold (to detect accidental wipes)
        self.min_hostname_count = self.SMALL_DOMAINS.get(domain, 20)

    @classmethod
    def tool_name(cls) -> str:
        return "cloudflare"

    def _load_config(self) -> Dict[str, Any]:
        """
        Load Cloudflare configuration from ai-config/scripts/config.yaml.

        Returns:
            Configuration dictionary

        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If configuration is invalid
        """
        # Look for config in ai-config/config.yaml
        config_paths = [
            Path("/app/config.yaml"),  # Docker container mount
            Path("/mnt/tank/faststorage/general/repo/ai-config/config.yaml"),
            Path.home() / ".config" / "infrastructure-toolkit" / "config.yaml",
        ]

        for config_path in config_paths:
            if config_path.exists():
                logger.debug(f"Loading config from: {config_path}")
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f)

        raise FileNotFoundError(
            "Cloudflare configuration not found. "
            f"Checked: {', '.join(str(p) for p in config_paths)}"
        )

    def validate_config(self) -> bool:
        """Validate Cloudflare configuration."""
        required_fields = ["api_token", "account_id"]

        for field in required_fields:
            if not getattr(self, field, None):
                raise ValueError(f"Missing required field: {field}")

        if not self.zone_id or not self.tunnel_id:
            raise ValueError(f"Missing zone_id or tunnel_id for domain: {self.domain}")

        return True

    def health_check(self) -> Dict[str, Any]:
        """
        Check Cloudflare API connectivity and authentication.

        Returns:
            Health check results
        """
        checks = {}

        # Test API connectivity
        try:
            response = self.session.get(
                f"{self.CLOUDFLARE_API_BASE}/user/tokens/verify",
                timeout=10
            )
            checks["api_connectivity"] = response.status_code == 200
            checks["authentication"] = response.json().get("success", False)
        except Exception as e:
            checks["api_connectivity"] = False
            checks["authentication"] = False
            checks["error"] = str(e)

        # Test tunnel access
        try:
            config = self._get_tunnel_config_raw()
            checks["tunnel_access"] = config is not None
        except Exception as e:
            checks["tunnel_access"] = False
            checks["tunnel_error"] = str(e)

        # Determine overall status
        all_healthy = all(checks.get(k, False) for k in ["api_connectivity", "authentication", "tunnel_access"])
        status = "healthy" if all_healthy else "unhealthy"

        return {
            "status": status,
            "checks": checks,
            "message": "All checks passed" if all_healthy else "One or more checks failed"
        }

    def get_current_state(self) -> Dict[str, Any]:
        """
        Get current tunnel configuration for backup.

        Returns:
            Current tunnel configuration
        """
        return self._get_tunnel_config_raw()

    def _get_tunnel_config_raw(self) -> Dict[str, Any]:
        """
        Get raw tunnel configuration from Cloudflare API.

        Returns:
            Full API response with tunnel configuration

        Raises:
            requests.HTTPError: If API request fails
        """
        url = f"{self.CLOUDFLARE_API_BASE}/accounts/{self.account_id}/cfd_tunnel/{self.tunnel_id}/configurations"

        response = self.session.get(url, timeout=30)
        response.raise_for_status()

        data = response.json()

        if not data.get("success"):
            errors = data.get("errors", [])
            raise RuntimeError(f"Cloudflare API error: {errors}")

        return data["result"]

    def get_tunnel_config(self) -> Dict[str, Any]:
        """
        Get tunnel configuration (wrapper for compatibility).

        Returns:
            Tunnel configuration
        """
        return self._get_tunnel_config_raw()

    def list_hostnames(self) -> List[Dict[str, str]]:
        """
        List all hostnames in tunnel configuration.

        Returns:
            List of hostname dictionaries with 'hostname' and 'service' keys
        """
        config = self.get_tunnel_config()
        ingress = config.get("config", {}).get("ingress", [])

        # Filter out catch-all rule (last rule without hostname)
        hostnames = [
            {"hostname": rule["hostname"], "service": rule["service"]}
            for rule in ingress
            if "hostname" in rule
        ]

        logger.info(f"Found {len(hostnames)} hostname(s) in tunnel")
        return hostnames

    def validate_tunnel_config(self, config: Optional[Dict[str, Any]] = None) -> tuple[bool, List[str]]:
        """
        Validate tunnel configuration structure and integrity.

        Args:
            config: Configuration to validate (or current if None)

        Returns:
            Tuple of (is_valid, list of errors)
        """
        if config is None:
            try:
                config = self.get_tunnel_config()
            except Exception as e:
                return False, [f"Failed to get config: {e}"]

        errors = []

        # Check top-level structure
        if "config" not in config:
            errors.append("Missing 'config' key in tunnel configuration")
            return False, errors

        tunnel_config = config["config"]

        # Check for ingress rules
        if "ingress" not in tunnel_config:
            errors.append("Missing 'ingress' key in tunnel config")
            return False, errors

        ingress = tunnel_config["ingress"]

        # Verify ingress is a list
        if not isinstance(ingress, list):
            errors.append(f"'ingress' must be a list, got {type(ingress)}")
            return False, errors

        # Verify minimum rule count (at least catch-all)
        if len(ingress) < 1:
            errors.append("Ingress rules list is empty (must have at least catch-all rule)")
            return False, errors

        # Verify catch-all rule (last rule should not have hostname)
        catch_all = ingress[-1]
        if "hostname" in catch_all:
            errors.append("Last ingress rule must be catch-all (no hostname)")

        if "service" not in catch_all:
            errors.append("Catch-all rule must have 'service' field")

        # Count hostnames (exclude catch-all)
        hostname_count = len([r for r in ingress if "hostname" in r])

        # Verify minimum hostname count (protect against accidental wipes)
        if hostname_count < self.min_hostname_count:
            errors.append(
                f"Suspicious hostname count: {hostname_count} "
                f"(expected at least {self.min_hostname_count}). "
                "This may indicate configuration corruption."
            )

        # Verify each hostname rule has required fields
        for i, rule in enumerate(ingress[:-1]):  # Exclude catch-all
            if "hostname" not in rule:
                errors.append(f"Rule {i} missing 'hostname' field")
            if "service" not in rule:
                errors.append(f"Rule {i} missing 'service' field")

        # Check for duplicate hostnames
        hostnames = [r["hostname"] for r in ingress if "hostname" in r]
        duplicates = [h for h in hostnames if hostnames.count(h) > 1]
        if duplicates:
            errors.append(f"Duplicate hostnames found: {set(duplicates)}")

        is_valid = len(errors) == 0

        if is_valid:
            logger.info(f"✓ Configuration valid: {hostname_count} hostname(s)")
        else:
            logger.error(f"✗ Configuration invalid: {len(errors)} error(s)")

        return is_valid, errors

    def add_hostname(
        self,
        service_name: str,
        server_ip: str,
        port: int,
        protocol: str = "http",
        hostname: Optional[str] = None
    ) -> bool:
        """
        Add hostname to tunnel configuration with automatic backup and safety.

        Args:
            service_name: Service name (e.g., 'prowlarr')
            server_ip: Server IP address
            port: Port number
            protocol: Protocol ('http', 'https', or 'ssh')
            hostname: Explicit full hostname (overrides auto-prefix).
                      Use for root domains (e.g., 'haymoed.com') or
                      cross-domain hostnames (e.g., 'luckyjadejewelry.com').

        Returns:
            True if successful
        """
        if hostname:
            full_hostname = hostname
        else:
            full_hostname = f"{service_name}.{self.domain_fqdn}"

        service_url = f"{protocol}://{server_ip}:{port}"

        logger.info(f"Adding hostname: {full_hostname} -> {service_url}")

        return self.execute_with_safety(
            operation_name=f"add-hostname-{service_name}",
            operation_func=self._do_add_hostname,
            hostname=full_hostname,
            service_url=service_url
        )

    def remove_hostname(self, hostname: str) -> bool:
        """
        Remove hostname from tunnel configuration with automatic backup and safety.

        Args:
            hostname: Full hostname to remove (e.g., 'prowlarr.haymoed.com')

        Returns:
            True if successful
        """
        logger.info(f"Removing hostname: {hostname}")

        return self.execute_with_safety(
            operation_name=f"remove-hostname-{hostname.split('.')[0]}",
            operation_func=self._do_remove_hostname,
            hostname=hostname
        )

    def _do_remove_hostname(self, hostname: str) -> bool:
        """Internal implementation of remove_hostname."""
        current_config = self.get_tunnel_config()

        is_valid, errors = self.validate_tunnel_config(current_config)
        if not is_valid:
            raise ValueError(f"Current configuration invalid: {errors}")

        updated_config = copy.deepcopy(current_config)
        ingress = updated_config["config"]["ingress"]

        original_len = len(ingress)
        updated_config["config"]["ingress"] = [
            rule for rule in ingress
            if rule.get("hostname") != hostname
        ]

        if len(updated_config["config"]["ingress"]) == original_len:
            raise ValueError(f"Hostname not found in tunnel config: {hostname}")

        # Temporarily allow one fewer hostname for validation
        saved_min = self.min_hostname_count
        self.min_hostname_count = max(0, saved_min - 1)
        try:
            is_valid, errors = self.validate_tunnel_config(updated_config)
        finally:
            self.min_hostname_count = saved_min

        if not is_valid:
            raise ValueError(f"Updated configuration invalid: {errors}")

        self._update_tunnel_config(updated_config)
        logger.info(f"✓ Removed hostname: {hostname}")
        return True

    def _do_add_hostname(self, hostname: str, service_url: str) -> bool:
        """
        Internal implementation of add_hostname (called by execute_with_safety).

        Args:
            hostname: Full hostname (e.g., 'prowlarr.haymoed.com')
            service_url: Service URL (e.g., 'http://192.168.1.11:9696')

        Returns:
            True if successful
        """
        # Get current configuration
        current_config = self.get_tunnel_config()

        # Validate current configuration
        is_valid, errors = self.validate_tunnel_config(current_config)
        if not is_valid:
            raise ValueError(f"Current configuration invalid: {errors}")

        # Create updated configuration using MERGE (not replace!)
        updated_config = self._merge_hostname(current_config, hostname, service_url)

        # Validate updated configuration
        is_valid, errors = self.validate_tunnel_config(updated_config)
        if not is_valid:
            raise ValueError(f"Updated configuration invalid: {errors}")

        # Apply updated configuration
        self._update_tunnel_config(updated_config)

        # Create DNS record
        self._create_dns_record(hostname)

        logger.info(f"✓ Added hostname: {hostname}")
        return True

    def _merge_hostname(
        self,
        current_config: Dict[str, Any],
        hostname: str,
        service_url: str
    ) -> Dict[str, Any]:
        """
        Merge new hostname into configuration (atomic operation).

        This is the CRITICAL FIX - we MERGE the new hostname into existing config,
        not replace the entire configuration.

        Args:
            current_config: Current tunnel configuration
            hostname: Hostname to add
            service_url: Service URL

        Returns:
            Updated configuration with new hostname

        Raises:
            ValueError: If hostname already exists
        """
        # Deep copy to avoid mutations
        updated_config = copy.deepcopy(current_config)

        # Get ingress rules
        ingress = updated_config["config"]["ingress"]

        # Check for duplicate hostname
        for rule in ingress[:-1]:  # Exclude catch-all
            if rule.get("hostname") == hostname:
                raise ValueError(f"Hostname already exists: {hostname}")

        # Create new rule
        new_rule = {
            "hostname": hostname,
            "service": service_url
        }

        # Insert before catch-all (atomic list operation)
        ingress.insert(-1, new_rule)

        logger.debug(f"Merged hostname into config: {hostname}")
        return updated_config

    def _update_tunnel_config(self, config: Dict[str, Any]) -> bool:
        """
        Update tunnel configuration via API.

        Args:
            config: Full tunnel configuration to apply

        Returns:
            True if successful

        Raises:
            RuntimeError: If API request fails
        """
        url = f"{self.CLOUDFLARE_API_BASE}/accounts/{self.account_id}/cfd_tunnel/{self.tunnel_id}/configurations"

        response = self.session.put(url, json=config, timeout=30)
        response.raise_for_status()

        data = response.json()

        if not data.get("success"):
            errors = data.get("errors", [])
            raise RuntimeError(f"Failed to update tunnel config: {errors}")

        logger.info("✓ Tunnel configuration updated")
        return True

    def _create_dns_record(self, hostname: str) -> bool:
        """
        Create DNS CNAME record for hostname.

        Handles root domains (name="@"), subdomains, and cross-zone hostnames.

        Args:
            hostname: Full hostname (e.g., 'prowlarr.haymoed.com' or 'haymoed.com')

        Returns:
            True if successful (or already exists)
        """
        domain_suffix = f".{self.domain_fqdn}"

        if hostname == self.domain_fqdn:
            # Root domain — use "@" (Cloudflare auto-flattens proxied CNAMEs at apex)
            dns_name = "@"
        elif hostname.endswith(domain_suffix):
            # Subdomain of configured domain — extract subdomain part
            dns_name = hostname[:-len(domain_suffix)]
        else:
            # Cross-zone hostname — can't create DNS in this zone
            logger.warning(
                f"Hostname {hostname} is not in {self.domain_fqdn} zone — "
                "skipping DNS record creation. Use 'dns-add' with the correct --domain."
            )
            return True

        dns_payload = {
            "type": "CNAME",
            "name": dns_name,
            "content": f"{self.tunnel_id}.cfargotunnel.com",
            "proxied": True
        }

        url = f"{self.CLOUDFLARE_API_BASE}/zones/{self.zone_id}/dns_records"

        try:
            response = self.session.post(url, json=dns_payload, timeout=30)

            if response.status_code == 400:
                data = response.json()
                errors = data.get("errors", [])
                if any(e.get("code") == 81053 for e in errors):
                    logger.info(f"DNS record already exists: {hostname}")
                    return True

            response.raise_for_status()

            logger.info(f"✓ Created DNS record: {hostname} (name={dns_name})")
            return True

        except Exception as e:
            logger.warning(f"DNS record creation failed (non-fatal): {e}")
            return True

    # =========================================================================
    # DNS CRUD
    # =========================================================================

    def list_dns_records(self, record_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List DNS records for the current domain's zone."""
        url = f"{self.CLOUDFLARE_API_BASE}/zones/{self.zone_id}/dns_records"
        params = {"per_page": 100}
        if record_type:
            params["type"] = record_type

        response = self.session.get(url, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        if not data.get("success"):
            raise RuntimeError(f"API error: {data.get('errors', [])}")
        return data["result"]

    def add_dns_record(
        self, record_type: str, name: str, content: str,
        proxied: bool = True, ttl: int = 1
    ) -> Dict[str, Any]:
        """Add a DNS record to the current domain's zone."""
        url = f"{self.CLOUDFLARE_API_BASE}/zones/{self.zone_id}/dns_records"
        payload = {
            "type": record_type, "name": name,
            "content": content, "proxied": proxied, "ttl": ttl
        }

        response = self.session.post(url, json=payload, timeout=30)

        if response.status_code == 400:
            data = response.json()
            if any(e.get("code") == 81053 for e in data.get("errors", [])):
                logger.info(f"DNS record already exists: {name}")
                return {"already_exists": True}

        response.raise_for_status()
        data = response.json()
        if not data.get("success"):
            raise RuntimeError(f"API error: {data.get('errors', [])}")
        logger.info(f"✓ Created DNS record: {record_type} {name} → {content}")
        return data["result"]

    def remove_dns_record(self, record_id: str) -> bool:
        """Delete a DNS record by ID."""
        url = f"{self.CLOUDFLARE_API_BASE}/zones/{self.zone_id}/dns_records/{record_id}"
        response = self.session.delete(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        if not data.get("success"):
            raise RuntimeError(f"API error: {data.get('errors', [])}")
        logger.info(f"✓ Deleted DNS record: {record_id}")
        return True

    # =========================================================================
    # Cloudflare Access
    # =========================================================================

    def list_access_apps(self) -> List[Dict[str, Any]]:
        """List Cloudflare Access applications."""
        url = f"{self.CLOUDFLARE_API_BASE}/accounts/{self.account_id}/access/apps"
        response = self.session.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        if not data.get("success"):
            raise RuntimeError(f"API error: {data.get('errors', [])}")
        return data["result"]

    def create_access_app(
        self, name: str, domain: str,
        app_type: str = "self_hosted", session_duration: str = "24h"
    ) -> Dict[str, Any]:
        """Create a Cloudflare Access application."""
        url = f"{self.CLOUDFLARE_API_BASE}/accounts/{self.account_id}/access/apps"
        payload = {
            "name": name, "domain": domain,
            "type": app_type, "session_duration": session_duration,
        }
        response = self.session.post(url, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        if not data.get("success"):
            raise RuntimeError(f"API error: {data.get('errors', [])}")
        logger.info(f"✓ Created Access app: {name} ({domain})")
        return data["result"]

    def add_access_policy(
        self, app_id: str, name: str,
        decision: str = "allow", emails: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Add a policy to a Cloudflare Access application."""
        url = f"{self.CLOUDFLARE_API_BASE}/accounts/{self.account_id}/access/apps/{app_id}/policies"
        payload = {
            "name": name, "decision": decision,
            "include": [{"email": {"email": e}} for e in (emails or [])],
        }
        response = self.session.post(url, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        if not data.get("success"):
            raise RuntimeError(f"API error: {data.get('errors', [])}")
        logger.info(f"✓ Added policy: {name} to app {app_id}")
        return data["result"]

    def rollback_from_backup(self, backup_path: Path) -> bool:
        """
        Restore tunnel configuration from backup.

        Args:
            backup_path: Path to backup file

        Returns:
            True if successful

        Raises:
            Exception: If restore fails
        """
        logger.info(f"Rolling back from backup: {backup_path}")

        # Load backup
        backup_data = self.backup_manager.load_backup(backup_path)
        config = backup_data["data"]

        # Validate backup configuration
        is_valid, errors = self.validate_tunnel_config(config)
        if not is_valid:
            raise ValueError(f"Backup configuration invalid: {errors}")

        # Apply backup configuration
        self._update_tunnel_config(config)

        logger.info("✓ Rollback successful")
        return True

    def verify_operation(self, operation_name: str, result: Any) -> bool:
        """
        Verify operation completed successfully.

        Args:
            operation_name: Name of operation
            result: Result from operation

        Returns:
            True if verification passed
        """
        # Get current config and validate
        try:
            current_config = self.get_tunnel_config()
            is_valid, errors = self.validate_tunnel_config(current_config)

            if not is_valid:
                logger.error(f"Post-operation validation failed: {errors}")
                return False

            logger.info(f"✓ Post-operation validation passed")
            return True

        except Exception as e:
            logger.error(f"Post-operation verification error: {e}")
            return False

    @classmethod
    def get_available_domains(cls) -> List[str]:
        """Get domain names from config file (for CLI choices)."""
        try:
            config = cls._load_config_static()
            cf = config.get("cloudflare", {})
            return [k for k in cf if k not in ("api_token", "account_id")]
        except Exception:
            return ["haymoed", "ramcyber", "cipherhq"]

    @staticmethod
    def _load_config_static() -> Dict[str, Any]:
        """Static config loader for class methods (no self needed)."""
        config_paths = [
            Path("/app/config.yaml"),
            Path("/mnt/tank/faststorage/general/repo/ai-config/config.yaml"),
            Path.home() / ".config" / "infrastructure-toolkit" / "config.yaml",
        ]
        for p in config_paths:
            if p.exists():
                with open(p, 'r') as f:
                    return yaml.safe_load(f)
        return {}

    @classmethod
    def configure_parser(cls, parser):
        """Configure argument parser for Cloudflare tool."""
        super().configure_parser(parser)

        domains = cls.get_available_domains()
        parser.add_argument(
            "--domain",
            choices=domains,
            default="haymoed",
            help=f"Domain to manage (default: haymoed). Available: {', '.join(domains)}"
        )

        subparsers = parser.add_subparsers(dest="subcommand", help="Cloudflare subcommands")

        # --- Tunnel hostname management ---
        subparsers.add_parser("list", help="List current tunnel hostnames")

        add_parser = subparsers.add_parser("add", help="Add hostname to tunnel")
        add_parser.add_argument("service", help="Service name (e.g., 'prowlarr')")
        add_parser.add_argument("ip", help="Server IP address")
        add_parser.add_argument("port", type=int, help="Port number")
        add_parser.add_argument(
            "--protocol", choices=["http", "https", "ssh"], default="http",
            help="Protocol (default: http)"
        )
        add_parser.add_argument(
            "--hostname",
            help="Exact hostname (overrides auto-prefix). Use for root domains "
                 "or cross-domain hostnames (e.g., 'luckyjadejewelry.com')"
        )

        remove_parser = subparsers.add_parser("remove", help="Remove hostname from tunnel")
        remove_parser.add_argument("hostname", help="Full hostname to remove")

        # --- Tunnel validation/health ---
        subparsers.add_parser("validate", help="Validate tunnel configuration")
        subparsers.add_parser("health-check", help="Check API connectivity")

        # --- Backups ---
        subparsers.add_parser("backups", help="List available backups")
        restore_parser = subparsers.add_parser("restore", help="Restore from backup")
        restore_parser.add_argument("backup_file", help="Path to backup file")

        # --- DNS management ---
        dns_list = subparsers.add_parser("dns-list", help="List DNS records")
        dns_list.add_argument("--type", dest="record_type", help="Filter by type (A, CNAME, etc.)")

        dns_add = subparsers.add_parser("dns-add", help="Add DNS record")
        dns_add.add_argument("record_type", help="Record type (CNAME, A, TXT, etc.)")
        dns_add.add_argument("name", help="Record name (subdomain or '@' for root)")
        dns_add.add_argument("content", help="Record content (IP or target)")
        dns_add.add_argument("--no-proxy", action="store_true", help="Disable Cloudflare proxy")

        dns_rm = subparsers.add_parser("dns-remove", help="Remove DNS record")
        dns_rm.add_argument("record_id", help="DNS record ID (get from dns-list)")

        # --- Cloudflare Access ---
        subparsers.add_parser("access-list", help="List Access applications")

        access_app = subparsers.add_parser("access-create-app", help="Create Access application")
        access_app.add_argument("name", help="Application name")
        access_app.add_argument("app_domain", help="Application domain")
        access_app.add_argument("--session-duration", default="24h", help="Session duration")

        access_pol = subparsers.add_parser("access-add-policy", help="Add policy to Access app")
        access_pol.add_argument("app_id", help="Access application ID")
        access_pol.add_argument("policy_name", help="Policy name")
        access_pol.add_argument("--decision", default="allow", choices=["allow", "deny", "bypass"])
        access_pol.add_argument("--emails", nargs="+", required=True, help="Email addresses")
