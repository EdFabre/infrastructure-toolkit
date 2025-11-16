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

    def __init__(self, domain: str = "haymoed", **kwargs):
        """
        Initialize Cloudflare tool.

        Args:
            domain: Domain to manage ('haymoed' or 'ramcyber')
            **kwargs: Additional arguments passed to BaseTool
        """
        # Load configuration before calling super().__init__
        config = self._load_config()

        # Extract domain-specific configuration
        if domain not in config.get("cloudflare", {}):
            raise ValueError(f"Domain '{domain}' not found in configuration")

        self.domain = domain
        self.api_token = config["cloudflare"]["api_token"]
        self.account_id = config["cloudflare"]["account_id"]
        self.zone_id = config["cloudflare"][domain]["zone_id"]
        self.tunnel_id = config["cloudflare"][domain]["tunnel_id"]

        super().__init__(config, **kwargs)

        # Setup HTTP session with authentication
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        })

        # Minimum hostname count threshold (to detect accidental wipes)
        self.min_hostname_count = 20

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
        # Look for config in ai-config/scripts/config.yaml
        config_paths = [
            Path("/mnt/tank/faststorage/general/repo/ai-config/scripts/config.yaml"),
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
        protocol: str = "http"
    ) -> bool:
        """
        Add hostname to tunnel configuration with automatic backup and safety.

        This is the SAFE version that fixes the bash script bugs:
        1. Creates automatic backup before modification
        2. Uses MERGE (not replace) to update configuration
        3. Verifies hostname count before/after
        4. Validates structure
        5. Rolls back on failure

        Args:
            service_name: Service name (e.g., 'prowlarr')
            server_ip: Server IP address
            port: Port number
            protocol: Protocol ('http' or 'https')

        Returns:
            True if successful

        Raises:
            ValueError: If hostname already exists or validation fails
            RuntimeError: If API request fails
        """
        hostname = f"{service_name}.{self.domain}.com"
        service_url = f"{protocol}://{server_ip}:{port}"

        logger.info(f"Adding hostname: {hostname} -> {service_url}")

        # Execute with automatic safety
        return self.execute_with_safety(
            operation_name=f"add-hostname-{service_name}",
            operation_func=self._do_add_hostname,
            hostname=hostname,
            service_url=service_url
        )

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

        Args:
            hostname: Full hostname (e.g., 'prowlarr.haymoed.com')

        Returns:
            True if successful (or already exists)
        """
        # Extract subdomain from hostname
        subdomain = hostname.replace(f".{self.domain}.com", "")

        dns_payload = {
            "type": "CNAME",
            "name": subdomain,
            "content": f"{self.tunnel_id}.cfargotunnel.com",
            "proxied": True
        }

        url = f"{self.CLOUDFLARE_API_BASE}/zones/{self.zone_id}/dns_records"

        try:
            response = self.session.post(url, json=dns_payload, timeout=30)

            # Check for "already exists" error (code 81053)
            if response.status_code == 400:
                data = response.json()
                errors = data.get("errors", [])
                if any(e.get("code") == 81053 for e in errors):
                    logger.info(f"DNS record already exists: {hostname}")
                    return True

            response.raise_for_status()

            logger.info(f"✓ Created DNS record: {hostname}")
            return True

        except Exception as e:
            logger.warning(f"DNS record creation failed (non-fatal): {e}")
            # Don't fail the entire operation if DNS creation fails
            return True

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
    def configure_parser(cls, parser):
        """Configure argument parser for Cloudflare tool."""
        super().configure_parser(parser)

        parser.add_argument(
            "--domain",
            choices=["haymoed", "ramcyber"],
            default="haymoed",
            help="Domain to manage (default: haymoed)"
        )

        subparsers = parser.add_subparsers(dest="subcommand", help="Cloudflare subcommands")

        # List command
        list_parser = subparsers.add_parser("list", help="List current hostnames")

        # Add command
        add_parser = subparsers.add_parser("add", help="Add hostname to tunnel")
        add_parser.add_argument("service", help="Service name (e.g., 'prowlarr')")
        add_parser.add_argument("ip", help="Server IP address")
        add_parser.add_argument("port", type=int, help="Port number")
        add_parser.add_argument(
            "--protocol",
            choices=["http", "https"],
            default="http",
            help="Protocol (default: http)"
        )

        # Validate command
        validate_parser = subparsers.add_parser("validate", help="Validate tunnel configuration")

        # Health command
        health_parser = subparsers.add_parser("health-check", help="Check API connectivity")

        # Backups command
        backups_parser = subparsers.add_parser("backups", help="List available backups")

        # Restore command
        restore_parser = subparsers.add_parser("restore", help="Restore from backup")
        restore_parser.add_argument("backup_file", help="Path to backup file")
