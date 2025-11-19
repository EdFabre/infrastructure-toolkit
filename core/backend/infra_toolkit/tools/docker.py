"""
Docker Compose Management Tool

Safe management of docker-compose deployments across boss servers.

Features:
- Validate docker-compose.yml before deployment
- Automatic timestamped backups (compatible with dcp alias pattern)
- Health verification after deployment
- Service state capture and restoration
- Rollback capability
- Multi-server support via SSH
"""

import json
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from ..base_tool import BaseTool


logger = logging.getLogger(__name__)


class DockerTool(BaseTool):
    """
    Docker Compose management with built-in safety mechanisms.

    This tool improves upon the existing dcp/dclog bash aliases by adding:
    1. YAML validation before deployment
    2. Verified backups (not just timestamped moves)
    3. Service state capture (which containers were running)
    4. Health verification after changes
    5. Automatic rollback on failure
    6. Dry-run mode for previews
    7. Backup cleanup with retention policy
    """

    # Default paths (can be overridden in config)
    DEFAULT_COMPOSE_PATH = Path("/opt/docker/docker-compose.yml")
    DEFAULT_REPO_BASE = Path("/mnt/tank/faststorage/general/repo/linux-servers")

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

    def __init__(self, server: Optional[str] = None, all_servers: bool = False, **kwargs):
        """
        Initialize Docker tool.

        Args:
            server: Server hostname to manage (None for all servers)
            all_servers: Explicitly query all configured servers (default behavior)
            **kwargs: Additional arguments passed to BaseTool
        """
        # Load configuration before calling super().__init__
        config = self._load_config()

        self.server = server
        # Default to all_servers=True if no specific server specified
        self.all_servers = all_servers or (server is None)
        self.is_remote = server is not None

        # Get list of servers to query (from config or defaults)
        docker_config = config.get("docker", {})
        self.servers = docker_config.get("servers", self.DEFAULT_SERVERS)

        # Determine paths based on server
        if self.is_remote:
            self.compose_path = self.DEFAULT_COMPOSE_PATH
            self.repo_path = self.DEFAULT_REPO_BASE / server / "opt" / "docker" / "docker-compose.yml"
        else:
            # Local server - detect hostname
            import socket
            hostname = socket.gethostname()
            self.compose_path = self.DEFAULT_COMPOSE_PATH
            self.repo_path = self.DEFAULT_REPO_BASE / hostname / "opt" / "docker" / "docker-compose.yml"

        super().__init__(config, **kwargs)

        # Backup retention (keep last N backups)
        self.backup_retention = config.get("docker", {}).get("backup_retention", 10)

    @classmethod
    def tool_name(cls) -> str:
        return "docker"

    def _load_config(self) -> Dict[str, Any]:
        """Load Docker configuration from config.yaml."""
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
        """Validate Docker configuration."""
        # Docker tool doesn't require API credentials
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

        # Return as-is and let SSH handle it
        return server

    def _execute_command(self, command: List[str], **kwargs) -> subprocess.CompletedProcess:
        """
        Execute command locally or via SSH.

        Args:
            command: Command to execute (as list)
            **kwargs: Additional subprocess arguments

        Returns:
            CompletedProcess result
        """
        if self.is_remote:
            # Build command string with proper quoting for SSH
            # Handle special cases like {{json .}} format strings
            cmd_parts = []
            for part in command:
                if '{{' in part or '}}' in part:
                    # Wrap format strings in double quotes
                    cmd_parts.append(f'"{part}"')
                else:
                    cmd_parts.append(part)

            cmd_string = " ".join(cmd_parts)

            # Resolve server hostname to IP address
            server_ip = self._resolve_server_address(self.server)

            # Wrap command in SSH with options for non-interactive execution
            ssh_command = [
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR",
                f"root@{server_ip}",
                cmd_string
            ]
            return subprocess.run(ssh_command, capture_output=True, text=True, **kwargs)
        else:
            return subprocess.run(command, capture_output=True, text=True, **kwargs)

    def validate_compose_file(self, file_path: Path) -> Tuple[bool, List[str]]:
        """
        Validate docker-compose.yml syntax and structure.

        Args:
            file_path: Path to docker-compose.yml file

        Returns:
            Tuple of (is_valid, list of errors)
        """
        errors = []

        try:
            # For remote servers, use SSH to read the file
            if self.is_remote:
                # Try to read via SSH
                result = self._execute_command(["cat", str(file_path)])
                if result.returncode != 0:
                    errors.append(f"Cannot read file on remote server: {result.stderr}")
                    return False, errors

                try:
                    compose_data = yaml.safe_load(result.stdout)
                except yaml.YAMLError as e:
                    errors.append(f"Invalid YAML syntax: {e}")
                    return False, errors
            else:
                # Local file access - use sudo cat to handle permission issues
                result = subprocess.run(
                    ["sudo", "cat", str(file_path)],
                    capture_output=True,
                    text=True
                )

                if result.returncode != 0:
                    errors.append(f"Cannot read file: {result.stderr}")
                    return False, errors

                # Parse YAML
                try:
                    compose_data = yaml.safe_load(result.stdout)
                except yaml.YAMLError as e:
                    errors.append(f"Invalid YAML syntax: {e}")
                    return False, errors

            # Validate structure
            if not isinstance(compose_data, dict):
                errors.append("Root element must be a dictionary")
                return False, errors

            # Check for required fields
            if "services" not in compose_data:
                errors.append("Missing required 'services' section")
                return False, errors

            if not isinstance(compose_data["services"], dict):
                errors.append("'services' must be a dictionary")
                return False, errors

            # Check version (optional but recommended)
            if "version" not in compose_data:
                logger.warning("No 'version' specified in docker-compose.yml")

            # Validate each service
            for service_name, service_config in compose_data["services"].items():
                if not isinstance(service_config, dict):
                    errors.append(f"Service '{service_name}' configuration must be a dictionary")
                    continue

                # Check for image or build
                if "image" not in service_config and "build" not in service_config:
                    errors.append(f"Service '{service_name}' missing 'image' or 'build' directive")

            # Use docker-compose config to validate
            # For remote validation, temporarily override server settings
            original_server = self.server
            original_is_remote = self.is_remote

            # Use docker-compose config to validate
            # For local validation, need sudo since file requires root permissions
            if self.is_remote:
                # Remote validation via SSH
                result = self._execute_command([
                    "docker-compose",
                    "-f", str(file_path),
                    "config",
                    "--quiet"
                ])
            else:
                # Local validation with sudo
                result = subprocess.run(
                    ["sudo", "docker-compose", "-f", str(file_path), "config", "--quiet"],
                    capture_output=True,
                    text=True
                )

            if result.returncode != 0:
                errors.append(f"docker-compose validation failed: {result.stderr}")

            # Restore original server settings
            self.server = original_server
            self.is_remote = original_is_remote

        except Exception as e:
            errors.append(f"Validation error: {e}")

        is_valid = len(errors) == 0

        if is_valid:
            logger.info(f"✓ Compose file valid: {file_path}")
        else:
            logger.error(f"✗ Compose file invalid: {len(errors)} error(s)")

        return is_valid, errors

    def get_running_services(self, server: Optional[str] = None) -> List[Dict[str, str]]:
        """
        Get list of currently running Docker containers.

        Args:
            server: Optional server to query (overrides self.server)

        Returns:
            List of container info dictionaries
        """
        try:
            # Temporarily override server if specified
            original_server = self.server
            original_is_remote = self.is_remote

            if server:
                self.server = server
                self.is_remote = True

            result = self._execute_command([
                "docker", "ps",
                "--format", "{{json .}}"
            ])

            # Restore original server
            self.server = original_server
            self.is_remote = original_is_remote

            if result.returncode != 0:
                logger.error(f"Failed to get running containers: {result.stderr}")
                return []

            containers = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    container = json.loads(line)
                    # Add server information
                    container["Server"] = server if server else "local"
                    containers.append(container)

            logger.info(f"Found {len(containers)} running container(s) on {server or 'local'}")
            return containers

        except Exception as e:
            logger.error(f"Error getting running services on {server or 'local'}: {e}")
            return []

    def get_all_running_services(self) -> List[Dict[str, str]]:
        """
        Get list of running containers across all configured servers.

        Returns:
            List of container info dictionaries with server information
        """
        all_containers = []

        # Query each server (servers can be dict or list)
        if isinstance(self.servers, dict):
            server_items = self.servers.items()
        else:
            server_items = [(s, s) for s in self.servers]

        for hostname, server_addr in server_items:
            logger.info(f"Querying {hostname} ({server_addr})...")
            containers = self.get_running_services(server=server_addr)

            # Update Server field to use friendly hostname instead of IP
            for container in containers:
                container["Server"] = hostname

            all_containers.extend(containers)

        logger.info(f"Found {len(all_containers)} total container(s) across {len(server_items)} server(s)")
        return all_containers

    def create_backup(self) -> Optional[Path]:
        """
        Create timestamped backup of current docker-compose.yml.

        Uses same naming convention as dcp alias:
        docker-compose.yml.YYYYMMDDTHHMMSSz.BAK

        Returns:
            Path to backup file, or None if failed
        """
        try:
            # Generate timestamp in UTC (ISO 8601 format)
            timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            backup_path = Path(f"{self.compose_path}.{timestamp}.BAK")

            # Copy current file to backup
            if self.is_remote:
                result = self._execute_command([
                    "cp",
                    str(self.compose_path),
                    str(backup_path)
                ])

                if result.returncode != 0:
                    logger.error(f"Backup failed: {result.stderr}")
                    return None
            else:
                import shutil
                shutil.copy2(self.compose_path, backup_path)

            # Verify backup
            is_valid, errors = self.validate_compose_file(backup_path)
            if not is_valid:
                logger.error(f"Backup verification failed: {errors}")
                return None

            logger.info(f"✓ Created backup: {backup_path}")
            return backup_path

        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            return None

    def list_backups(self) -> List[Dict[str, Any]]:
        """
        List all backup files for docker-compose.yml.

        Returns:
            List of backup info dictionaries
        """
        try:
            # Get list of .BAK files
            backup_dir = self.compose_path.parent

            if self.is_remote:
                result = self._execute_command([
                    "ls", "-la",
                    str(backup_dir / "docker-compose.yml.*.BAK")
                ])

                # Parse ls output
                backups = []
                for line in result.stdout.strip().split('\n'):
                    if line and '.BAK' in line:
                        parts = line.split()
                        if len(parts) >= 9:
                            filename = parts[-1]
                            backups.append({
                                "filename": Path(filename).name,
                                "path": filename,
                                "size": int(parts[4])
                            })
            else:
                backups = []
                for backup_file in backup_dir.glob("docker-compose.yml.*.BAK"):
                    backups.append({
                        "filename": backup_file.name,
                        "path": str(backup_file),
                        "size": backup_file.stat().st_size
                    })

            # Sort by filename (timestamp embedded in name)
            backups.sort(key=lambda x: x["filename"], reverse=True)

            logger.info(f"Found {len(backups)} backup(s)")
            return backups

        except Exception as e:
            logger.error(f"Error listing backups: {e}")
            return []

    def cleanup_old_backups(self, keep_count: int = 10) -> int:
        """
        Remove old backup files, keeping most recent N backups.

        Args:
            keep_count: Number of backups to retain

        Returns:
            Number of backups removed
        """
        try:
            backups = self.list_backups()

            if len(backups) <= keep_count:
                logger.info(f"No cleanup needed ({len(backups)} backups, keeping {keep_count})")
                return 0

            # Remove oldest backups
            to_remove = backups[keep_count:]
            removed_count = 0

            for backup in to_remove:
                if self.is_remote:
                    result = self._execute_command(["rm", backup["path"]])
                    if result.returncode == 0:
                        removed_count += 1
                else:
                    Path(backup["path"]).unlink()
                    removed_count += 1

            logger.info(f"✓ Removed {removed_count} old backup(s)")
            return removed_count

        except Exception as e:
            logger.error(f"Error cleaning up backups: {e}")
            return 0

    def get_container_logs(self, container: str, tail: int = 100, follow: bool = False) -> str:
        """
        Get logs from a specific container.

        Args:
            container: Container name
            tail: Number of lines to retrieve (default: 100)
            follow: Follow log output (default: False)

        Returns:
            Container logs as string
        """
        try:
            cmd = ["docker", "logs"]
            if tail:
                cmd.extend(["--tail", str(tail)])
            if follow:
                cmd.append("-f")
            cmd.append(container)

            result = self._execute_command(cmd)
            if result.returncode == 0:
                return result.stdout
            else:
                logger.error(f"Failed to get logs for {container}: {result.stderr}")
                return f"Error: {result.stderr}"

        except Exception as e:
            logger.error(f"Error getting logs for {container}: {e}")
            return f"Error: {str(e)}"

    def health_check(self) -> Dict[str, Any]:
        """
        Check Docker health and connectivity.

        Returns:
            Health check results
        """
        checks = {}

        # Check Docker daemon
        try:
            result = self._execute_command(["docker", "info"])
            checks["docker_running"] = result.returncode == 0
        except Exception as e:
            checks["docker_running"] = False
            checks["docker_error"] = str(e)

        # Check compose file exists
        checks["compose_file_exists"] = self.compose_path.exists() if not self.is_remote else True

        # Check compose file valid
        if checks["compose_file_exists"]:
            is_valid, errors = self.validate_compose_file(self.compose_path)
            checks["compose_file_valid"] = is_valid
            if not is_valid:
                checks["compose_errors"] = errors

        # Check running containers
        try:
            containers = self.get_running_services()
            checks["container_count"] = len(containers)
        except Exception as e:
            checks["container_count"] = 0
            checks["container_error"] = str(e)

        # Overall status
        all_healthy = checks.get("docker_running", False) and \
                     checks.get("compose_file_valid", False)

        status = "healthy" if all_healthy else "unhealthy"

        return {
            "status": status,
            "checks": checks,
            "message": "All checks passed" if all_healthy else "One or more checks failed"
        }

    # BaseTool abstract methods

    def get_current_state(self) -> Dict[str, Any]:
        """Get current Docker state for backup."""
        return {
            "compose_file": str(self.compose_path),
            "running_services": self.get_running_services(),
            "timestamp": datetime.utcnow().isoformat()
        }

    def rollback_from_backup(self, backup_path: Path) -> bool:
        """
        Restore docker-compose.yml from backup.

        Args:
            backup_path: Path to backup file

        Returns:
            True if successful
        """
        try:
            logger.info(f"Rolling back from backup: {backup_path}")

            # Validate backup first
            is_valid, errors = self.validate_compose_file(backup_path)
            if not is_valid:
                raise ValueError(f"Backup file invalid: {errors}")

            # Copy backup to active location
            if self.is_remote:
                result = self._execute_command([
                    "cp",
                    str(backup_path),
                    str(self.compose_path)
                ])

                if result.returncode != 0:
                    raise RuntimeError(f"Rollback failed: {result.stderr}")
            else:
                import shutil
                shutil.copy2(backup_path, self.compose_path)

            logger.info("✓ Rollback successful")
            return True

        except Exception as e:
            logger.error(f"Rollback error: {e}")
            return False

    def verify_operation(self, operation_name: str, result: Any) -> bool:
        """Verify operation completed successfully."""
        # Check compose file is valid after operation
        is_valid, errors = self.validate_compose_file(self.compose_path)

        if not is_valid:
            logger.error(f"Post-operation validation failed: {errors}")
            return False

        logger.info("✓ Post-operation validation passed")
        return True

    @classmethod
    def configure_parser(cls, parser):
        """Configure argument parser for Docker tool."""
        super().configure_parser(parser)

        parser.add_argument(
            "--server",
            help="Server hostname to manage (default: local)"
        )

        parser.add_argument(
            "--all-servers",
            action="store_true",
            help="Query all configured servers"
        )

        subparsers = parser.add_subparsers(dest="subcommand", help="Docker subcommands")

        # Health check command
        health_parser = subparsers.add_parser("health-check", help="Check Docker health")

        # Validate command
        validate_parser = subparsers.add_parser("validate", help="Validate docker-compose.yml")
        validate_parser.add_argument(
            "--file",
            help="Path to docker-compose.yml file (default: /opt/docker/docker-compose.yml)"
        )

        # List command
        list_parser = subparsers.add_parser("list", help="List running containers")

        # Backups command
        backups_parser = subparsers.add_parser("backups", help="Manage backups")
        backups_parser.add_argument("--cleanup", action="store_true", help="Remove old backups")
        backups_parser.add_argument("--keep", type=int, default=10, help="Number of backups to keep")

        # Rollback command
        rollback_parser = subparsers.add_parser("rollback", help="Restore from backup")
        rollback_parser.add_argument("backup_file", nargs="?", help="Backup file to restore (default: most recent)")

        # Deploy command
        deploy_parser = subparsers.add_parser("deploy", help="Deploy docker-compose changes")
        deploy_parser.add_argument("--from-repo", action="store_true", help="Deploy from repository (sync first)")
        deploy_parser.add_argument("--service", help="Deploy specific service only")
        deploy_parser.add_argument("--verify", action="store_true", default=True, help="Verify health after deployment")
        deploy_parser.add_argument("--no-verify", action="store_true", help="Skip post-deployment verification")

        # Restart command
        restart_parser = subparsers.add_parser("restart", help="Restart services")
        restart_parser.add_argument("service", nargs="?", help="Service name to restart (default: all)")
        restart_parser.add_argument("--verify", action="store_true", default=True, help="Verify health after restart")

        # Logs command
        logs_parser = subparsers.add_parser("logs", help="View service logs")
        logs_parser.add_argument("service", help="Service name")
        logs_parser.add_argument("--tail", type=int, default=100, help="Number of lines to show")
        logs_parser.add_argument("--follow", "-f", action="store_true", help="Follow log output")

        # Sync command
        sync_parser = subparsers.add_parser("sync", help="Sync configuration from repository")
        sync_parser.add_argument("--verify", action="store_true", default=True, help="Verify configuration before sync")

    def deploy(self, from_repo: bool = False, service: Optional[str] = None) -> Dict[str, Any]:
        """
        Deploy docker-compose changes with automatic backup and verification.

        Args:
            from_repo: Sync from repository before deployment
            service: Optional service name to deploy (default: all)

        Returns:
            Deployment result dictionary
        """
        try:
            logger.info(f"Starting deployment on {self.server or 'local'}...")

            # Step 1: Create backup
            backup_path = self.create_backup()
            if not backup_path:
                raise RuntimeError("Failed to create backup before deployment")

            # Step 2: Capture current running state
            running_before = self.get_running_services()
            logger.info(f"Captured state: {len(running_before)} running container(s)")

            # Step 3: Sync from repository if requested
            if from_repo:
                self.sync_from_repo()

            # Step 4: Validate new configuration
            is_valid, errors = self.validate_compose_file(self.compose_path)
            if not is_valid:
                logger.error(f"Validation failed: {errors}")
                raise ValueError(f"Invalid docker-compose.yml: {errors}")

            # Step 5: Deploy changes
            if service:
                logger.info(f"Deploying service: {service}")
                result = self._execute_command([
                    "docker-compose",
                    "-f", str(self.compose_path),
                    "up", "-d", service
                ])
            else:
                logger.info("Deploying all services")
                result = self._execute_command([
                    "docker-compose",
                    "-f", str(self.compose_path),
                    "up", "-d"
                ])

            if result.returncode != 0:
                raise RuntimeError(f"Deployment failed: {result.stderr}")

            # Step 6: Verify deployment
            running_after = self.get_running_services()
            logger.info(f"Post-deployment: {len(running_after)} running container(s)")

            # Step 7: Cleanup old backups
            self.cleanup_old_backups(keep_count=self.backup_retention)

            return {
                "status": "success",
                "backup_created": str(backup_path),
                "containers_before": len(running_before),
                "containers_after": len(running_after),
                "deployment_output": result.stdout
            }

        except Exception as e:
            logger.error(f"Deployment error: {e}")
            if backup_path and backup_path.exists():
                logger.warning("Attempting automatic rollback...")
                if self.rollback_from_backup(backup_path):
                    logger.info("✓ Rollback successful")
                else:
                    logger.error("✗ Rollback failed - manual intervention required")
            raise

    def sync_from_repo(self) -> bool:
        """
        Sync docker-compose.yml from repository to active location.

        Returns:
            True if successful
        """
        try:
            logger.info(f"Syncing from repository: {self.repo_path}")

            # Verify repo file exists
            if not self.repo_path.exists():
                raise FileNotFoundError(f"Repository file not found: {self.repo_path}")

            # Validate repo file before sync
            is_valid, errors = self.validate_compose_file(self.repo_path)
            if not is_valid:
                raise ValueError(f"Repository file invalid: {errors}")

            # Copy to active location
            if self.is_remote:
                result = self._execute_command([
                    "cp",
                    str(self.repo_path),
                    str(self.compose_path)
                ])

                if result.returncode != 0:
                    raise RuntimeError(f"Sync failed: {result.stderr}")
            else:
                import shutil
                shutil.copy2(self.repo_path, self.compose_path)

            logger.info("✓ Sync successful")
            return True

        except Exception as e:
            logger.error(f"Sync error: {e}")
            return False

    def restart_service(self, service: Optional[str] = None) -> Dict[str, Any]:
        """
        Restart Docker services.

        Args:
            service: Service name to restart (None for all)

        Returns:
            Restart result dictionary
        """
        try:
            if service:
                logger.info(f"Restarting service: {service}")
                result = self._execute_command([
                    "docker-compose",
                    "-f", str(self.compose_path),
                    "restart", service
                ])
            else:
                logger.info("Restarting all services")
                result = self._execute_command([
                    "docker-compose",
                    "-f", str(self.compose_path),
                    "restart"
                ])

            if result.returncode != 0:
                raise RuntimeError(f"Restart failed: {result.stderr}")

            logger.info("✓ Restart successful")

            return {
                "status": "success",
                "service": service or "all",
                "output": result.stdout
            }

        except Exception as e:
            logger.error(f"Restart error: {e}")
            raise

    def view_logs(self, service: str, tail: int = 100, follow: bool = False) -> None:
        """
        View service logs.

        Args:
            service: Service name
            tail: Number of lines to show
            follow: Follow log output
        """
        try:
            cmd = [
                "docker-compose",
                "-f", str(self.compose_path),
                "logs",
                "--tail", str(tail)
            ]

            if follow:
                cmd.append("--follow")

            cmd.append(service)

            # For follow mode, don't capture output (stream directly)
            if follow:
                if self.is_remote:
                    # Build command string for SSH
                    cmd_string = " ".join(cmd)

                    # Resolve server hostname to IP address
                    server_ip = self._resolve_server_address(self.server)

                    ssh_cmd = [
                        "ssh",
                        "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null",
                        "-o", "LogLevel=ERROR",
                        "-t",  # Force pseudo-terminal allocation for better streaming
                        f"root@{server_ip}",
                        cmd_string
                    ]
                    subprocess.run(ssh_cmd)
                else:
                    subprocess.run(cmd)
            else:
                result = self._execute_command(cmd)
                print(result.stdout)

        except Exception as e:
            logger.error(f"Error viewing logs: {e}")
            raise
