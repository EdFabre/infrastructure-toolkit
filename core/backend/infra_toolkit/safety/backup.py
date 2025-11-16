"""
Backup Manager

Handles automatic backup creation and management for all tools.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


class BackupManager:
    """
    Manages automatic backups for infrastructure tools.

    Features:
    - Automatic backup before operations
    - Timestamped backup files
    - Backup listing and cleanup
    - JSON serialization
    """

    def __init__(self, tool_name: str, backup_dir: Path):
        """
        Initialize backup manager.

        Args:
            tool_name: Name of tool (e.g., 'cloudflare')
            backup_dir: Directory to store backups
        """
        self.tool_name = tool_name
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        logger.debug(f"BackupManager initialized: {self.backup_dir}")

    def create_backup(
        self,
        name: str,
        data: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> Path:
        """
        Create a backup file.

        Args:
            name: Backup name (will be timestamped)
            data: Data to backup (must be JSON-serializable)
            metadata: Optional metadata to include in backup

        Returns:
            Path to created backup file

        Raises:
            ValueError: If data cannot be serialized
            IOError: If backup file cannot be written
        """
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"{self.tool_name}-{name}-{timestamp}.json"
        backup_path = self.backup_dir / filename

        backup_data = {
            "tool": self.tool_name,
            "name": name,
            "timestamp": datetime.now().isoformat(),
            "metadata": metadata or {},
            "data": data
        }

        try:
            with open(backup_path, 'w') as f:
                json.dump(backup_data, f, indent=2, default=str)

            logger.info(f"Created backup: {backup_path.name}")
            return backup_path

        except (TypeError, ValueError) as e:
            raise ValueError(f"Cannot serialize backup data: {e}")
        except IOError as e:
            raise IOError(f"Cannot write backup file: {e}")

    def load_backup(self, backup_path: Path) -> Dict[str, Any]:
        """
        Load backup data from file.

        Args:
            backup_path: Path to backup file

        Returns:
            Backup data dictionary

        Raises:
            FileNotFoundError: If backup file doesn't exist
            ValueError: If backup file is invalid
        """
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup not found: {backup_path}")

        try:
            with open(backup_path, 'r') as f:
                backup_data = json.load(f)

            # Validate structure
            required_keys = ["tool", "name", "timestamp", "data"]
            if not all(key in backup_data for key in required_keys):
                raise ValueError("Invalid backup file structure")

            logger.debug(f"Loaded backup: {backup_path.name}")
            return backup_data

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in backup file: {e}")

    def list_backups(self, pattern: str = "*.json") -> List[Dict[str, Any]]:
        """
        List available backups.

        Args:
            pattern: Glob pattern for backup files

        Returns:
            List of backup info dictionaries, sorted by timestamp (newest first)
        """
        backups = []

        for backup_file in sorted(self.backup_dir.glob(pattern), reverse=True):
            try:
                stat = backup_file.stat()
                # Try to load metadata
                try:
                    with open(backup_file, 'r') as f:
                        data = json.load(f)
                    metadata = {
                        "path": backup_file,
                        "filename": backup_file.name,
                        "size": stat.st_size,
                        "created": datetime.fromtimestamp(stat.st_mtime),
                        "tool": data.get("tool", "unknown"),
                        "name": data.get("name", ""),
                        "timestamp": data.get("timestamp", ""),
                    }
                except (json.JSONDecodeError, KeyError):
                    # Fallback for non-JSON or malformed files
                    metadata = {
                        "path": backup_file,
                        "filename": backup_file.name,
                        "size": stat.st_size,
                        "created": datetime.fromtimestamp(stat.st_mtime),
                        "tool": self.tool_name,
                        "name": "",
                        "timestamp": "",
                    }

                backups.append(metadata)

            except Exception as e:
                logger.warning(f"Could not read backup {backup_file}: {e}")

        return backups

    def cleanup_old_backups(self, keep_count: int = 10) -> int:
        """
        Remove old backup files, keeping only the most recent ones.

        Args:
            keep_count: Number of backups to keep

        Returns:
            Number of backups deleted
        """
        backups = self.list_backups()

        if len(backups) <= keep_count:
            logger.debug(f"No cleanup needed ({len(backups)} backups)")
            return 0

        to_delete = backups[keep_count:]
        deleted_count = 0

        for backup in to_delete:
            try:
                backup["path"].unlink()
                logger.debug(f"Deleted old backup: {backup['filename']}")
                deleted_count += 1
            except Exception as e:
                logger.warning(f"Could not delete backup {backup['filename']}: {e}")

        logger.info(f"Cleaned up {deleted_count} old backup(s)")
        return deleted_count

    def get_backup_size(self) -> int:
        """
        Get total size of all backups in bytes.

        Returns:
            Total backup size in bytes
        """
        total_size = 0
        for backup_file in self.backup_dir.glob("*.json"):
            try:
                total_size += backup_file.stat().st_size
            except:
                pass

        return total_size

    def verify_backup(self, backup_path: Path) -> bool:
        """
        Verify backup file is valid and readable.

        Args:
            backup_path: Path to backup file

        Returns:
            True if backup is valid
        """
        try:
            data = self.load_backup(backup_path)
            return "data" in data and data["data"] is not None
        except Exception as e:
            logger.error(f"Backup verification failed: {e}")
            return False
