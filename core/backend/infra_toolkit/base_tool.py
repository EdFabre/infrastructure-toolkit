"""
Base Tool Abstract Class

Provides common interface and safety mechanisms for all infrastructure tools.
"""

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional

from .safety.backup import BackupManager
from .safety.verification import VerificationManager


logger = logging.getLogger(__name__)


class BaseTool(ABC):
    """
    Abstract base class for all infrastructure tools.

    Provides:
    - Automatic backup/restore mechanisms
    - Dry-run mode
    - State verification
    - Rollback on failure
    - Comprehensive logging
    """

    def __init__(
        self,
        config: Dict[str, Any],
        dry_run: bool = False,
        verbose: bool = False,
        no_verify: bool = False,
    ):
        """
        Initialize tool with configuration and safety options.

        Args:
            config: Tool-specific configuration dictionary
            dry_run: If True, preview changes without executing
            verbose: Enable verbose logging
            no_verify: Skip verification checks (dangerous!)
        """
        self.config = config
        self.dry_run = dry_run
        self.verbose = verbose
        self.no_verify = no_verify

        # Initialize logging
        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        else:
            logging.getLogger().setLevel(logging.INFO)

        # Initialize safety managers
        self.backup_manager = BackupManager(
            tool_name=self.tool_name(),
            backup_dir=self.get_backup_dir()
        )
        self.verification_manager = VerificationManager()

        logger.info(f"Initialized {self.tool_name()} v{self.version()}")
        if dry_run:
            logger.info("DRY-RUN MODE: No changes will be applied")

    @classmethod
    @abstractmethod
    def tool_name(cls) -> str:
        """Return the tool name (e.g., 'cloudflare', 'docker')"""
        pass

    @classmethod
    def version(cls) -> str:
        """Return tool version (default from package version)"""
        from . import __version__
        return __version__

    @abstractmethod
    def validate_config(self) -> bool:
        """
        Validate tool-specific configuration.

        Returns:
            True if configuration is valid

        Raises:
            ValueError: If configuration is invalid
        """
        pass

    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """
        Check tool health and connectivity.

        Returns:
            Dictionary with health check results:
            {
                'status': 'healthy|degraded|unhealthy',
                'checks': {
                    'connectivity': True/False,
                    'authentication': True/False,
                    ...
                },
                'message': 'Optional status message'
            }
        """
        pass

    def get_backup_dir(self) -> Path:
        """
        Get backup directory for this tool.

        Returns:
            Path to backup directory
        """
        # Default to project data directory
        from pathlib import Path
        base_dir = Path(__file__).parent.parent.parent.parent.parent
        backup_dir = base_dir / "data" / "backups" / self.tool_name()
        backup_dir.mkdir(parents=True, exist_ok=True)
        return backup_dir

    def execute_with_safety(
        self,
        operation_name: str,
        operation_func: callable,
        *args,
        **kwargs
    ) -> Any:
        """
        Execute operation with automatic backup and rollback.

        Args:
            operation_name: Human-readable operation name (for logging)
            operation_func: Function to execute
            *args, **kwargs: Arguments to pass to operation_func

        Returns:
            Result from operation_func

        Raises:
            Exception: If operation fails (after attempting rollback)
        """
        logger.info(f"Executing: {operation_name}")

        if self.dry_run:
            logger.info(f"[DRY-RUN] Would execute: {operation_name}")
            logger.info(f"[DRY-RUN] Arguments: args={args}, kwargs={kwargs}")
            return None

        # Create backup before operation
        backup_path = None
        try:
            # Get current state for backup
            current_state = self.get_current_state()
            backup_path = self.backup_manager.create_backup(
                name=f"pre-{operation_name}",
                data=current_state
            )
            logger.info(f"Created backup: {backup_path}")

        except Exception as e:
            logger.warning(f"Failed to create backup: {e}")
            if not self.no_verify:
                raise RuntimeError(
                    "Cannot proceed without backup. Use --no-verify to override (dangerous!)"
                )

        # Execute operation
        try:
            result = operation_func(*args, **kwargs)

            # Verify result if enabled
            if not self.no_verify:
                if not self.verify_operation(operation_name, result):
                    raise ValueError(f"Verification failed for {operation_name}")

            logger.info(f"✓ {operation_name} completed successfully")
            return result

        except Exception as e:
            logger.error(f"✗ {operation_name} failed: {e}")

            # Attempt rollback if backup exists
            if backup_path and backup_path.exists():
                logger.warning("Attempting automatic rollback...")
                try:
                    self.rollback_from_backup(backup_path)
                    logger.info("✓ Rollback successful")
                except Exception as rollback_error:
                    logger.error(f"✗ Rollback failed: {rollback_error}")
                    logger.error("MANUAL INTERVENTION REQUIRED!")

            raise

    @abstractmethod
    def get_current_state(self) -> Dict[str, Any]:
        """
        Get current state for backup purposes.

        Returns:
            Dictionary representing current state
        """
        pass

    @abstractmethod
    def rollback_from_backup(self, backup_path: Path) -> bool:
        """
        Restore state from backup file.

        Args:
            backup_path: Path to backup file

        Returns:
            True if rollback successful

        Raises:
            Exception: If rollback fails
        """
        pass

    def verify_operation(self, operation_name: str, result: Any) -> bool:
        """
        Verify operation completed successfully.

        Args:
            operation_name: Name of operation
            result: Result from operation

        Returns:
            True if verification passed
        """
        # Default implementation - subclasses can override
        return True

    @classmethod
    def configure_parser(cls, parser):
        """
        Configure argument parser for this tool.

        Subclasses should override to add tool-specific arguments.

        Args:
            parser: argparse.ArgumentParser instance
        """
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
            help="Skip verification checks (dangerous!)"
        )
