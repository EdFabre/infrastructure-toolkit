"""
Uptime Kuma Monitoring Tool

Export and backup Uptime Kuma monitor configurations.

Features:
- Export monitor configurations to YAML files
- Backup Kuma database via Fly.io
"""

import json
import logging
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from ..base_tool import BaseTool

logger = logging.getLogger(__name__)


class UptimeKumaTool(BaseTool):
    """
    Uptime Kuma monitor management and backup.

    Provides export of monitor configurations and database backups
    via Fly.io SSH.
    """

    # Fields to keep when exporting monitors
    KEEP_FIELDS = [
        "id", "name", "description", "type", "url", "method", "hostname",
        "port", "keyword", "interval", "retryInterval", "maxretries",
        "accepted_statuscodes", "pushToken", "active",
    ]

    def __init__(self, config: Dict[str, Any], **kwargs):
        super().__init__(config, **kwargs)
        self.kuma_config = config.get("uptime_kuma", {})
        self.url = self.kuma_config.get("url", "https://uptime.haymoed.com")
        self.username = self.kuma_config.get("username", "")
        self.password = self.kuma_config.get("password", "")
        self.fly_app = self.kuma_config.get("fly_app", "empty-dust-1532")
        self.backup_dir = Path(
            self.kuma_config.get("backup_dir", "/mnt/tank/backups/uptime-kuma")
        )
        self.output_dir = Path(
            self.kuma_config.get(
                "output_dir",
                "/mnt/tank/faststorage/general/repo/ai-config/docs/infrastructure/services/uptime-monitoring/monitors",
            )
        )

    @classmethod
    def tool_name(cls) -> str:
        return "uptime-kuma"

    def validate_config(self) -> bool:
        """Validate Uptime Kuma configuration."""
        if not self.username or not self.password:
            raise ValueError("Uptime Kuma credentials not configured in config.yaml")
        if self.password == "CHANGE_ME":
            raise ValueError("Uptime Kuma password is still the default placeholder")
        return True

    def health_check(self) -> Dict[str, Any]:
        """Check Uptime Kuma connectivity."""
        import requests
        try:
            resp = requests.get(self.url, timeout=10)
            ok = resp.status_code == 200
            return {
                "status": "healthy" if ok else "unhealthy",
                "checks": {"uptime_kuma_reachable": ok},
                "message": f"Uptime Kuma reachable at {self.url}" if ok else "Cannot reach Uptime Kuma",
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "checks": {"uptime_kuma_reachable": False},
                "message": str(e),
            }

    def get_current_state(self) -> Dict[str, Any]:
        return {"message": "Read-only tool - no state tracking needed"}

    def rollback_from_backup(self, backup_path: Path) -> bool:
        raise NotImplementedError("Uptime Kuma tool does not support rollback")

    def export_monitors(self) -> bool:
        """Export all monitor configurations to YAML files."""
        try:
            from uptime_kuma_api import UptimeKumaApi
        except ImportError:
            logger.error("uptime_kuma_api not installed. Run: pip install uptime_kuma_api")
            print("ERROR: uptime_kuma_api not installed. Run: pip install uptime_kuma_api")
            return False

        if not self.username or not self.password:
            logger.error("Uptime Kuma credentials not configured in config.yaml")
            print("ERROR: Set uptime_kuma.username and uptime_kuma.password in config.yaml")
            return False

        print(f"Connecting to {self.url}...")
        api = UptimeKumaApi(self.url)
        api.login(self.username, self.password)

        monitors = api.get_monitors()
        print(f"Found {len(monitors)} monitors\n")

        all_monitors = []
        for m in monitors:
            try:
                time.sleep(0.5)
                details = api.get_monitor(m["id"])
                all_monitors.append(details)
                print(f"  OK {m['id']:2d}: {m['name']}")
            except Exception as e:
                print(f"  FAIL {m['id']:2d}: {m['name']} - {e}")
                all_monitors.append(m)

        api.disconnect()

        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Save complete JSON export
        json_path = self.output_dir / "_all_monitors.json"
        with open(json_path, "w") as f:
            json.dump(all_monitors, f, default=str, indent=2)
        print(f"\nSaved complete export to {json_path}")

        # Create individual YAML files
        for m in all_monitors:
            safe_name = re.sub(r"[^a-zA-Z0-9-]", "-", m["name"].lower())
            safe_name = re.sub(r"-+", "-", safe_name).strip("-")

            config = {
                k: v for k, v in m.items() if k in self.KEEP_FIELDS and v is not None
            }
            if "type" in config:
                config["type"] = str(config["type"]).replace("MonitorType.", "")

            filename = self.output_dir / f"{m['id']:02d}-{safe_name}.yaml"
            with open(filename, "w") as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        print(f"Created {len(all_monitors)} individual YAML files")
        print(f"Output directory: {self.output_dir}")
        return True

    def backup(self) -> bool:
        """Backup Uptime Kuma database from Fly.io."""
        flyctl = Path.home() / ".fly" / "bin" / "flyctl"
        if not flyctl.exists():
            # Try PATH
            import shutil
            flyctl_path = shutil.which("flyctl")
            if not flyctl_path:
                print("ERROR: flyctl not found")
                return False
            flyctl = Path(flyctl_path)

        self.backup_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_file = f"uptime-kuma-{timestamp}.tar.gz"
        remote_backup = "/app/data/backup.tar.gz"

        print(f"=== Uptime Kuma Backup ===")
        print(f"Timestamp: {timestamp}")
        print(f"App: {self.fly_app}")
        print()

        # Check app status
        print("Checking app status...")
        result = subprocess.run(
            [str(flyctl), "status", "-a", self.fly_app],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"ERROR: Cannot reach app {self.fly_app}")
            return False
        print("  App is running")

        # Create backup on remote
        print("Creating backup archive on Fly.io...")
        subprocess.run(
            [
                str(flyctl), "ssh", "console", "-a", self.fly_app, "-C",
                "/bin/sh -c 'cd /app/data && tar -czf backup.tar.gz kuma.db'",
            ],
            capture_output=True,
        )
        print("  Archive created")

        # Download backup
        print("Downloading backup...")
        subprocess.run(
            [
                str(flyctl), "ssh", "sftp", "get", remote_backup,
                str(self.backup_dir / backup_file), "-a", self.fly_app,
            ],
            capture_output=True,
        )

        local_path = self.backup_dir / backup_file
        if local_path.exists():
            size_mb = local_path.stat().st_size / (1024 * 1024)
            print(f"  Backup saved: {backup_file} ({size_mb:.1f}MB)")
        else:
            print("ERROR: Backup file not created")
            return False

        # Cleanup remote
        print("Cleaning up remote backup file...")
        subprocess.run(
            [
                str(flyctl), "ssh", "console", "-a", self.fly_app, "-C",
                "/bin/sh -c 'rm -f /app/data/backup.tar.gz'",
            ],
            capture_output=True,
        )

        # Cleanup old local backups (30 days)
        print("Cleaning up old backups...")
        import time as time_mod
        cutoff = time_mod.time() - (30 * 86400)
        deleted = 0
        for old_file in self.backup_dir.glob("uptime-kuma-*.tar.gz"):
            if old_file.stat().st_mtime < cutoff:
                old_file.unlink()
                deleted += 1
        print(f"  Deleted {deleted} old backup(s)")

        # List recent
        print("\nRecent backups:")
        recent = sorted(self.backup_dir.glob("uptime-kuma-*.tar.gz"))[-5:]
        for f in recent:
            size = f.stat().st_size / (1024 * 1024)
            print(f"  {f.name} ({size:.1f}MB)")

        print("\n=== Backup Complete ===")
        return True

    @classmethod
    def configure_parser(cls, parser):
        """Configure argument parser for Uptime Kuma tool."""
        super().configure_parser(parser)
        subs = parser.add_subparsers(dest="subcommand", help="Uptime Kuma subcommands")
        subs.add_parser("export", help="Export monitor configurations to YAML")
        subs.add_parser("backup", help="Backup Kuma database from Fly.io")
        subs.add_parser("health-check", help="Check Uptime Kuma connectivity")
