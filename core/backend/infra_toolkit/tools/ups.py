"""
UPS Power Monitoring Tool

Read-only monitoring for dual UPS infrastructure via Prometheus.
Queries metrics from ups-exporter (Smart-UPS) and nut-exporter (BE600M1).
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from ..base_tool import BaseTool

logger = logging.getLogger(__name__)

PROMETHEUS_URL = "http://192.168.1.80:9090"

# Metric definitions for each UPS
SMART_UPS_METRICS = {
    "status": "ups_status",
    "battery_charge": "ups_battery_charge_percent",
    "runtime": "ups_runtime_seconds",
    "load": "ups_output_watts_percent",
    "input_voltage": "ups_input_voltage",
    "output_voltage": "ups_output_voltage",
    "battery_temp": "ups_battery_temperature_celsius",
    "energy_kwh": "ups_output_energy_kwh",
    "efficiency": "ups_output_efficiency_percent",
}

BE600M1_METRICS = {
    "status": 'nut_ups_status{ups="be600m1",status="OL"}',
    "battery_charge": 'nut_battery_charge{ups="be600m1"}',
    "runtime": 'nut_battery_runtime_seconds{ups="be600m1"}',
    "load": 'nut_load{ups="be600m1"}',
    "input_voltage": 'nut_input_voltage_volts{ups="be600m1"}',
}


class UPSTool(BaseTool):
    """
    UPS power monitoring via Prometheus queries.

    Read-only tool providing:
    1. Dual UPS status (Smart-UPS + BE600M1)
    2. Historical range queries (min/max/avg)
    3. Energy consumption tracking
    """

    def __init__(self, **kwargs):
        config = {"ups": {"prometheus_url": PROMETHEUS_URL}}
        super().__init__(config, **kwargs)
        self.prom_url = PROMETHEUS_URL
        self.session = requests.Session()

    @classmethod
    def tool_name(cls) -> str:
        return "ups"

    def validate_config(self) -> bool:
        return True

    def _query_instant(self, expr: str) -> Optional[float]:
        """Run a Prometheus instant query, return scalar value or None."""
        try:
            resp = self.session.get(
                f"{self.prom_url}/api/v1/query",
                params={"query": expr},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("data", {}).get("result", [])
            if results:
                return float(results[0]["value"][1])
            return None
        except Exception as e:
            logger.debug(f"Query failed for {expr}: {e}")
            return None

    def _query_range(self, expr: str, duration: str = "1h", step: str = "60s") -> List[Dict]:
        """Run a Prometheus range query."""
        try:
            import time
            end = time.time()
            dur_map = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}
            start = end - dur_map.get(duration, 3600)
            resp = self.session.get(
                f"{self.prom_url}/api/v1/query_range",
                params={"query": expr, "start": start, "end": end, "step": step},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("data", {}).get("result", [])
            if results:
                return [float(v[1]) for v in results[0]["values"]]
            return []
        except Exception as e:
            logger.debug(f"Range query failed for {expr}: {e}")
            return []

    def _get_ups_values(self, metrics: dict) -> Dict[str, Optional[float]]:
        """Query all metrics for a UPS."""
        return {name: self._query_instant(expr) for name, expr in metrics.items()}

    def status(self) -> Dict[str, Any]:
        """Get current status of both UPS units."""
        smart = self._get_ups_values(SMART_UPS_METRICS)
        be600 = self._get_ups_values(BE600M1_METRICS)

        # Convert BE600M1 ratios to percentages
        if be600.get("battery_charge") is not None:
            be600["battery_charge"] = be600["battery_charge"] * 100
        if be600.get("load") is not None:
            be600["load"] = be600["load"] * 100

        return {
            "smart_ups": {
                "name": "Smart-UPS (Servers)",
                "online": smart.get("status") == 1,
                "battery_pct": smart.get("battery_charge"),
                "runtime_s": smart.get("runtime"),
                "load_pct": smart.get("load"),
                "input_v": smart.get("input_voltage"),
                "output_v": smart.get("output_voltage"),
                "temp_c": smart.get("battery_temp"),
                "energy_kwh": smart.get("energy_kwh"),
                "efficiency_pct": smart.get("efficiency"),
            },
            "be600m1": {
                "name": "BE600M1 (Network)",
                "online": be600.get("status") == 1,
                "battery_pct": be600.get("battery_charge"),
                "runtime_s": be600.get("runtime"),
                "load_pct": be600.get("load"),
                "input_v": be600.get("input_voltage"),
            },
        }

    def history(self, duration: str = "1h") -> Dict[str, Any]:
        """Get historical min/max/avg for key metrics."""
        result = {}
        for ups_name, metrics in [("smart_ups", SMART_UPS_METRICS), ("be600m1", BE600M1_METRICS)]:
            ups_hist = {}
            for metric_name in ["battery_charge", "runtime", "load"]:
                if metric_name not in metrics:
                    continue
                values = self._query_range(metrics[metric_name], duration)
                if values:
                    ups_hist[metric_name] = {
                        "min": round(min(values), 2),
                        "max": round(max(values), 2),
                        "avg": round(sum(values) / len(values), 2),
                        "samples": len(values),
                    }
            result[ups_name] = ups_hist
        return result

    def energy(self) -> Dict[str, Any]:
        """Get energy consumption stats."""
        daily = self._query_instant("increase(ups_output_energy_kwh[24h])")
        weekly = self._query_instant("increase(ups_output_energy_kwh[7d])")
        rate_kw = self._query_instant("rate(ups_output_energy_kwh[5m])")
        watts = rate_kw * 1000 if rate_kw is not None else None
        return {
            "daily_kwh": round(daily, 3) if daily else None,
            "weekly_kwh": round(weekly, 3) if weekly else None,
            "current_watts": round(watts, 1) if watts else None,
        }

    def health_check(self) -> Dict[str, Any]:
        """Check Prometheus connectivity."""
        try:
            resp = self.session.get(f"{self.prom_url}/api/v1/status/config", timeout=5)
            ok = resp.status_code == 200
            return {
                "status": "healthy" if ok else "unhealthy",
                "checks": {"prometheus_reachable": ok},
                "message": "Prometheus reachable" if ok else "Cannot reach Prometheus",
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "checks": {"prometheus_reachable": False},
                "message": str(e),
            }

    def get_current_state(self) -> Dict[str, Any]:
        return {"message": "Read-only tool - no state tracking needed"}

    def rollback_from_backup(self, backup_path: Path) -> bool:
        raise NotImplementedError("UPS tool is read-only - no rollback needed")

    def verify_operation(self, operation_name: str, result: Any) -> bool:
        return True

    @classmethod
    def configure_parser(cls, parser):
        super().configure_parser(parser)
        subs = parser.add_subparsers(dest="subcommand", help="UPS subcommands")
        subs.add_parser("status", help="Show current UPS status (both units)")
        hist = subs.add_parser("history", help="Historical min/max/avg")
        hist.add_argument("--duration", default="1h", choices=["1h", "6h", "24h", "7d"], help="Time range")
        subs.add_parser("energy", help="Energy consumption (daily/weekly/watts)")
        subs.add_parser("health-check", help="Check Prometheus connectivity")
