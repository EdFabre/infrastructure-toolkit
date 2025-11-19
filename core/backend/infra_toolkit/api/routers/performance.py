"""
Performance Monitoring API Router

Exposes performance monitoring endpoints for server health metrics.
"""

from fastapi import APIRouter, HTTPException
from typing import List, Optional

from ...tools.performance import PerformanceTool


router = APIRouter()


@router.get("/dashboard")
def get_dashboard():
    """
    Get multi-server health dashboard

    Returns health metrics for all configured servers including:
    - CPU load averages
    - Memory usage
    - Disk usage
    - Status (healthy/warning/critical)
    """
    try:
        # Initialize tool (uses default config)
        perf_tool = PerformanceTool()
        metrics = perf_tool.get_all_servers_metrics()

        return {"servers": metrics}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/servers/{server}/metrics")
def get_server_metrics(server: str):
    """
    Get detailed metrics for a specific server

    Args:
        server: Server hostname (e.g., boss-01)

    Returns detailed server metrics including memory, CPU, disk
    """
    try:
        perf_tool = PerformanceTool()
        metrics = perf_tool.get_server_metrics(server)

        if not metrics.get("reachable"):
            raise HTTPException(
                status_code=404,
                detail=f"Server {server} is unreachable"
            )

        return metrics
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/summary")
def get_summary():
    """
    Get aggregated metrics summary

    Returns statistics across all servers:
    - Total/reachable server counts
    - Healthy/warning/critical counts
    - Individual server metrics
    """
    try:
        perf_tool = PerformanceTool()
        metrics_list = perf_tool.get_all_servers_metrics()

        # Calculate aggregates
        total_servers = len(metrics_list)
        reachable = sum(1 for m in metrics_list if m.get("reachable"))
        healthy = sum(1 for m in metrics_list if m.get("status") == "healthy")
        warning = sum(1 for m in metrics_list if m.get("status") == "warning")
        critical = sum(1 for m in metrics_list if m.get("status") == "critical")

        return {
            "total_servers": total_servers,
            "reachable": reachable,
            "healthy": healthy,
            "warning": warning,
            "critical": critical,
            "servers": metrics_list
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
