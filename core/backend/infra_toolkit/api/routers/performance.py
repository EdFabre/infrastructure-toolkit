"""
Performance Monitoring API Router

Exposes performance monitoring endpoints for server health metrics.
"""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional

from ...tools.performance import PerformanceTool


router = APIRouter()


@router.get("/dashboard")
def get_dashboard(
    no_cache: bool = Query(False, description="Bypass cache and fetch fresh data"),
    include_containers: bool = Query(True, description="Include cAdvisor container metrics")
):
    """
    Get multi-server health dashboard

    Returns health metrics for all configured servers including:
    - CPU load averages
    - Memory usage
    - Disk usage
    - Container metrics (CPU, memory, network) from cAdvisor
    - Status (healthy/warning/critical)

    Query Parameters:
    - no_cache: Force fresh data (bypasses 60s cache)
    - include_containers: Include container metrics from cAdvisor (default: true)
    """
    try:
        # Initialize tool (uses default config)
        perf_tool = PerformanceTool()
        use_cache = not no_cache

        metrics = perf_tool.get_all_servers_metrics(
            include_containers=include_containers,
            use_cache=use_cache
        )

        return {
            "servers": metrics,
            "cache_info": {
                "cached": use_cache and len(metrics) > 0,
                "ttl_seconds": 60
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/servers/{server}/metrics")
def get_server_metrics(
    server: str,
    no_cache: bool = Query(False, description="Bypass cache and fetch fresh data"),
    include_containers: bool = Query(True, description="Include cAdvisor container metrics")
):
    """
    Get detailed metrics for a specific server

    Args:
        server: Server hostname (e.g., boss-01)

    Returns detailed server metrics including:
    - Memory, CPU, disk usage
    - Container metrics (if include_containers=true)

    Query Parameters:
    - no_cache: Force fresh data (bypasses 60s cache)
    - include_containers: Include container metrics from cAdvisor (default: true)
    """
    try:
        perf_tool = PerformanceTool()
        use_cache = not no_cache

        metrics = perf_tool.get_server_metrics(
            server,
            include_containers=include_containers,
            use_cache=use_cache
        )

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
def get_summary(
    no_cache: bool = Query(False, description="Bypass cache and fetch fresh data"),
    include_containers: bool = Query(True, description="Include cAdvisor container metrics")
):
    """
    Get aggregated metrics summary

    Returns statistics across all servers:
    - Total/reachable server counts
    - Healthy/warning/critical counts
    - Individual server metrics
    - Container counts (if include_containers=true)

    Query Parameters:
    - no_cache: Force fresh data (bypasses 60s cache)
    - include_containers: Include container metrics from cAdvisor (default: true)
    """
    try:
        perf_tool = PerformanceTool()
        use_cache = not no_cache

        metrics_list = perf_tool.get_all_servers_metrics(
            include_containers=include_containers,
            use_cache=use_cache
        )

        # Calculate aggregates
        total_servers = len(metrics_list)
        reachable = sum(1 for m in metrics_list if m.get("reachable"))
        healthy = sum(1 for m in metrics_list if m.get("status") == "healthy")
        warning = sum(1 for m in metrics_list if m.get("status") == "warning")
        critical = sum(1 for m in metrics_list if m.get("status") == "critical")
        unreachable = sum(1 for m in metrics_list if m.get("status") == "unreachable")

        # Calculate container stats if included
        container_stats = {}
        if include_containers:
            total_containers = sum(
                len(m.get("containers", {}))
                for m in metrics_list
            )
            container_stats = {
                "total_containers": total_containers,
                "servers_with_cadvisor": sum(
                    1 for m in metrics_list if m.get("cadvisor_available", False)
                )
            }

        return {
            "total_servers": total_servers,
            "reachable": reachable,
            "healthy": healthy,
            "warning": warning,
            "critical": critical,
            "unreachable": unreachable,
            **container_stats,
            "cache_info": {
                "cached": use_cache,
                "ttl_seconds": 60
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
