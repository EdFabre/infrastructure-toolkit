"""Docker Management API Router"""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional

from ...tools.docker import DockerTool

router = APIRouter()


@router.get("/containers")
def get_containers(
    server: Optional[str] = Query(None, description="Specific server to query (omit for all servers)"),
    no_cache: bool = Query(False, description="Bypass cache and fetch fresh data")
):
    """
    List Docker containers across servers

    Query Parameters:
    - server: Query specific server (omit for all servers)
    - no_cache: Force fresh data (bypasses 60s cache)
    """
    try:
        docker_tool = DockerTool(server=server, all_servers=(server is None))
        use_cache = not no_cache

        if docker_tool.all_servers:
            containers = docker_tool.get_all_running_services(use_cache=use_cache)
        else:
            containers = docker_tool.get_running_services()

        return {
            "containers": containers,
            "total": len(containers),
            "cache_info": {
                "cached": use_cache and docker_tool.all_servers,
                "ttl_seconds": 60
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/servers/{server}/health")
def get_docker_health(server: str):
    """Check Docker health on specific server"""
    try:
        docker_tool = DockerTool(server=server)
        health = docker_tool.health_check()
        return health
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
