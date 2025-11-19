"""Docker Management API Router"""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional

from ...tools.docker import DockerTool

router = APIRouter()


@router.get("/containers")
def get_containers(server: Optional[str] = Query(None)):
    """List Docker containers across servers"""
    try:
        docker_tool = DockerTool(server=server, all_servers=(server is None))

        if docker_tool.all_servers:
            containers = docker_tool.get_all_running_services()
        else:
            containers = docker_tool.get_running_services()

        return {"containers": containers, "total": len(containers)}
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
