"""Pterodactyl Monitoring API Router"""

from fastapi import APIRouter, HTTPException

from ...tools.pterodactyl import PterodactylTool

router = APIRouter()


@router.get("/nodes")
def get_nodes():
    """List Pterodactyl nodes (wings)"""
    try:
        ptero_tool = PterodactylTool()
        nodes = ptero_tool.list_nodes()
        return {"nodes": nodes}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/diagnose")
def diagnose():
    """Diagnose tunnel configuration issues"""
    try:
        ptero_tool = PterodactylTool()
        diagnosis = ptero_tool.diagnose_tunnel_config()
        return diagnosis
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
