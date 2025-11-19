"""Network Monitoring API Router"""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional

from ...tools.network import NetworkTool

router = APIRouter()


@router.get("/health")
def get_health():
    """Get UDM-SE system health status"""
    try:
        net_tool = NetworkTool()
        health = net_tool.get_system_health()
        return health
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/networks")
def get_networks():
    """List network configurations"""
    try:
        net_tool = NetworkTool()
        networks = net_tool.get_networks()
        return {"networks": networks}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/wifi")
def get_wifi():
    """List WiFi (WLAN) networks"""
    try:
        net_tool = NetworkTool()
        wlans = net_tool.get_wifi_networks()
        return {"wlans": wlans}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/devices")
def get_devices():
    """List network devices (APs, switches, gateway)"""
    try:
        net_tool = NetworkTool()
        devices = net_tool.get_devices()
        return {"devices": devices}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/clients")
def get_clients(
    top: Optional[int] = Query(None, ge=1, le=100),
    sortBy: Optional[str] = Query("bandwidth", regex="^(bandwidth|signal|name)$")
):
    """List active network clients"""
    try:
        net_tool = NetworkTool()
        clients = net_tool.get_clients()

        # Sort clients
        if sortBy == "bandwidth":
            clients.sort(key=lambda c: c.get("total_bytes", 0), reverse=True)
        elif sortBy == "signal":
            clients.sort(key=lambda c: c.get("signal", -100), reverse=True)
        elif sortBy == "name":
            clients.sort(key=lambda c: c.get("hostname", "").lower())

        # Limit to top N
        if top:
            clients = clients[:top]

        return {"clients": clients, "total": len(clients)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
