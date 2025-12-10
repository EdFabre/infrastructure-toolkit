"""Proxmox VE USB Management API Router"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from ...tools.proxmox import ProxmoxTool

router = APIRouter()


class USBResetRequest(BaseModel):
    """Request body for USB reset"""
    device_id: str
    use_hostport: bool = True


@router.get("/health")
def health_check(host: str = "pve3"):
    """Check Proxmox tool health and connectivity"""
    try:
        proxmox_tool = ProxmoxTool(host=host)
        health = proxmox_tool.health_check()
        return health
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vms/{vm_id}/usb")
def get_usb_status(vm_id: int, host: str = "pve3"):
    """Get USB device status for a VM"""
    try:
        proxmox_tool = ProxmoxTool(host=host)
        health = proxmox_tool.check_usb_health(vm_id)
        return health
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/vms/{vm_id}/usb/reset")
def reset_usb_device(vm_id: int, request: USBResetRequest, host: str = "pve3"):
    """Reset a USB device on a VM"""
    try:
        proxmox_tool = ProxmoxTool(host=host)
        success = proxmox_tool.reset_usb_device(
            vm_id=vm_id,
            device_id=request.device_id,
            use_hostport=request.use_hostport
        )

        if success:
            # Get updated status
            health = proxmox_tool.check_usb_health(vm_id)
            return {
                "success": True,
                "message": f"USB device {request.device_id} reset successfully",
                "new_status": health
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to reset USB device")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/vms/{vm_id}/usb/auto-fix")
def auto_fix_usb(vm_id: int, host: str = "pve3"):
    """Auto-detect and fix unhealthy USB devices"""
    try:
        proxmox_tool = ProxmoxTool(host=host)
        result = proxmox_tool.auto_fix_usb(vm_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vms/{vm_id}/config")
def get_vm_config(vm_id: int, host: str = "pve3"):
    """Get VM configuration"""
    try:
        proxmox_tool = ProxmoxTool(host=host)
        config = proxmox_tool.get_vm_config(vm_id)
        return {"config": config}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
