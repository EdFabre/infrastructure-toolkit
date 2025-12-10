"""NAS Monitoring API Router"""

from fastapi import APIRouter, HTTPException, Query

from ...tools.nas import NASTool

router = APIRouter()


@router.get("/systems")
def get_nas_systems():
    """List all configured NAS systems with metrics"""
    try:
        nas_tool = NASTool()
        metrics = nas_tool.get_all_nas_metrics()
        return {"systems": metrics, "total": len(metrics)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
def get_nas_health():
    """Check health status of all NAS systems"""
    try:
        nas_tool = NASTool()
        health = nas_tool.health_check()
        return health
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Unraid action endpoints

@router.get("/unraid/array-status")
def get_unraid_array_status():
    """Get Unraid array status from /proc/mdstat"""
    try:
        nas_tool = NASTool()
        # Get Unraid IP from config
        unraid_ip = nas_tool.nas_systems.get("unraid", {}).get("ip")
        if not unraid_ip:
            raise HTTPException(status_code=404, detail="Unraid system not configured")

        status = nas_tool.get_unraid_array_status(unraid_ip)
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/unraid/parity-status")
def get_unraid_parity_status():
    """Get Unraid parity check status"""
    try:
        nas_tool = NASTool()
        unraid_ip = nas_tool.nas_systems.get("unraid", {}).get("ip")
        if not unraid_ip:
            raise HTTPException(status_code=404, detail="Unraid system not configured")

        status = nas_tool.get_unraid_parity_status(unraid_ip)
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/unraid/disk-status")
def get_unraid_disk_status():
    """Get Unraid disk spin status"""
    try:
        nas_tool = NASTool()
        unraid_ip = nas_tool.nas_systems.get("unraid", {}).get("ip")
        if not unraid_ip:
            raise HTTPException(status_code=404, detail="Unraid system not configured")

        status = nas_tool.get_unraid_disk_status(unraid_ip)
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# TrueNAS action endpoints

@router.get("/truenas/scrub-status")
def get_truenas_scrub_status(pool: str = Query(None, description="Optional pool name")):
    """Get TrueNAS pool scrub status"""
    try:
        nas_tool = NASTool()
        truenas_ip = nas_tool.nas_systems.get("truenas", {}).get("ip")
        if not truenas_ip:
            raise HTTPException(status_code=404, detail="TrueNAS system not configured")

        status = nas_tool.get_truenas_pool_scrub_status(truenas_ip, pool)
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/truenas/datasets")
def get_truenas_datasets(pool: str = Query(None, description="Optional pool name")):
    """Get TrueNAS datasets"""
    try:
        nas_tool = NASTool()
        truenas_ip = nas_tool.nas_systems.get("truenas", {}).get("ip")
        if not truenas_ip:
            raise HTTPException(status_code=404, detail="TrueNAS system not configured")

        datasets = nas_tool.get_truenas_dataset_list(truenas_ip, pool)
        return datasets
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/truenas/services")
def get_truenas_services(service: str = Query(None, description="Optional service name")):
    """Get TrueNAS service status"""
    try:
        nas_tool = NASTool()
        truenas_ip = nas_tool.nas_systems.get("truenas", {}).get("ip")
        if not truenas_ip:
            raise HTTPException(status_code=404, detail="TrueNAS system not configured")

        services = nas_tool.get_truenas_service_status(truenas_ip, service)
        return services
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
