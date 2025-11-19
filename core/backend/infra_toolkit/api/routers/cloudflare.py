"""Cloudflare Management API Router"""

from fastapi import APIRouter, HTTPException, Query

from ...tools.cloudflare import CloudflareTool

router = APIRouter()


@router.get("/hostnames")
def get_hostnames(domain: str = Query("haymoed", regex="^(haymoed|ramcyber)$")):
    """List Cloudflare tunnel hostnames"""
    try:
        cf_tool = CloudflareTool(domain=domain)
        config = cf_tool.get_tunnel_config()

        # Extract hostnames from ingress rules
        hostnames = []
        for rule in config.get("config", {}).get("ingress", []):
            if "hostname" in rule:
                hostnames.append({
                    "hostname": rule["hostname"],
                    "service": rule.get("service", "")
                })

        return {"hostnames": hostnames}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/validate")
def validate_config(domain: str = Query("haymoed", regex="^(haymoed|ramcyber)$")):
    """Validate Cloudflare tunnel configuration"""
    try:
        cf_tool = CloudflareTool(domain=domain)
        is_valid, errors = cf_tool.validate_tunnel_config()

        return {
            "is_valid": is_valid,
            "errors": errors
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
