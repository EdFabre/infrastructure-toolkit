"""infra-toolkit MCP server — infrastructure management via MCP.

Exposes Cloudflare, Proxmox, Pterodactyl, Docker, UPS, and network tools.

Usage:
    python -m infra_toolkit.mcp_server
    infra-mcp serve
"""

import json
import subprocess
import sys
from typing import Any, Dict


def _send(msg: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _recv() -> Dict[str, Any]:
    line = sys.stdin.readline()
    if not line:
        sys.exit(0)
    return json.loads(line)


def _run(*args: str) -> str:
    try:
        result = subprocess.run(
            ["infra-toolkit"] + list(args), capture_output=True, text=True, timeout=60,
        )
        output = result.stdout.strip()
        if result.returncode != 0 and result.stderr:
            output += f"\n[stderr] {result.stderr.strip()}"
        return output or "(no output)"
    except subprocess.TimeoutExpired:
        return "Error: timed out after 60s"
    except Exception as exc:
        return f"Error: {exc}"


TOOLS = [
    {"name": "infra_cloudflare_list", "description": "List all Cloudflare tunnel hostnames",
     "inputSchema": {"type": "object", "properties": {"domain": {"type": "string", "description": "Domain (haymoed or ramcyber)"}}}},
    {"name": "infra_cloudflare_add", "description": "Add a hostname to Cloudflare tunnel (with auto-backup)",
     "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}, "ip": {"type": "string"}, "port": {"type": "integer"}, "protocol": {"type": "string", "description": "http or https"}}, "required": ["service", "ip", "port"]}},
    {"name": "infra_cloudflare_validate", "description": "Validate Cloudflare tunnel configuration integrity",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "infra_cloudflare_health", "description": "Check Cloudflare API connectivity",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "infra_pterodactyl_health", "description": "Pterodactyl panel health check",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "infra_pterodactyl_nodes", "description": "List all Pterodactyl nodes/wings",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "infra_pterodactyl_servers", "description": "List game servers",
     "inputSchema": {"type": "object", "properties": {"node": {"type": "string", "description": "Filter by node ID"}}}},
    {"name": "infra_pterodactyl_diagnose", "description": "Diagnose Pterodactyl tunnel/heartbeat issues",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "infra_docker_list", "description": "List Docker containers on a host",
     "inputSchema": {"type": "object", "properties": {"host": {"type": "string", "description": "Host to check"}}}},
    {"name": "infra_network_scan", "description": "Scan network for hosts",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "infra_ups_status", "description": "Check UPS status",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "infra_proxmox_status", "description": "Proxmox cluster status",
     "inputSchema": {"type": "object", "properties": {}}},
]


def handle_tool_call(name: str, arguments: Dict[str, Any]) -> str:
    if name == "infra_cloudflare_list":
        args = ["cloudflare", "list"]
        if arguments.get("domain"): args.extend(["--domain", arguments["domain"]])
        return _run(*args)
    elif name == "infra_cloudflare_add":
        return _run("cloudflare", "add", arguments["service"], arguments["ip"], str(arguments["port"]),
                     *(["--protocol", arguments["protocol"]] if arguments.get("protocol") else []))
    elif name == "infra_cloudflare_validate":
        return _run("cloudflare", "validate")
    elif name == "infra_cloudflare_health":
        return _run("cloudflare", "health-check")
    elif name == "infra_pterodactyl_health":
        return _run("pterodactyl", "health-check")
    elif name == "infra_pterodactyl_nodes":
        return _run("pterodactyl", "nodes")
    elif name == "infra_pterodactyl_servers":
        args = ["pterodactyl", "servers"]
        if arguments.get("node"): args.extend(["--node", arguments["node"]])
        return _run(*args)
    elif name == "infra_pterodactyl_diagnose":
        return _run("pterodactyl", "diagnose")
    elif name == "infra_docker_list":
        args = ["docker", "list"]
        if arguments.get("host"): args.extend(["--host", arguments["host"]])
        return _run(*args)
    elif name == "infra_network_scan":
        return _run("network", "scan")
    elif name == "infra_ups_status":
        return _run("ups", "status")
    elif name == "infra_proxmox_status":
        return _run("proxmox", "status")
    return json.dumps({"error": f"Unknown tool: {name}"})


def serve() -> None:
    while True:
        msg = _recv()
        method = msg.get("method", "")
        req_id = msg.get("id")
        if method == "initialize":
            _send({"jsonrpc": "2.0", "id": req_id, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "infra-toolkit", "version": "2.0.0"}}})
        elif method == "notifications/initialized":
            pass
        elif method == "tools/list":
            _send({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            params = msg.get("params", {})
            try:
                result = handle_tool_call(params.get("name", ""), params.get("arguments", {}))
                _send({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": result}]}})
            except Exception as exc:
                _send({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": f"Error: {exc}"}], "isError": True}})
        elif req_id is not None:
            _send({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}})


if __name__ == "__main__":
    serve()
