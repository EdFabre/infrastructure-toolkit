"""WebSocket router for real-time updates and log streaming."""

import asyncio
import json
import logging
from typing import Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from datetime import datetime

from ...tools.performance import PerformanceTool
from ...tools.network import NetworkTool
from ...tools.docker import DockerTool

logger = logging.getLogger(__name__)
router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections for broadcasting updates."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        """Accept and track a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection."""
        self.active_connections.discard(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Send a message to a specific WebSocket connection."""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            self.disconnect(websocket)

    async def broadcast(self, message: dict):
        """Broadcast a message to all connected clients."""
        disconnected = set()
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting to connection: {e}")
                disconnected.add(connection)

        # Clean up disconnected clients
        for connection in disconnected:
            self.disconnect(connection)


# Global connection manager
manager = ConnectionManager()


@router.websocket("/ws/metrics")
async def websocket_metrics(websocket: WebSocket):
    """WebSocket endpoint for real-time performance metrics."""
    await manager.connect(websocket)

    try:
        # Send initial metrics immediately
        perf_tool = PerformanceTool()
        initial_metrics = perf_tool.get_all_servers_metrics()
        await manager.send_personal_message(
            {
                "type": "metrics",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"servers": initial_metrics}
            },
            websocket
        )

        # Keep connection alive and send updates every 30 seconds
        while True:
            try:
                # Wait for 30 seconds or for client message
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)

                # Handle client commands
                try:
                    command = json.loads(data)
                    if command.get("action") == "refresh":
                        # Force refresh metrics
                        metrics = perf_tool.get_all_servers_metrics()
                        await manager.send_personal_message(
                            {
                                "type": "metrics",
                                "timestamp": datetime.utcnow().isoformat(),
                                "data": {"servers": metrics}
                            },
                            websocket
                        )
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON received: {data}")

            except asyncio.TimeoutError:
                # Send periodic updates every 30 seconds
                metrics = perf_tool.get_all_servers_metrics()
                await manager.send_personal_message(
                    {
                        "type": "metrics",
                        "timestamp": datetime.utcnow().isoformat(),
                        "data": {"servers": metrics}
                    },
                    websocket
                )

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("Client disconnected from metrics WebSocket")
    except Exception as e:
        logger.error(f"Error in metrics WebSocket: {e}")
        manager.disconnect(websocket)


@router.websocket("/ws/logs/{server}")
async def websocket_logs(websocket: WebSocket, server: str):
    """WebSocket endpoint for real-time log streaming from Docker containers."""
    await manager.connect(websocket)

    try:
        docker_tool = DockerTool(server=server)

        # Send initial message
        await manager.send_personal_message(
            {
                "type": "logs",
                "timestamp": datetime.utcnow().isoformat(),
                "server": server,
                "message": f"Connected to log stream for {server}"
            },
            websocket
        )

        # Stream logs in real-time
        while True:
            try:
                # Wait for client command
                data = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)

                try:
                    command = json.loads(data)

                    if command.get("action") == "get_logs":
                        container = command.get("container")
                        if container:
                            # Get container logs
                            logs = docker_tool.get_container_logs(
                                container,
                                tail=command.get("tail", 100)
                            )

                            await manager.send_personal_message(
                                {
                                    "type": "logs",
                                    "timestamp": datetime.utcnow().isoformat(),
                                    "server": server,
                                    "container": container,
                                    "logs": logs
                                },
                                websocket
                            )

                    elif command.get("action") == "list_containers":
                        # List containers on this server
                        containers = docker_tool.get_running_services()
                        await manager.send_personal_message(
                            {
                                "type": "containers",
                                "timestamp": datetime.utcnow().isoformat(),
                                "server": server,
                                "containers": containers
                            },
                            websocket
                        )

                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON received: {data}")

            except asyncio.TimeoutError:
                # Send heartbeat
                await manager.send_personal_message(
                    {
                        "type": "heartbeat",
                        "timestamp": datetime.utcnow().isoformat()
                    },
                    websocket
                )

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info(f"Client disconnected from logs WebSocket for {server}")
    except Exception as e:
        logger.error(f"Error in logs WebSocket: {e}")
        manager.disconnect(websocket)


@router.websocket("/ws/network")
async def websocket_network(websocket: WebSocket):
    """WebSocket endpoint for real-time network monitoring."""
    await manager.connect(websocket)

    try:
        net_tool = NetworkTool()

        # Send initial network status
        health = net_tool.get_system_health()
        clients = net_tool.get_clients()

        await manager.send_personal_message(
            {
                "type": "network",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {
                    "health": health,
                    "clients": clients
                }
            },
            websocket
        )

        # Keep connection alive and send updates every 30 seconds
        while True:
            try:
                # Wait for 30 seconds or for client message
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)

                try:
                    command = json.loads(data)
                    if command.get("action") == "refresh":
                        # Force refresh network data
                        health = net_tool.get_system_health()
                        clients = net_tool.get_clients()

                        await manager.send_personal_message(
                            {
                                "type": "network",
                                "timestamp": datetime.utcnow().isoformat(),
                                "data": {
                                    "health": health,
                                    "clients": clients
                                }
                            },
                            websocket
                        )
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON received: {data}")

            except asyncio.TimeoutError:
                # Send periodic updates
                health = net_tool.get_system_health()
                clients = net_tool.get_clients()

                await manager.send_personal_message(
                    {
                        "type": "network",
                        "timestamp": datetime.utcnow().isoformat(),
                        "data": {
                            "health": health,
                            "clients": clients
                        }
                    },
                    websocket
                )

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("Client disconnected from network WebSocket")
    except Exception as e:
        logger.error(f"Error in network WebSocket: {e}")
        manager.disconnect(websocket)
