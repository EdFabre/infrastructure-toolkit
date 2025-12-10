"""
FastAPI Main Application

Entry point for the Infrastructure Toolkit REST API.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

from .routers import performance, network, docker, cloudflare, pterodactyl, proxmox, websocket, nas, auth
from ..database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup: Initialize database and create default admin user
    print("🚀 Starting Infrastructure Toolkit API...")
    init_db()
    yield
    # Shutdown
    print("👋 Shutting down Infrastructure Toolkit API...")


app = FastAPI(
    title="Infrastructure Toolkit API",
    description="REST API for infrastructure monitoring and management",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Vite dev server
        "http://192.168.1.10:5173",  # Network access
        "http://localhost:3000",  # Alternative dev port
        "https://infra.haymoed.com",  # Production
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, tags=["authentication"])  # Auth router (no prefix, has /api/auth in router)
app.include_router(performance.router, prefix="/api/perf", tags=["performance"])
app.include_router(network.router, prefix="/api/net", tags=["network"])
app.include_router(docker.router, prefix="/api/docker", tags=["docker"])
app.include_router(cloudflare.router, prefix="/api/cloudflare", tags=["cloudflare"])
app.include_router(pterodactyl.router, prefix="/api/pterodactyl", tags=["pterodactyl"])
app.include_router(proxmox.router, prefix="/api/proxmox", tags=["proxmox"])
app.include_router(nas.router, prefix="/api/nas", tags=["nas"])
app.include_router(websocket.router, prefix="/api", tags=["websocket"])


@app.get("/api/health")
def health_check():
    """API health check endpoint"""
    return {"status": "healthy"}


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for better error responses"""
    return JSONResponse(
        status_code=500,
        content={
            "error": str(exc),
            "type": type(exc).__name__
        }
    )
