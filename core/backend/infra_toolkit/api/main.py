"""
FastAPI Main Application

Entry point for the Infrastructure Toolkit REST API.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .routers import performance, network, docker, cloudflare, pterodactyl, websocket


app = FastAPI(
    title="Infrastructure Toolkit API",
    description="REST API for infrastructure monitoring and management",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Vite dev server
        "http://localhost:3000",  # Alternative dev port
        "https://infra.haymoed.com",  # Production
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(performance.router, prefix="/api/perf", tags=["performance"])
app.include_router(network.router, prefix="/api/net", tags=["network"])
app.include_router(docker.router, prefix="/api/docker", tags=["docker"])
app.include_router(cloudflare.router, prefix="/api/cloudflare", tags=["cloudflare"])
app.include_router(pterodactyl.router, prefix="/api/pterodactyl", tags=["pterodactyl"])
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
