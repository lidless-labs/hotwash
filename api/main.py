"""
Playbook Forge API - Main Application Entry Point

FastAPI backend for converting markdown/mermaid playbooks to visual IR flowcharts.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.database import init_db
from api.seed import seed_db
from api.routers import export, parse, playbooks

app = FastAPI(
    title="Playbook Forge API",
    description="Convert markdown/mermaid playbooks to visual IR flowcharts",
    version="0.1.0"
)

# CORS middleware for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5177",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(parse.router, prefix="/api", tags=["parse"])
app.include_router(playbooks.router, prefix="/api", tags=["playbooks"])
app.include_router(export.router, prefix="/api", tags=["export"])


@app.on_event("startup")
def startup_event():
    init_db()
    seed_db()


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler returning structured JSON errors."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc)
        }
    )


@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "ok", "service": "playbook-forge-api"}


@app.get("/api/health")
async def health():
    """Detailed health check endpoint."""
    return {
        "status": "healthy",
        "service": "playbook-forge-api",
        "version": "0.1.0"
    }
