"""
Playbook Forge API - Main Application Entry Point

FastAPI backend for converting markdown/mermaid playbooks to visual IR flowcharts.
"""

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.auth import initialize_api_key
from api.crypto import get_cipher
from api.database import init_db
from api.seed import seed_db
from api.routers import export, integrations, parse, playbooks

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_api_key()
    get_cipher()
    init_db()
    seed_db()
    yield


app = FastAPI(
    title="Playbook Forge API",
    description="Convert markdown/mermaid playbooks to visual IR flowcharts",
    version="0.1.0",
    lifespan=lifespan,
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
app.include_router(integrations.router, prefix="/api", tags=["integrations"])


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler returning structured JSON errors."""
    logger.exception("Unhandled exception during request %s %s", request.method, request.url.path, exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": "Internal server error"
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
