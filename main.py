"""
Sentinel AI
Application Entry Point
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.health import router as health_router
from app.api.investigations import router as investigations_router
from app.config import settings


# ============================================================
# Paths
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
WEB_DIRECTORY = BASE_DIR / "web"
INDEX_FILE = WEB_DIRECTORY / "index.html"


# ============================================================
# Application Lifecycle
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifecycle."""
    yield


# ============================================================
# FastAPI Application
# ============================================================

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Email threat detection and digital-forensics "
        "investigation platform."
    ),
    lifespan=lifespan,
)


# ============================================================
# API Routers
# ============================================================

app.include_router(health_router)
app.include_router(investigations_router)


# ============================================================
# Frontend Static Files
# ============================================================

app.mount(
    "/assets",
    StaticFiles(directory=WEB_DIRECTORY),
    name="assets",
)


# ============================================================
# Frontend Routes
# ============================================================

@app.get("/style.css", include_in_schema=False)
def stylesheet() -> FileResponse:
    """Serve dashboard stylesheet."""
    return FileResponse(
        WEB_DIRECTORY / "style.css",
        media_type="text/css",
    )


@app.get("/app.js", include_in_schema=False)
def javascript() -> FileResponse:
    """Serve dashboard JavaScript."""
    return FileResponse(
        WEB_DIRECTORY / "app.js",
        media_type="application/javascript",
    )


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    """Serve the Sentinel AI dashboard."""
    return FileResponse(INDEX_FILE)


# ============================================================
# API Root
# ============================================================

@app.get("/api", tags=["System"])
def api_root() -> dict[str, str]:
    """API status endpoint."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "operational",
    }