"""
Overwatch V2 FastAPI application entry-point.
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes.engagements import router as engagements_router
from .routes.feedback import router as feedback_router
from .routes.scans import router as scans_router
from .routes.targets import router as targets_router

logger = logging.getLogger(__name__)

# ──────────────────────────── Lifespan ────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup / shutdown lifecycle."""
    logger.info("Overwatch V2 starting up")
    try:
        from ..persistence.database import init_db
        await init_db()
        logger.info("Database initialised successfully")
    except Exception as exc:
        logger.error("Database initialisation failed: %s", exc)
        # Do not hard-crash — database may be unavailable in test mode
    yield
    logger.info("Overwatch V2 shutting down")


# ──────────────────────────── App ────────────────────────────

app = FastAPI(
    title="Overwatch API",
    version="2.0.0",
    description=(
        "AI-Powered Penetration Testing Platform — "
        "multi-agent, self-learning, CVSS-scored findings."
    ),
    lifespan=lifespan,
)

# ──────────────────────────── Middleware ────────────────────────────

_cors_origins_raw = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:8080,http://localhost:5173")
_cors_origins = [o.strip() for o in _cors_origins_raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────── Routers ────────────────────────────

API_V1 = "/api/v1"

app.include_router(targets_router,     prefix=API_V1)
app.include_router(scans_router,       prefix=API_V1)
app.include_router(engagements_router, prefix=API_V1)
app.include_router(feedback_router,    prefix=API_V1)

# ──────────────────────────── Health endpoints ────────────────────────────

@app.get("/", tags=["meta"])
async def root() -> Dict[str, Any]:
    """API root — returns health info and feature flags."""
    return {
        "service": "Overwatch API",
        "version": "2.0.0",
        "status": "ok",
        "feature_flags": {
            "agent_system": True,
            "attack_graph": True,
            "five_layer_memory": True,
            "validation_engine": True,
            "reporting_engine": True,
            "cost_optimisation": True,
            "anthropic_key_configured": bool(os.environ.get("ANTHROPIC_API_KEY")),
        },
        "docs": "/docs",
        "redoc": "/redoc",
    }


@app.get("/health", tags=["meta"])
async def health_check() -> Dict[str, Any]:
    """Lightweight liveness probe."""
    db_ok = False
    try:
        from ..persistence.database import AsyncSessionLocal
        from sqlalchemy import text
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        db_ok = True
    except Exception as exc:
        logger.warning("Health check DB ping failed: %s", exc)

    return {
        "status": "healthy" if db_ok else "degraded",
        "database": "ok" if db_ok else "unavailable",
    }
