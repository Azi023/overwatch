"""
FastAPI application entry point.
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.overwatch_core.api.routes import targets
from src.overwatch_core.persistence.database import init_db, engine

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown events."""
    # Startup
    logger.info("Starting Overwatch API...")
    await init_db()
    logger.info("Database initialized")

    yield

    # Shutdown
    logger.info("Shutting down Overwatch API...")
    await engine.dispose()
    logger.info("Database connections closed")


# Create FastAPI app
app = FastAPI(
    title="Overwatch API",
    description="AI-Powered Penetration Testing Platform",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Include router (add this after CORS middleware, before @app.get("/"))
app.include_router(targets.router, prefix="/api/v1/targets", tags=["Targets"])

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Overwatch API",
        "version": "0.1.0",
        "status": "operational",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.overwatch_core.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
