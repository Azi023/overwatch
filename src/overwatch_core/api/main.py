"""
Update for main.py - Add feedback router registration.

Add this import and router registration to your existing main.py
"""

# Add this import at the top with other route imports:
# from .routes.feedback import router as feedback_router

# Add this line in your router registration section:
# app.include_router(feedback_router)

# Full example of updated main.py:

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import routers
from .routes.targets import router as targets_router
from .routes.scans import router as scans_router
from .routes.feedback import router as feedback_router  # NEW

# Create app
app = FastAPI(
    title="Overwatch API",
    description="AI-Powered Penetration Testing Platform",
    version="0.2.0",  # Bump version for learning features
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(targets_router)
app.include_router(scans_router)
app.include_router(feedback_router)  # NEW - Learning/feedback endpoints


@app.get("/")
async def root():
    return {
        "name": "Overwatch API",
        "version": "0.2.0",
        "status": "running",
        "features": {
            "scanning": True,
            "learning": True,  # NEW
            "feedback": True   # NEW
        }
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "database": "connected",
        "redis": "connected",
        "learning_enabled": True  # NEW
    }