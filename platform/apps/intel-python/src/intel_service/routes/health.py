"""Health check routes for the intelligence service."""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check() -> dict:
    """Unauthenticated health check."""
    return {
        "status": "healthy",
        "service": "cdsip-intel-service",
        "version": "0.1.0",
    }


@router.get("/ready")
async def readiness_check() -> dict:
    """Readiness probe."""
    return {"ready": True}
