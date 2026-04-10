"""Health check routes."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check() -> dict:
    """Health check endpoint — unauthenticated."""
    return {
        "status": "healthy",
        "service": "cdsip-intel-service",
        "version": "0.1.0",
    }
