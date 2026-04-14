"""CDSIP Intelligence Service — FastAPI application.

This service is a placeholder for future defensive intelligence capabilities:
- Incident summarization
- Evidence correlation
- Risk analysis explanations
- Threat context enrichment (from local data only)

It does NOT:
- Execute tools directly
- Make offensive decisions
- Access external threat feeds without policy approval
- Bypass the Policy Governor
"""

from fastapi import FastAPI
from intel_service.config import settings
from intel_service.routes.health import router as health_router
from intel_service.routes.anomaly import router as anomaly_router

app = FastAPI(
    title="CDSIP Intelligence Service",
    description="Defensive security intelligence and analysis service",
    version=settings.version,
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url=None,
)

app.include_router(health_router)
app.include_router(anomaly_router)


@app.on_event("startup")
async def startup() -> None:
    """Service startup — initialize resources."""
    print(f"=== {settings.service_name} v{settings.version} ===")
    print(f"Environment: {settings.environment}")


@app.on_event("shutdown")
async def shutdown() -> None:
    """Service shutdown — cleanup resources."""
    print("Intelligence service shutting down")
