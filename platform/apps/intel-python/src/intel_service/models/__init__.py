"""Base Pydantic models for the intelligence service."""

from pydantic import BaseModel
from datetime import datetime
from uuid import UUID


class BaseResponse(BaseModel):
    """Base response model with common fields."""
    
    class Config:
        from_attributes = True


class AnalysisRequest(BaseModel):
    """Placeholder for future analysis requests."""
    
    asset_id: UUID | None = None
    incident_id: UUID | None = None
    evidence_ids: list[UUID] = []
    analysis_type: str = "summary"


class AnalysisResponse(BaseModel):
    """Placeholder for future analysis responses."""
    
    analysis_id: UUID
    analysis_type: str
    result: dict
    confidence: float
    rationale: str
    evidence_references: list[UUID]
    created_at: datetime
