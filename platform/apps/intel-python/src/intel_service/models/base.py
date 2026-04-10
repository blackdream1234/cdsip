"""Base model definitions."""

from pydantic import BaseModel


class ServiceInfo(BaseModel):
    """Service metadata."""
    
    name: str = "cdsip-intel-service"
    version: str = "0.1.0"
    status: str = "placeholder"
    capabilities: list[str] = [
        "incident_summarization",
        "evidence_correlation",
        "risk_explanation",
    ]
    note: str = "This service is a V1 placeholder. Intelligence capabilities will be implemented in future phases."
