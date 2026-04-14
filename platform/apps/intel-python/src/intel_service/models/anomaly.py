from pydantic import BaseModel, Field

class PortFinding(BaseModel):
    port: int
    protocol: str
    service_name: str | None = None
    state: str

class AnomalyRequest(BaseModel):
    asset_id: str
    current_ports: list[PortFinding]
    baseline_ports: list[int] = Field(default_factory=list)
    risk_score: float

class AnomalyResult(BaseModel):
    is_anomalous: bool
    anomaly_score: float
    reasons: list[str]
