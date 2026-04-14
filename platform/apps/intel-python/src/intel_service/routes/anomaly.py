from fastapi import APIRouter
from intel_service.models.anomaly import AnomalyRequest, AnomalyResult

router = APIRouter(prefix="/api/v1/intel", tags=["intel"])

@router.post("/analyze-ports", response_model=AnomalyResult)
async def analyze_ports(request: AnomalyRequest) -> AnomalyResult:
    """Analyze incoming scan results for anomalous port exposure."""
    
    reasons = []
    anomaly_score = 0.0

    # High baseline risk implies lower tolerance for new ports
    tolerance = 2 if request.risk_score < 50 else 0

    new_ports = [
        p.port for p in request.current_ports 
        if p.port not in request.baseline_ports and p.state == "open"
    ]

    if new_ports:
        if len(new_ports) > tolerance:
            anomaly_score += 0.5
            reasons.append(f"Detected {len(new_ports)} new open ports beyond tolerance limits.")
        
        # Check for explicitly dangerous default ports
        dangerous_ports = {21, 23, 445, 3389}
        exposed_dangerous = dangerous_ports.intersection(new_ports)
        if exposed_dangerous:
            anomaly_score += 0.5
            reasons.append(f"Critical: Newly exposed dangerous administrative/legacy services on ports {exposed_dangerous}.")

    return AnomalyResult(
        is_anomalous=anomaly_score >= 0.5,
        anomaly_score=min(anomaly_score, 1.0),
        reasons=reasons
    )
