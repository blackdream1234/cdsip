import pytest
from fastapi.testclient import TestClient
from intel_service.main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_anomaly_detection_safe():
    payload = {
        "asset_id": "test_asset_001",
        "current_ports": [
            {"port": 80, "protocol": "tcp", "service_name": "http", "state": "open"},
            {"port": 443, "protocol": "tcp", "service_name": "https", "state": "open"}
        ],
        "baseline_ports": [80, 443],
        "risk_score": 10.0
    }
    response = client.post("/api/v1/intel/analyze-ports", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_anomalous"] is False
    assert data["anomaly_score"] == 0.0
    assert len(data["reasons"]) == 0

def test_anomaly_detection_dangerous_ports():
    payload = {
        "asset_id": "test_asset_002",
        "current_ports": [
            {"port": 80, "protocol": "tcp", "service_name": "http", "state": "open"},
            {"port": 23, "protocol": "tcp", "service_name": "telnet", "state": "open"}
        ],
        "baseline_ports": [80],
        "risk_score": 80.0
    }
    response = client.post("/api/v1/intel/analyze-ports", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_anomalous"] is True
    assert data["anomaly_score"] >= 0.5
    assert any("23" in reason for reason in data["reasons"])

def test_anomaly_detection_tolerance_breach():
    # Adding many new unknown ports should trip the threshold
    payload = {
        "asset_id": "test_asset_003",
        "current_ports": [
            {"port": 80, "protocol": "tcp", "service_name": "http", "state": "open"},
            {"port": 8080, "protocol": "tcp", "state": "open"},
            {"port": 8081, "protocol": "tcp", "state": "open"},
            {"port": 8082, "protocol": "tcp", "state": "open"}
        ],
        "baseline_ports": [80],
        # If risk_score > 50, tolerance is 0, so 3 new ports immediately fails
        "risk_score": 60.0
    }
    response = client.post("/api/v1/intel/analyze-ports", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_anomalous"] is True
    assert data["anomaly_score"] >= 0.5
    assert any("tolerance limits" in reason for reason in data["reasons"])
