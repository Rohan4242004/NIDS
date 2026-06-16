import pytest
from app.models.user import User
from app.models.traffic_log import TrafficLog
from app.core.security import get_password_hash

def test_dashboard_summary_aggregates(client, db):
    # 1. Register admin and authenticate
    hashed = get_password_hash("password123")
    user = User(username="adminuser", email="admin@nids.security", password_hash=hashed, role="admin")
    db.add(user)
    
    # 2. Add traffic logs
    log1 = TrafficLog(
        src_ip="192.168.1.15", src_port=53, dst_ip="8.8.8.8", dst_port=53,
        protocol="UDP", duration=0.01, total_packets=2, total_bytes=150
    )
    log2 = TrafficLog(
        src_ip="192.168.1.20", src_port=443, dst_ip="1.1.1.1", dst_port=443,
        protocol="TCP", duration=0.03, total_packets=5, total_bytes=1200
    )
    db.add(log1)
    db.add(log2)
    db.commit()
    
    # Login
    login_res = client.post("/api/v1/auth/token", data={
        "username": "adminuser",
        "password": "password123"
    })
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Fetch summary
    response = client.get("/api/v1/dashboard/summary", headers=headers)
    assert response.status_code == 200
    data = response.json()
    
    assert data["total_connections"] == 2
    assert data["active_threats"] == 0
    assert len(data["throughput_series"]) == 10
    
    # Verify KPI card formatting
    kpis = {card["title"]: card["value"] for card in data["kpi_cards"]}
    assert "Total Connections" in kpis
    assert kpis["Total Connections"] == "2"
    assert "Avg Extraction Latency" in kpis
    # Average duration = (0.01 + 0.03) / 2 = 0.02s = 20.0 ms
    assert kpis["Avg Extraction Latency"] == "20.0 ms"
