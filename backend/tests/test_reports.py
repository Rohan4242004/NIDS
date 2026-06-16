import pytest
import json
from app.models.user import User
from app.models.traffic_log import TrafficLog
from app.core.security import get_password_hash

def test_reports_export_streaming(client, db):
    # 1. Seed admin user
    hashed = get_password_hash("password123")
    user = User(username="adminuser", email="admin@nids.security", password_hash=hashed, role="admin")
    db.add(user)
    
    # 2. Seed some traffic logs
    log = TrafficLog(
        src_ip="192.168.1.50", src_port=1234, dst_ip="8.8.8.8", dst_port=80,
        protocol="TCP", duration=1.23, total_packets=12, total_bytes=6400
    )
    db.add(log)
    db.commit()
    
    # Login
    login_res = client.post("/api/v1/auth/token", data={
        "username": "adminuser",
        "password": "password123"
    })
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test 1: Export CSV
    response_csv = client.get("/api/v1/reports/export?report_type=traffic&export_format=csv", headers=headers)
    assert response_csv.status_code == 200
    assert response_csv.headers["content-type"] == "text/csv; charset=utf-8"
    
    csv_data = response_csv.text
    assert "Log ID,Source IP,Source Port,Destination IP" in csv_data
    assert "192.168.1.50" in csv_data
    assert "6400" in csv_data
    
    # Test 2: Export JSON
    response_json = client.get("/api/v1/reports/export?report_type=traffic&export_format=json", headers=headers)
    assert response_json.status_code == 200
    assert response_json.headers["content-type"] == "application/json"
    
    # Parse json to make sure it's valid
    parsed_json = json.loads(response_json.text)
    assert isinstance(parsed_json, list)
    assert len(parsed_json) == 1
    assert parsed_json[0]["src_ip"] == "192.168.1.50"
    assert parsed_json[0]["total_bytes"] == 6400
    
def test_reports_export_unauthorized_for_operators(client, db):
    # Seed operator user
    hashed = get_password_hash("password123")
    user = User(username="operatoruser", email="op@nids.security", password_hash=hashed, role="operator")
    db.add(user)
    db.commit()
    
    # Login
    login_res = client.post("/api/v1/auth/token", data={
        "username": "operatoruser",
        "password": "password123"
    })
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Fetch export (should fail since export requires admin role)
    response = client.get("/api/v1/reports/export?report_type=traffic&export_format=csv", headers=headers)
    assert response.status_code == 403
