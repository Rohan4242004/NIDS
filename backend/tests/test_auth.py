import pytest
from app.models.user import User
from app.core.security import get_password_hash

def test_register_first_user_as_admin(client, db):
    # Register first user
    response = client.post("/api/v1/auth/register", json={
        "username": "adminuser",
        "email": "admin@nids.security",
        "password": "password123",
        "role": "operator"  # First user gets promoted to admin regardless
    })
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "adminuser"
    assert data["email"] == "admin@nids.security"
    assert data["role"] == "admin" # promoted

def test_register_second_user_keeps_role(client, db):
    # Register first (will be admin)
    client.post("/api/v1/auth/register", json={
        "username": "adminuser",
        "email": "admin@nids.security",
        "password": "password123"
    })
    
    # Register second user
    response = client.post("/api/v1/auth/register", json={
        "username": "operatoruser",
        "email": "op@nids.security",
        "password": "password123",
        "role": "operator"
    })
    assert response.status_code == 201
    data = response.json()
    assert data["role"] == "operator" # kept

def test_login_successful(client, db):
    # Seed user
    hashed = get_password_hash("password123")
    user = User(username="testuser", email="test@nids.security", password_hash=hashed, role="operator")
    db.add(user)
    db.commit()
    
    # Login
    response = client.post("/api/v1/auth/token", data={
        "username": "testuser",
        "password": "password123"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_login_invalid_credentials(client, db):
    response = client.post("/api/v1/auth/token", data={
        "username": "nonexistent",
        "password": "wrongpassword"
    })
    assert response.status_code == 401

def test_protected_routes(client, db):
    # Seed user
    hashed = get_password_hash("password123")
    user = User(username="testuser", email="test@nids.security", password_hash=hashed, role="operator")
    db.add(user)
    db.commit()
    
    # Check /me fails without credentials
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401
    
    # Login to get token
    login_res = client.post("/api/v1/auth/token", data={
        "username": "testuser",
        "password": "password123"
    })
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Check /me succeeds with credentials
    res = client.get("/api/v1/auth/me", headers=headers)
    assert res.status_code == 200
    assert res.json()["username"] == "testuser"
