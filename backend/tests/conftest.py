import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from main import app
from app.database.connection import Base, get_db
from app.models.attack_type import AttackType

# 1. Setup in-memory test database
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    # Create all tables in memory
    Base.metadata.create_all(bind=engine)
    
    # Seed AttackType reference data
    db = TestingSessionLocal()
    try:
        expected_attacks = {
            "Benign": {"id": 1, "default_severity": "LOW", "description": "Safe traffic."},
            "DDoS": {"id": 2, "default_severity": "CRITICAL", "description": "DDoS attack."},
            "PortScan": {"id": 3, "default_severity": "MEDIUM", "description": "Port scan."},
            "BruteForce": {"id": 4, "default_severity": "HIGH", "description": "Brute force."},
            "Botnet": {"id": 5, "default_severity": "CRITICAL", "description": "Botnet."},
            "WebAttack": {"id": 6, "default_severity": "MEDIUM", "description": "Web attack."}
        }
        for name, info in expected_attacks.items():
            db.add(AttackType(
                id=info["id"],
                name=name,
                description=info["description"],
                default_severity=info["default_severity"]
            ))
        db.commit()
    finally:
        db.close()
        
    yield
    # Drop all tables after session
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def db():
    # Database session with automatic rollback at the end of each test
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture
def client(db):
    # Override get_db dependency
    def override_get_db():
        try:
            yield db
        finally:
            pass
            
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
