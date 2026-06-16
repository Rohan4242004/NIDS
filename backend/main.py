import os
from typing import List
from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, Query, status
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from sqlalchemy.orm import Session

# Import DB setup
from app.database.connection import engine, Base, SessionLocal

# Import all 8 models to ensure tables are created
from app.models.user import User
from app.models.attack_type import AttackType
from app.models.traffic_log import TrafficLog
from app.models.model_prediction import ModelPrediction
from app.models.alert import Alert
from app.models.blocked_ip import BlockedIP
from app.models.system_log import SystemLog
from app.models.ml_model import MLModel

# Import routers
from app.api.auth import router as auth_router
from app.api.logs import router as logs_router
from app.api.alerts import router as alerts_router
from app.api.models import router as models_router
from app.api.dashboard import router as dashboard_router
from app.api.users import router as users_router
from app.api.system import router as system_router
from app.api.reports import router as reports_router

# Import Sniffer & Security settings
from app.packet_capture.sniffer import sniffer_daemon
from app.auth.jwt_handler import SECRET_KEY, ALGORITHM

# 1. Initialize Tables
Base.metadata.create_all(bind=engine)

# Seed default Attack Types reference and keep in sync
db = SessionLocal()
try:
    expected_attacks = {
        "Benign": {"id": 1, "default_severity": "LOW", "description": "Safe, normal connection network traffic."},
        "DDoS": {"id": 2, "default_severity": "CRITICAL", "description": "Distributed Denial of Service attack flooding ports."},
        "PortScan": {"id": 3, "default_severity": "MEDIUM", "description": "Scanning network addresses looking for open services."},
        "BruteForce": {"id": 4, "default_severity": "HIGH", "description": "SSH/FTP/HTTP Authentication brute force cracking."},
        "Botnet": {"id": 5, "default_severity": "CRITICAL", "description": "Botnet infected machine traffic."},
        "WebAttack": {"id": 6, "default_severity": "MEDIUM", "description": "Web vulnerability scanners or SQL/XSS injections."}
    }
    
    for name, info in expected_attacks.items():
        at = db.query(AttackType).filter((AttackType.id == info["id"]) | (AttackType.name == name)).first()
        if at:
            # Sync fields if mismatch
            updated = False
            if at.name != name:
                at.name = name
                updated = True
            if at.default_severity != info["default_severity"]:
                at.default_severity = info["default_severity"]
                updated = True
            if at.description != info["description"]:
                at.description = info["description"]
                updated = True
            if updated:
                db.add(at)
        else:
            new_at = AttackType(
                id=info["id"],
                name=name,
                description=info["description"],
                default_severity=info["default_severity"]
            )
            db.add(new_at)
    db.commit()
    print("[Main Startup] Attack types seeded and synchronized successfully.")

    # Seed default active ML model in DB if none exists
    model_count = db.query(MLModel).count()
    if model_count == 0:
        from datetime import datetime
        meta_path = os.path.join("ml_pipeline", "models", "model_metadata.json")
        model_name = "RandomForest"
        accuracy = 0.985
        f1_score = 0.984
        version = "v1.0.0"
        if os.path.exists(meta_path):
            try:
                import json
                with open(meta_path, "r") as f:
                    meta = json.load(f)
                    model_name = meta.get("best_model", "RandomForest")
                    accuracy = meta.get("accuracy", 0.985)
                    f1_score = meta.get("f1_score", 0.984)
            except Exception:
                pass
        
        new_model = MLModel(
            id=1,
            model_name=model_name,
            version=version,
            accuracy=accuracy,
            f1_score=f1_score,
            filepath=os.path.join("ml_pipeline", "models", "active_model.joblib"),
            is_active=True,
            deployed_at=datetime.utcnow()
        )
        db.add(new_model)
        db.commit()
        print("[Main Startup] Default ML Model seeded in database registry.")
except Exception as e:
    db.rollback()
    print(f"[Main Startup] Error seeding/synchronizing attack types and models: {e}")
finally:
    db.close()

# 2. FastAPI Setup
app = FastAPI(
    title="AI-Powered NIDS API",
    description="Real-time network traffic sniffer, machine learning classification engine, and alert logging api.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# 3. CORS Settings
cors_origins_raw = os.getenv("CORS_ORIGINS", "")
if cors_origins_raw:
    origins = [origin.strip() for origin in cors_origins_raw.split(",") if origin.strip()]
else:
    origins = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "http://localhost",
        "http://127.0.0.1"
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

main_loop = None

# 4. WebSocket Client Connection Pool
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"[WS Manager] Client connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        print(f"[WS Manager] Client disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                # Handle dead connections
                print(f"[WS Manager] Failed to send to socket: {e}")

manager = ConnectionManager()

# Setup sniffer broadcast callback to forward events to WebSocket clients
import asyncio
def forward_event_to_websockets(payload):
    global main_loop
    if main_loop and main_loop.is_running():
        asyncio.run_coroutine_threadsafe(manager.broadcast(payload), main_loop)
    else:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(manager.broadcast(payload))
        except RuntimeError:
            pass

sniffer_daemon.set_broadcast_callback(forward_event_to_websockets)

# 5. REST Route Registrations
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(logs_router, prefix="/api/v1/logs", tags=["Traffic Logs"])
app.include_router(alerts_router, prefix="/api/v1/alerts", tags=["Security Alerts"])
app.include_router(models_router, prefix="/api/v1/models", tags=["ML Models"])
app.include_router(dashboard_router, prefix="/api/v1/dashboard", tags=["Dashboard Analytics"])
app.include_router(users_router, prefix="/api/v1/users", tags=["User Management"])
app.include_router(system_router, prefix="/api/v1/system", tags=["System Diagnostics"])
app.include_router(reports_router, prefix="/api/v1/reports", tags=["Report Exporter"])

# 6. WebSocket Live Stream Endpoint
@app.websocket("/api/v1/ws/live")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(None)):
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
        
    try:
        # Validate JWT token passed as query param
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except JWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(websocket)
    try:
        # Keep connection open. WebSockets receive messages from client if needed
        while True:
            data = await websocket.receive_text()
            # ECHO / PING support
            await websocket.send_json({"event": "pong", "payload": data})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"[WS Endpoint] Connection error: {e}")
        manager.disconnect(websocket)

# 7. Lifespan Controls
@app.on_event("startup")
def startup_event():
    global main_loop
    try:
        main_loop = asyncio.get_running_loop()
    except RuntimeError:
        main_loop = asyncio.get_event_loop()

    # Retrieve interface from env
    interface = os.getenv("SNIFFER_INTERFACE", None)
    if not interface or interface.strip() == "":
        interface = None
    
    # Start capturing network traffic
    sniffer_daemon.start(interface=interface)

@app.on_event("shutdown")
def shutdown_event():
    # Terminate sniffer background worker
    sniffer_daemon.stop()

@app.get("/")
def read_root():
    return {
        "project": "AI-Powered Network Intrusion Detection System (NIDS)",
        "status": "Online",
        "api_docs": "/docs",
        "realtime_ws": "/api/v1/ws/live"
    }
