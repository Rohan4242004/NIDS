from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional, List

# --- AUTH SCHEMAS ---
class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: Optional[str] = "operator"

class UserCreate(UserBase):
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(UserBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None


# --- TRAFFIC LOG SCHEMAS ---
class TrafficLogBase(BaseModel):
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    duration: float
    total_packets: int
    total_bytes: int

class TrafficLogResponse(TrafficLogBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


# --- ATTACK TYPE SCHEMA ---
class AttackTypeResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    default_severity: str

    class Config:
        from_attributes = True


# --- MODEL PREDICTION SCHEMA ---
class ModelPredictionResponse(BaseModel):
    id: int
    log_id: int
    model_version: str
    predicted_attack_type_id: int
    confidence_score: float
    features_computed: Optional[dict] = None
    prediction_time: datetime

    class Config:
        from_attributes = True


# --- ML MODEL SCHEMAS ---
class MLModelResponse(BaseModel):
    id: int
    model_name: str
    version: str
    accuracy: float
    f1_score: float
    filepath: str
    is_active: bool
    deployed_at: datetime

    class Config:
        from_attributes = True


# --- ALERT SCHEMAS ---
class AlertBase(BaseModel):
    log_id: int
    attack_type_id: int
    prediction_id: Optional[int] = None
    severity: str
    status: Optional[str] = "UNRESOLVED"
    notes: Optional[str] = None

class AlertCreate(AlertBase):
    pass

class AlertUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None

class AlertHistoryResponse(BaseModel):
    id: int
    alert_id: int
    status: str
    notes: Optional[str] = None
    changed_by: str
    created_at: datetime

    class Config:
        from_attributes = True

class AlertResponse(AlertBase):
    id: int
    created_at: datetime
    traffic_log: Optional[TrafficLogResponse] = None
    attack_type: Optional[AttackTypeResponse] = None
    history: Optional[List[AlertHistoryResponse]] = None

    class Config:
        from_attributes = True


# --- BLOCKED IP SCHEMAS ---
class BlockedIPBase(BaseModel):
    ip_address: str
    blocked_reason: str
    expires_at: Optional[datetime] = None

class BlockedIPResponse(BlockedIPBase):
    id: int
    blocked_at: datetime
    status: str

    class Config:
        from_attributes = True


# --- SYSTEM LOG SCHEMA ---
class SystemLogResponse(BaseModel):
    id: int
    module_name: str
    log_level: str
    message: str
    created_at: datetime

    class Config:
        from_attributes = True


# --- KPI SUMMARY SCHEMA ---
class KPICard(BaseModel):
    title: str
    value: str
    change: str
    type: str  # positive, negative, neutral

class DashboardSummary(BaseModel):
    total_connections: int
    active_threats: int
    avg_latency_ms: float
    threat_rate: float
    kpi_cards: List[KPICard]
    threat_distribution: List[dict]
    throughput_series: List[dict]


# --- FLOW INGEST SCHEMA ---
class FlowIngest(BaseModel):
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    duration: float
    total_packets: int
    total_bytes: int
    features: List[float]


# --- USER MANAGEMENT SCHEMAS ---
class UserRoleUpdate(BaseModel):
    role: str


