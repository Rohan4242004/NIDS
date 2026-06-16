from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from app.schemas.log import NetworkLogResponse

class AlertBase(BaseModel):
    log_id: int
    severity: str
    attack_type: str
    status: Optional[str] = "UNRESOLVED"
    notes: Optional[str] = None

class AlertCreate(AlertBase):
    pass

class AlertUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None

class AlertResponse(AlertBase):
    id: int
    generated_at: datetime
    network_log: Optional[NetworkLogResponse] = None

    class Config:
        from_attributes = True
