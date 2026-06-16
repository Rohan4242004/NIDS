from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class NetworkLogBase(BaseModel):
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    duration: float
    total_packets: int
    total_bytes: int
    prediction_label: str
    confidence_score: float

class NetworkLogCreate(NetworkLogBase):
    pass

class NetworkLogResponse(NetworkLogBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True
