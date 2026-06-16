from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database.connection import Base

class TrafficLog(Base):
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    src_ip = Column(String(45), index=True, nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_ip = Column(String(45), index=True, nullable=False)
    dst_port = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False)
    duration = Column(Float, nullable=False)
    total_packets = Column(Integer, nullable=False)
    total_bytes = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    predictions = relationship("ModelPrediction", back_populates="traffic_log", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="traffic_log", cascade="all, delete-orphan")
