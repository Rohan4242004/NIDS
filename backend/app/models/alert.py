from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database.connection import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    log_id = Column(Integer, ForeignKey("traffic_logs.id", ondelete="CASCADE"), nullable=False)
    attack_type_id = Column(Integer, ForeignKey("attack_types.id"), nullable=False)
    prediction_id = Column(Integer, ForeignKey("model_predictions.id", ondelete="SET NULL"), nullable=True)
    severity = Column(String(15), default="MEDIUM", nullable=False, index=True)
    status = Column(String(20), default="UNRESOLVED", nullable=False, index=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    traffic_log = relationship("TrafficLog", back_populates="alerts")
    attack_type = relationship("AttackType")
    prediction = relationship("ModelPrediction")
    history = relationship("AlertHistory", back_populates="alert", cascade="all, delete-orphan")
