from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database.connection import Base

class ModelPrediction(Base):
    __tablename__ = "model_predictions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    log_id = Column(Integer, ForeignKey("traffic_logs.id", ondelete="CASCADE"), nullable=False)
    model_version = Column(String(30), nullable=False)
    predicted_attack_type_id = Column(Integer, ForeignKey("attack_types.id"), nullable=False)
    confidence_score = Column(Float, nullable=False)
    features_computed = Column(JSON, nullable=True)
    prediction_time = Column(DateTime, default=datetime.utcnow)

    traffic_log = relationship("TrafficLog", back_populates="predictions")
    attack_type = relationship("AttackType")
