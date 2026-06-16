from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime
from datetime import datetime
from app.database.connection import Base

class MLModel(Base):
    __tablename__ = "ml_models"

    id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String(100), nullable=False)
    version = Column(String(20), unique=True, index=True, nullable=False)
    accuracy = Column(Float, nullable=False)
    f1_score = Column(Float, nullable=False)
    filepath = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=False, nullable=False)
    deployed_at = Column(DateTime, default=datetime.utcnow)
