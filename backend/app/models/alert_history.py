from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database.connection import Base

class AlertHistory(Base):
    __tablename__ = "alert_histories"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    status = Column(String(20), nullable=False)
    notes = Column(Text, nullable=True)
    changed_by = Column(String(50), default="SYSTEM", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    alert = relationship("Alert", back_populates="history")
