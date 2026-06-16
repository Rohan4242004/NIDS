from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from app.database.connection import Base

class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    blocked_reason = Column(String(255), nullable=False)
    blocked_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    status = Column(String(15), default="ACTIVE", nullable=False)
