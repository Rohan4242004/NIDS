from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime
from app.database.connection import Base

class SystemLog(Base):
    __tablename__ = "system_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    module_name = Column(String(50), nullable=False)
    log_level = Column(String(15), default="INFO", nullable=False, index=True)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
