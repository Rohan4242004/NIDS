from sqlalchemy import Column, Integer, BigInteger, String, Float, DateTime
from datetime import datetime
from app.database.connection import Base

class NetworkLog(Base):
    __tablename__ = "network_logs"

    id = Column(BigInteger, primary_key=True, index=True)
    src_ip = Column(String(45), index=True, nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_ip = Column(String(45), index=True, nullable=False)
    dst_port = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False)
    duration = Column(Float, nullable=False)
    total_packets = Column(BigInteger, nullable=False)
    total_bytes = Column(BigInteger, nullable=False)
    prediction_label = Column(String(50), nullable=False)
    confidence_score = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
