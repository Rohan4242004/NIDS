from sqlalchemy import Column, Integer, String
from app.database.connection import Base

class AttackType(Base):
    __tablename__ = "attack_types"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), unique=True, index=True, nullable=False)
    description = Column(String(255), nullable=True)
    default_severity = Column(String(15), default="INFO", nullable=False)
