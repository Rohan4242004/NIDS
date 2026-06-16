import os
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "AI-Powered Network Intrusion Detection System (NIDS)"
    API_V1_STR: str = "/api/v1"
    
    # Security / JWT
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key-change-in-production-1234567890")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 120

    # Database
    # Defaulting to sqlite for easy local deployment, but supporting mysql+pymysql override
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./nids.db")
    
    # Network Sniffer Interface
    # If None, Scapy will sniff on the default interface
    SNIFFER_INTERFACE: Optional[str] = os.getenv("SNIFFER_INTERFACE", None)

    # SMTP / Email Notification configuration
    SMTP_HOST: str = os.getenv("SMTP_HOST", "localhost")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_TLS: bool = os.getenv("SMTP_TLS", "True").lower() == "true"
    SMTP_USERNAME: Optional[str] = os.getenv("SMTP_USERNAME", None)
    SMTP_PASSWORD: Optional[str] = os.getenv("SMTP_PASSWORD", None)
    SMTP_FROM_EMAIL: str = os.getenv("SMTP_FROM_EMAIL", "alerts@nids.security")
    SMTP_TO_EMAIL: str = os.getenv("SMTP_TO_EMAIL", "admin@nids.security")

    class Config:
        case_sensitive = True
        env_file = ".env"

settings = Settings()
