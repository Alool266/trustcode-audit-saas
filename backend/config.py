from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    """Application settings from environment variables"""

    # Database
    database_url: str = "postgresql://sentinel:ChangeMe123!@postgres:5432/sentinel_wallet"

    # Redis
    redis_url: str = "redis://redis:6379"

    # AI Model
    model_path: str = "/app/models"
    confidence_threshold: float = 0.85
    anomaly_score_threshold: float = 0.75

    # Logging
    log_level: str = "INFO"

    # Feature flags
    enable_fraud_detection: bool = True
    enable_anomaly_monitoring: bool = True
    enable_compliance_audit: bool = True

    class Config:
        env_file = ".env"

settings = Settings()