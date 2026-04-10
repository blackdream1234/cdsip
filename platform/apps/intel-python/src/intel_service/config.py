"""Configuration for the intelligence service."""

import os


class Settings:
    """Service configuration loaded from environment variables."""

    host: str = os.getenv("INTEL_SERVICE_HOST", "0.0.0.0")
    port: int = int(os.getenv("INTEL_SERVICE_PORT", "8081"))
    database_url: str = os.getenv("DATABASE_URL", "")
    environment: str = os.getenv("CDSIP_ENVIRONMENT", "development")
    service_name: str = "cdsip-intel-service"
    version: str = "0.1.0"


settings = Settings()
