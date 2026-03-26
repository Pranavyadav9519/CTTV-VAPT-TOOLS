"""
Enhanced Configuration Management with Security Best Practices
Supports multiple environments (dev, staging, production)
All sensitive data comes from environment variables
"""

import os
import logging
from pathlib import Path
from datetime import timedelta
from typing import Optional


class Config:
    """Base configuration - use for all environments"""

    # Application info
    APP_NAME = "CCTV Vulnerability Assessment Tool (VAPT)"
    APP_VERSION = "2.0.0"
    APP_ENV = os.getenv("APP_ENV", "development")

    # Paths
    BASE_DIR = Path(__file__).parent.parent.parent.absolute()
    BACKEND_DIR = BASE_DIR / "backend"
    REPORTS_DIR = BACKEND_DIR / "reports"
    LOGS_DIR = BACKEND_DIR / "logs"
    DATA_DIR = BACKEND_DIR / "data"

    # Ensure directories exist
    for dir_path in [REPORTS_DIR, LOGS_DIR, DATA_DIR]:
        dir_path.mkdir(parents=True, exist_ok=True)

    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{BACKEND_DIR}/vapt_tool.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,  # Validate connections before use
        "pool_recycle": 300,  # Recycle connections every 5 minutes
        "pool_size": int(os.getenv("DB_POOL_SIZE", 10)),
        "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", 20)),
    }

    # Security Configuration
    SECRET_KEY = os.getenv("SECRET_KEY")
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY environment variable is required")

    # JWT Configuration
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

    # Session Configuration
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)

    # CORS Configuration
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

    # Redis Configuration
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    CELERY_BROKER_URL = REDIS_URL
    CELERY_RESULT_BACKEND = REDIS_URL

    # Celery Configuration
    CELERY_TASK_SERIALIZER = "json"
    CELERY_RESULT_SERIALIZER = "json"
    CELERY_ACCEPT_CONTENT = ["json"]
    CELERY_TASK_TRACK_STARTED = True
    CELERY_TASK_TIME_LIMIT = 30 * 60  # 30 minutes
    CELERY_TASK_SOFT_TIME_LIMIT = 25 * 60  # 25 minutes

    # Encryption Configuration
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
    if not ENCRYPTION_KEY:
        raise ValueError("ENCRYPTION_KEY environment variable is required")

    # Scanning Configuration
    MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", 3))
    MAX_SCAN_HOSTS = int(os.getenv("MAX_SCAN_HOSTS", 1024))
    SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", 3600))
    PORT_SCAN_TIMEOUT = int(os.getenv("PORT_SCAN_TIMEOUT", 10))
    NETWORK_SCAN_TIMEOUT = int(os.getenv("NETWORK_SCAN_TIMEOUT", 30))

    # Logging Configuration
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_FILE = LOGS_DIR / "vapt.log"

    # Audit Configuration
    AUDIT_LOG_KEY = os.getenv("AUDIT_LOG_KEY")
    if not AUDIT_LOG_KEY:
        raise ValueError("AUDIT_LOG_KEY environment variable is required for audit trail integrity")

    # Report Configuration
    REPORT_FORMATS = ["json", "html", "pdf"]
    REPORT_RETENTION_DAYS = int(os.getenv("REPORT_RETENTION_DAYS", 90))
    MAX_REPORT_SIZE_MB = int(os.getenv("MAX_REPORT_SIZE_MB", 100))

    # Feature Flags
    ENABLE_DEEP_SCAN = os.getenv("ENABLE_DEEP_SCAN", "false").lower() == "true"
    ENABLE_CREDENTIAL_TESTING = os.getenv("ENABLE_CREDENTIAL_TESTING", "false").lower() == "true"
    ENABLE_CLOUD_BACKUP = os.getenv("ENABLE_CLOUD_BACKUP", "false").lower() == "true"

    # S3 Configuration (optional)
    S3_BUCKET = os.getenv("S3_BUCKET")
    S3_REGION = os.getenv("S3_REGION", "us-east-1")
    S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY")
    S3_SECRET_KEY = os.getenv("S3_SECRET_KEY")

    @classmethod
    def validate(cls):
        """Validate critical configuration"""
        required_vars = ["SECRET_KEY", "JWT_SECRET_KEY", "ENCRYPTION_KEY", "AUDIT_LOG_KEY"]
        missing = [var for var in required_vars if not getattr(cls, var, None)]

        if missing:
            raise ValueError(f"Missing required configuration: {', '.join(missing)}")

        return True


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False


class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SESSION_COOKIE_SECURE = False
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    # Force HTTPS in production
    PREFERRED_URL_SCHEME = "https"


def get_config() -> Config:
    """Get configuration based on environment"""
    env = os.getenv("APP_ENV", "development").lower()

    config_map = {
        "development": DevelopmentConfig,
        "testing": TestingConfig,
        "production": ProductionConfig,
        "staging": ProductionConfig,
    }

    config_class = config_map.get(env, DevelopmentConfig)

    # Validate configuration
    config_class.validate()

    return config_class()


# Logging setup
def setup_logging():
    """Configure application logging"""
    config = get_config()

    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL),
        format=config.LOG_FORMAT,
        handlers=[
            logging.FileHandler(config.LOG_FILE),
            logging.StreamHandler()
        ]
    )

    # Set third-party library log levels
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)


# Validate on import
try:
    get_config()
except ValueError as e:
    logging.error(f"Configuration Error: {e}")
    raise
