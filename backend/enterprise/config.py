"""
VAPT Tool - Enterprise Configuration
Production-grade configuration management for CCTV/DVR VAPT platform
"""

import os
from pathlib import Path
from datetime import timedelta
from typing import Dict, List, Any


class Config:
    """Base configuration class with validation and security defaults"""

    APP_NAME = "VAPT Platform"
    APP_VERSION = "2.0.0"
    APP_DESCRIPTION = "Enterprise Vulnerability Assessment Platform for CCTV/DVR Systems"

    BASE_DIR = Path(__file__).parent.parent.absolute()
    REPORTS_DIR = BASE_DIR / "reports"
    LOGS_DIR = BASE_DIR / "logs"
    DATA_DIR = BASE_DIR / "data"

    SECRET_KEY = os.environ.get("SECRET_KEY", "")

    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRE = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRE = timedelta(days=30)
    JWT_TOKEN_LOCATION = ["headers"]
    JWT_HEADER_NAME = "Authorization"
    JWT_HEADER_TYPE = "Bearer"

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "postgresql://vaptuser:vaptpass@localhost:5432/vaptdb"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_size": 10,
        "max_overflow": 20,
        "pool_pre_ping": True,
        "pool_recycle": 300,
        "pool_timeout": 30,
    }

    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

    CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", REDIS_URL)
    CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", REDIS_URL)
    CELERY_TASK_SERIALIZER = "json"
    CELERY_RESULT_SERIALIZER = "json"
    CELERY_ACCEPT_CONTENT = ["json"]
    CELERY_TIMEZONE = "UTC"
    CELERY_ENABLE_UTC = True
    CELERY_TASK_TRACK_STARTED = True
    CELERY_TASK_TIME_LIMIT = 3600
    CELERY_TASK_SOFT_TIME_LIMIT = 3000

    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    CORS_ORIGINS = os.environ.get(
        "CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")

    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URL = os.environ.get("REDIS_URL", "memory://")
    RATELIMIT_STRATEGY = "fixed-window"
    RATELIMIT_DEFAULT = "100/hour"
    RATELIMIT_HEADERS_ENABLED = True

    SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", 30))
    MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", 5))
    PORT_SCAN_TIMEOUT = int(os.environ.get("PORT_SCAN_TIMEOUT", 10))
    NETWORK_SCAN_TIMEOUT = int(os.environ.get("NETWORK_SCAN_TIMEOUT", 60))
    MAX_HOSTS_PER_SCAN = int(os.environ.get("MAX_HOSTS_PER_SCAN", 256))
    MAX_PORTS_PER_HOST = int(os.environ.get("MAX_PORTS_PER_HOST", 1000))

    CCTV_PORTS = [
        80, 443, 554, 8080, 8000, 8443,
        37777, 37778, 34567, 34599, 9000,
        8899, 5000, 6036, 8200, 10554, 8554,
    ]

    CCTV_OUI_PREFIXES = {
        "00:40:8C": "Axis Communications",
        "AC:CC:8E": "Axis Communications",
        "00:1E:06": "WIBRAIN",
        "28:57:BE": "Hangzhou Hikvision",
        "C0:56:E3": "Hangzhou Hikvision",
        "54:C4:15": "Hangzhou Hikvision",
        "44:19:B6": "Hangzhou Hikvision",
        "C4:2F:90": "Hangzhou Hikvision",
        "A4:14:37": "Hangzhou Hikvision",
        "E0:50:8B": "Zhejiang Dahua",
        "3C:EF:8C": "Zhejiang Dahua",
        "40:F4:FD": "Zhejiang Dahua",
        "90:02:A9": "Zhejiang Dahua",
        "B0:C5:54": "D-Link",
        "38:83:45": "TP-Link",
    }

    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
    if not ENCRYPTION_KEY:
        from cryptography.fernet import Fernet
        ENCRYPTION_KEY = Fernet.generate_key().decode()

    IDEMPOTENCY_TTL = 86400

    WORKER_MAX_MEMORY_MB = int(os.environ.get("WORKER_MAX_MEMORY_MB", 512))
    WORKER_MAX_CPU_PERCENT = int(os.environ.get("WORKER_MAX_CPU_PERCENT", 80))

    PRIVATE_NETWORKS = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
    ]

    @classmethod
    def validate(cls) -> List[str]:
        errors = []
        if not cls.SECRET_KEY:
            errors.append("SECRET_KEY is required")
        elif len(cls.SECRET_KEY) < 32:
            errors.append("SECRET_KEY must be at least 32 characters")
        if cls.SCAN_TIMEOUT <= 0:
            errors.append("SCAN_TIMEOUT must be positive")
        if cls.PORT_SCAN_TIMEOUT <= 0:
            errors.append("PORT_SCAN_TIMEOUT must be positive")
        if cls.MAX_CONCURRENT_SCANS <= 0:
            errors.append("MAX_CONCURRENT_SCANS must be positive")
        return errors

    @classmethod
    def load_from_env(cls):
        """Return the config class (already loaded from env at definition time)."""
        return cls

    @classmethod
    def as_flask_dict(cls) -> Dict[str, Any]:
        """Return all uppercase class attributes as a dict suitable for Flask config."""
        return {
            key: getattr(cls, key)
            for key in dir(cls)
            if key.isupper() and not key.startswith("_")
        }

    @classmethod
    def init_directories(cls):
        for directory in [cls.REPORTS_DIR, cls.LOGS_DIR, cls.DATA_DIR]:
            directory.mkdir(parents=True, exist_ok=True)


class DevelopmentConfig(Config):
    DEBUG = True
    LOG_LEVEL = "DEBUG"
    RATELIMIT_ENABLED = False
    SQLALCHEMY_ECHO = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    RATELIMIT_ENABLED = True


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_ENGINE_OPTIONS = {}
    RATELIMIT_ENABLED = False


config_by_name: Dict[str, Any] = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": ProductionConfig,
}
