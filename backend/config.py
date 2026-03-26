"""
VAPT Tool Configuration
Enterprise-grade configuration management for CCTV/DVR vulnerability assessment
"""

import importlib.util
import os
import logging
from datetime import timedelta
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)


class Config:
    """Base configuration class with validation"""

    # Application Settings
    APP_NAME = "VAPT Tool"
    APP_VERSION = "1.0.0"
    APP_DESCRIPTION = (
        "Vulnerability Assessment & Penetration Testing "
        "for CCTV/DVR Systems"
    )

    # Paths
    BASE_DIR = Path(__file__).parent.absolute()
    REPORTS_DIR = BASE_DIR / "reports"
    LOGS_DIR = BASE_DIR / "logs"
    DATA_DIR = BASE_DIR / "data"

    # Database - Use environment variables for security
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{BASE_DIR}/vapt_tool.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,  # Test connections before use
        "pool_recycle": 300,  # Recycle connections every 5 minutes
    }

    # Security - Require SECRET_KEY from environment
    SECRET_KEY = os.environ.get("SECRET_KEY")
    SESSION_COOKIE_SECURE = (
        os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true"
    )
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # JWT Configuration
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRE = timedelta(
        hours=int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_HOURS", 1))
    )
    JWT_REFRESH_TOKEN_EXPIRE = timedelta(
        days=int(os.environ.get("JWT_REFRESH_TOKEN_EXPIRE_DAYS", 30))
    )

    # Scanning Configuration
    SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", 30))  # seconds per host
    MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", 5))
    PORT_SCAN_TIMEOUT = int(os.environ.get("PORT_SCAN_TIMEOUT", 10))
    NETWORK_SCAN_TIMEOUT = int(
        os.environ.get("NETWORK_SCAN_TIMEOUT", 60)
    )  # seconds for network discovery

    # Retry Configuration
    MAX_RETRIES = int(os.environ.get("MAX_RETRIES", 3))
    RETRY_BACKOFF_FACTOR = float(os.environ.get("RETRY_BACKOFF_FACTOR", 0.3))

    # Common CCTV/DVR Ports
    CCTV_PORTS = [
        80,  # HTTP Web Interface
        443,  # HTTPS Web Interface
        554,  # RTSP Streaming
        8080,  # Alternative HTTP
        8000,  # Alternative HTTP
        8443,  # Alternative HTTPS
        37777,  # Dahua
        37778,  # Dahua
        34567,  # XMEye/Generic Chinese DVR
        34599,  # XMEye/Generic Chinese DVR
        9000,  # Hikvision
        8899,  # Hikvision
        5000,  # Synology/Generic
        6036,  # Hikvision SDK
        8200,  # Hikvision
        10554,  # Alternative RTSP
        8554,  # Alternative RTSP
    ]

    # CCTV Manufacturer OUI Prefixes (MAC address prefixes)
    CCTV_OUI_PREFIXES = {
        "00:40:8C": "Axis Communications",
        "AC:CC:8E": "Axis Communications",
        "00:1E:06": "WIBRAIN",
        "00:12:17": "Cisco-Linksys",
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
        "1C:5F:2B": "D-Link",
        "00:80:77": "Brother Industries",
        "00:0A:EB": "Shenzhen TP-Link",
        "38:83:45": "TP-Link",
    }

    # Rate Limiting
    RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", 100))
    RATE_LIMIT_WINDOW = timedelta(
        hours=int(
            os.environ.get("RATE_LIMIT_WINDOW_HOURS", 1)
        )
    )

    # Logging
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # CORS Configuration
    CORS_ORIGINS = os.environ.get(
        "CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")

    # Required Dependencies
    REQUIRED_PACKAGES = [
        "flask",
        "flask_cors",
        "flask_socketio",
        "flask_sqlalchemy",
        "requests",
        "scapy",
        "netifaces",
        "python-socketio",
    ]

    @classmethod
    def validate_configuration(cls) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []

        # Check required environment variables
        required_env_vars = ["SECRET_KEY"]
        for var in required_env_vars:
            if not os.environ.get(var):
                errors.append(
                    f"Required environment variable '{var}' is not set"
                )

        # Validate SECRET_KEY length
        if cls.SECRET_KEY and len(cls.SECRET_KEY) < 32:
            errors.append("SECRET_KEY must be at least 32 characters long")

        # Validate timeouts
        if cls.SCAN_TIMEOUT <= 0:
            errors.append("SCAN_TIMEOUT must be positive")
        if cls.PORT_SCAN_TIMEOUT <= 0:
            errors.append("PORT_SCAN_TIMEOUT must be positive")

        # Validate database URI
        if not cls.SQLALCHEMY_DATABASE_URI:
            errors.append("DATABASE_URL environment variable is required")

        # Validate paths
        for path_attr in ["REPORTS_DIR", "LOGS_DIR", "DATA_DIR"]:
            path = getattr(cls, path_attr)
            if not path:
                errors.append(f"{path_attr} cannot be empty")

        return errors

    @classmethod
    def check_dependencies(cls) -> Dict[str, bool]:
        """Check if required dependencies are installed"""
        missing_deps = {}
        for package in cls.REQUIRED_PACKAGES:
            try:
                __import__(package.replace("-", "_"))
                missing_deps[package] = True
            except ImportError:
                missing_deps[package] = False

        # Special check for scapy
        # Use importlib to check availability without importing the package
        if importlib.util.find_spec("scapy") is not None:
            missing_deps["scapy"] = True
        else:
            missing_deps["scapy"] = False

        return missing_deps

    @classmethod
    def init_directories(cls):
        """Initialize required directories with error handling"""
        directories = [cls.REPORTS_DIR, cls.LOGS_DIR, cls.DATA_DIR]
        for directory in directories:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                # Test write permissions
                test_file = directory / ".write_test"
                test_file.write_text("test")
                test_file.unlink()
            except (OSError, PermissionError) as e:
                logger.error(
                    f"Cannot create or write to directory {directory}: {e}"
                )
                raise RuntimeError(
                    f"Directory initialization failed: {directory}"
                ) from e

    @classmethod
    def validate_at_startup(cls):
        """Comprehensive validation at application startup"""
        logger.info("Performing startup configuration validation...")

        # Check dependencies
        deps_status = cls.check_dependencies()
        missing_deps = [
            pkg for pkg, available in deps_status.items() if not available
        ]
        if missing_deps:
            error_msg = (
                f"Missing required dependencies: {', '.join(missing_deps)}"
            )
            logger.error(error_msg)
            raise RuntimeError(error_msg)

        # Validate configuration
        config_errors = cls.validate_configuration()
        if config_errors:
            error_msg = (
                "Configuration validation failed:\n"
                + "\n".join(f"- {err}" for err in config_errors)
            )
            logger.error(error_msg)
            raise RuntimeError(error_msg)

        # Initialize directories
        cls.init_directories()

        logger.info("Configuration validation completed successfully")


class DevelopmentConfig(Config):
    """Development configuration"""

    DEBUG = True
    LOG_LEVEL = "DEBUG"


class ProductionConfig(Config):
    """Production configuration"""

    DEBUG = False
    SESSION_COOKIE_SECURE = True


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
