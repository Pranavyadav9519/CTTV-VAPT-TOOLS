"""
Flask-Limiter configuration for API rate limiting and DDoS protection
"""

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os


def init_limiter(app: Flask) -> Limiter:
    """Initialize rate limiter for Flask app"""
    
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri=os.getenv("REDIS_URL", "redis://localhost:6379/1"),
        strategy="fixed-window",
    )
    
    return limiter


# Rate limit configurations for different endpoints
RATE_LIMITS = {
    # Authentication endpoints - strict
    "login": "5 per minute",
    "register": "3 per hour",
    "refresh_token": "10 per minute",
    "forgot_password": "3 per hour",
    
    # API endpoints - moderate
    "create_scan": "10 per day",
    "list_scans": "30 per minute",
    "get_scan": "60 per minute",
    
    # Report endpoints - moderate
    "generate_report": "20 per day",
    "list_reports": "30 per minute",
    "download_report": "100 per day",
    "delete_report": "10 per day",
    
    # Device endpoints
    "list_devices": "60 per minute",
    "get_device": "120 per minute",
    
    # Vulnerability endpoints
    "list_vulnerabilities": "60 per minute",
    "get_vulnerability": "120 per minute",
    
    # General API - loose
    "health_check": "1000 per minute",
}


def get_limit(endpoint: str) -> str:
    """Get rate limit for an endpoint"""
    return RATE_LIMITS.get(endpoint, "100 per hour")
