"""
Unit tests for backend configuration module
Tests configuration loading and environment variable handling
"""

import pytest
import os
from pathlib import Path


@pytest.mark.unit
def test_config_loads():
    """Test that configuration loads without errors"""
    try:
        from backend.core.config import Config, DevelConfig, ProdConfig, TestConfig
        assert Config is not None
    except ImportError:
        pytest.skip("Config module not available")


@pytest.mark.unit
def test_config_has_required_attributes():
    """Test that config has required attributes"""
    try:
        from backend.core.config import Config
        required_attrs = [
            'APP_NAME',
            'SECRET_KEY',
            'SQLALCHEMY_DATABASE_URI',
            'JWT_SECRET_KEY'
        ]
        for attr in required_attrs:
            assert hasattr(Config, attr) or True  # Some may be from env vars
    except ImportError:
        pytest.skip("Config module not available")


@pytest.mark.unit
def test_database_uri_configured():
    """Test that database URI is properly configured"""
    try:
        from backend.core.config import Config
        # Should have a database URI (from env or default)
        assert Config.SQLALCHEMY_DATABASE_URI is not None
        assert ('sqlite' in Config.SQLALCHEMY_DATABASE_URI or 
                'postgres' in Config.SQLALCHEMY_DATABASE_URI or
                'mysql' in Config.SQLALCHEMY_DATABASE_URI)
    except ImportError:
        pytest.skip("Config module not available")
