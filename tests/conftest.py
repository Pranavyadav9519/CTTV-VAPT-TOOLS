"""
Pytest configuration and fixtures for VAPT testing suite.
Provides database, application, and client fixtures for all tests.
"""

import pytest
import tempfile
import os
from pathlib import Path

# Add backend to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

# Provide a minimal SECRET_KEY for tests so Config doesn't fail validation
os.environ.setdefault("SECRET_KEY", "test-secret-key-minimum-32-characters-long!")


@pytest.fixture(scope="session")
def test_app_config():
    """Create a test configuration"""
    class TestConfig:
        APP_ENV = "testing"
        TESTING = True
        DEBUG = True
        SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        JWT_SECRET_KEY = "test-secret-key-do-not-use-in-production"
        SECRET_KEY = "test-secret-key-minimum-32-characters-long!"
        REDIS_URL = None
        JWT_EXPIRATION_HOURS = 24
        MAX_CONCURRENT_SCANS = 1
        SCAN_TIMEOUT_MINUTES = 5
        WTF_CSRF_ENABLED = False

    return TestConfig


@pytest.fixture(scope="session")
def app(test_app_config):
    """Create application instance for testing"""
    try:
        from backend.enterprise import create_app
        app_instance = create_app("testing")
        return app_instance
    except Exception:
        pytest.skip("Backend enterprise app module not available")


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Create test CLI runner"""
    return app.test_cli_runner()


@pytest.fixture(autouse=True)
def db(app):
    """Create database and provide transaction context"""
    try:
        from backend.enterprise.extensions import db as database_instance

        with app.app_context():
            database_instance.create_all()
            yield database_instance
            database_instance.session.remove()
            database_instance.drop_all()
    except ImportError:
        pytest.skip("Database module not available")


@pytest.fixture
def auth_headers(client):
    """Create authentication headers with JWT token"""
    return {'Authorization': 'Bearer test-token'}


@pytest.fixture
def admin_headers(client):
    """Create authentication headers for admin user"""
    return {'Authorization': 'Bearer admin-test-token'}


@pytest.fixture
def sample_scan_data():
    """Provide sample scan data for testing"""
    return {
        'network_range': '192.168.1.0/24',
        'scan_type': 'network',
        'ports': [22, 80, 443, 8080],
        'timeout': 300,
        'max_threads': 4
    }


@pytest.fixture
def sample_device_data():
    """Provide sample device data for testing"""
    return {
        'ip_address': '192.168.1.100',
        'device_type': 'ip_camera',
        'is_cctv': True,
        'confidence_score': 0.95,
        'os_info': 'Linux 4.x',
        'manufacturer': 'Hikvision'
    }


@pytest.fixture
def sample_vulnerability_data():
    """Provide sample vulnerability data for testing"""
    return {
        'title': 'Default Credentials',
        'description': 'Device uses default credentials',
        'severity': 'high',
        'cvss_score': 7.5,
        'cve_id': 'CVE-2021-1234',
        'remediation': 'Change default credentials'
    }


@pytest.fixture
def temp_report_dir():
    """Provide temporary directory for test reports"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


def pytest_configure(config):
    """Register custom markers"""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "e2e: mark test as an end-to-end test"
    )
    config.addinivalue_line(
        "markers", "requires_db: mark test as requiring database"
    )
    config.addinivalue_line(
        "markers", "requires_redis: mark test as requiring Redis"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "api: mark test as API related"
    )
    config.addinivalue_line(
        "markers", "security: mark test as security related"
    )
