"""
Local conftest for integration tests.
Overrides the session-scoped 'app' and 'db' autouse fixtures so that
CRR pipeline tests can run without the full enterprise Flask application.
"""

import os
import sys
import pathlib
import pytest

# Ensure the backend package root is on the path so bare imports work
_BACKEND = pathlib.Path(__file__).parent.parent.parent / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

os.environ.setdefault("SECRET_KEY", "test-secret-key-minimum-32-characters-long!")


@pytest.fixture(scope="session")
def app():
    """Minimal app stub – CRR unit tests do not require Flask."""
    return None


@pytest.fixture(autouse=True)
def db(app):
    """Override the global autouse db fixture – CRR tests are DB-free."""
    yield None
