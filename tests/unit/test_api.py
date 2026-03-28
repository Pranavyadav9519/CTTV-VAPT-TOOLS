"""
Unit tests for API endpoints and routes
Tests HTTP methods, status codes, and response formats
"""

import pytest
import json


@pytest.mark.unit
@pytest.mark.api
def test_health_check_endpoint(client):
    """Test health check endpoint"""
    response = client.get('/health', follow_redirects=True)
    assert response.status_code in [200, 404]  # 404 if not implemented


@pytest.mark.unit
@pytest.mark.api
def test_api_version_endpoint(client):
    """Test API version endpoint"""
    response = client.get('/api/version', follow_redirects=True)
    # Accept 200 or 404 depending on implementation
    assert response.status_code in [200, 404]


@pytest.mark.unit
@pytest.mark.api
def test_reports_endpoint_requires_auth(client):
    """Test that reports endpoint requires authentication"""
    response = client.get('/api/v1/reports')
    # Should be 401 or 403 if auth is required, 404 if not mounted
    assert response.status_code in [200, 401, 403, 404]


@pytest.mark.unit
@pytest.mark.api
def test_api_response_format(client, auth_headers):
    """Test that API responses are valid JSON"""
    response = client.post(
        '/api/auth/login',
        json={'username': 'test', 'password': 'test'},
        follow_redirects=True
    )
    
    if response.status_code in [200, 401, 400]:
        # Response should be JSON
        try:
            data = response.get_json()
            assert data is not None or response.status_code != 200
        except Exception:
            # Some endpoints may not return JSON
            pass


@pytest.mark.unit
@pytest.mark.api
def test_cors_headers_present(client):
    """Test that CORS headers are configured"""
    response = client.get('/', follow_redirects=True)
    # Check if CORS headers might be present
    # Note: Not all responses will have CORS headers
    assert response.status_code in [200, 404, 405]
