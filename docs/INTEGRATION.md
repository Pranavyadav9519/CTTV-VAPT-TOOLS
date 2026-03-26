# Integration Guide - Phase 4 Security & Performance Modules

**Version:** 1.0.0  
**Status:** Implementation Reference  

## Overview

This guide shows how to integrate the three new Phase 4 modules into your existing Flask API:

1. **backend/core/rate_limiting.py** - Endpoint rate limiting
2. **backend/core/request_schemas.py** - Request validation
3. **backend/core/caching.py** - Query caching

---

## Integration 1: Rate Limiting

### Step 1: Initialize in App Factory

```python
# backend/app.py (or backend/enterprise/app.py)

from flask import Flask
from backend.core.rate_limiting import init_limiter, limiter
from flask_limiter.util import get_remote_address

def create_app(config_name='development'):
    app = Flask(__name__)
    app.config.from_object(config)
    
    # Initialize rate limiter
    init_limiter(app)
    
    # Register blueprints
    from backend.api.reports import report_bp
    from backend.api.scans import scan_bp
    
    app.register_blueprint(report_bp)
    app.register_blueprint(scan_bp)
    
    return app
```

### Step 2: Apply to Endpoints

```python
# backend/api/reports.py

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from backend.core.rate_limiting import limiter, get_limit
from backend.core.request_schemas import ReportGenerateSchema

report_bp = Blueprint('reports', __name__, url_prefix='/api/reports')

# Get the rate limit from configuration
@report_bp.route('', methods=['POST'])
@jwt_required()
@limiter.limit(get_limit('generate_report'))  # 20 per day
def generate_report():
    """Generate VAPT report from scan."""
    try:
        # Input validation (see Integration 2 below)
        schema = ReportGenerateSchema(**request.get_json())
        
        # Business logic
        report = generate_report_from_scan(
            schema.scan_id,
            schema.format,
            schema.include_remediation
        )
        
        return jsonify(report.to_dict()), 201
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@report_bp.route('/<report_id>/download', methods=['GET'])
@jwt_required()
@limiter.limit(get_limit('download_report'))  # 100 per day
def download_report(report_id):
    """Download generated report."""
    report = Report.query.get_or_404(report_id)
    
    # Stream file to user
    return send_file(report.file_path)

@report_bp.route('', methods=['GET'])
@jwt_required()
@limiter.limit("60 per minute")  # List is less restrictive
def list_reports():
    """List all reports for current user."""
    page = request.args.get('page', 1, type=int)
    
    reports = Report.query.filter_by(
        tenant_id=current_user.tenant_id
    ).paginate(page=page, per_page=20)
    
    return jsonify({
        'items': [r.to_dict() for r in reports.items],
        'total': reports.total,
        'pages': reports.pages
    })
```

### Step 3: Handle Rate Limit Exceeded (Optional)

```python
# backend/app.py

from flask_limiter.util import get_remote_address

@app.errorhandler(429)  # Too Many Requests
def rate_limit_exceeded(e):
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': str(e.description)
    }), 429
```

---

## Integration 2: Request Validation

### Step 1: Create Validation Decorator

```python
# backend/core/validators.py

from functools import wraps
from flask import request, jsonify
from pydantic import ValidationError

def validate_json(schema_class):
    """Decorator to validate JSON request body against Pydantic schema."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                json_data = request.get_json()
                if not json_data:
                    return jsonify({'error': 'Request body required'}), 400
                
                validated_data = schema_class(**json_data)
                # Store validated data in request context
                request.validated = validated_data
                
                return f(*args, **kwargs)
                
            except ValidationError as e:
                return jsonify({
                    'error': 'Validation error',
                    'details': e.errors()
                }), 400
                
        return decorated_function
    return decorator
```

### Step 2: Apply to Endpoints

```python
# backend/api/scans.py

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from backend.core.validators import validate_json
from backend.core.request_schemas import ScanCreateSchema, DeviceFilterSchema

scan_bp = Blueprint('scans', __name__, url_prefix='/api/scans')

@scan_bp.route('', methods=['POST'])
@jwt_required()
@limiter.limit("10 per day")
@validate_json(ScanCreateSchema)  # Validates network_range, ports, timeout
def create_scan():
    """Create new network scan."""
    scan_data = request.validated.dict()
    
    # Create scan with validated data
    scan = Scan(
        tenant_id=get_jwt_identity(),
        network_range=scan_data['network_range'],
        scan_name=scan_data.get('scan_name', 'Unnamed Scan'),
        ports=scan_data.get('ports'),
        timeout=scan_data.get('timeout', 300)
    )
    
    db.session.add(scan)
    db.session.commit()
    
    return jsonify(scan.to_dict()), 201

@scan_bp.route('/<scan_id>/devices', methods=['GET'])
@jwt_required()
@limiter.limit("60 per minute")
@validate_json(DeviceFilterSchema)  # Validates pagination, filters
def list_devices(scan_id):
    """List devices in scan."""
    query_data = request.validated.dict()
    
    device_query = Device.query.filter(
        Device.scan_id == scan_id,
        Device.tenant_id == get_jwt_identity()
    )
    
    # Optional filtering
    if query_data.get('severity'):
        device_query = device_query.filter(
            Device.severity == query_data['severity']
        )
    
    paginated = device_query.paginate(
        page=query_data.get('page', 1),
        per_page=query_data.get('per_page', 20)
    )
    
    return jsonify({
        'devices': [d.to_dict() for d in paginated.items],
        'total': paginated.total,
        'pages': paginated.pages
    })
```

### Step 3: Custom Validation Examples

```python
# backend/core/request_schemas.py (enhance existing)

from pydantic import BaseModel, Field, validator
import ipaddress

class ScanCreateSchema(BaseModel):
    network_range: str
    scan_name: Optional[str] = Field(None, max_length=255)
    ports: Optional[List[int]] = None
    timeout: Optional[int] = Field(300, ge=30, le=3600)
    
    @validator('network_range')
    def validate_cidr(cls, v):
        """Validate CIDR notation."""
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"Invalid CIDR notation: {v}")
        return v
    
    @validator('ports')
    def validate_ports(cls, v):
        """Validate port ranges."""
        if v:
            if not all(1 <= port <= 65535 for port in v):
                raise ValueError("Ports must be between 1 and 65535")
        return v
```

---

## Integration 3: Redis Caching

### Step 1: Initialize Redis Connection

```python
# backend/core/caching.py (already has this, verify it's initialized)

from redis import Redis
import json

class CacheManager:
    def __init__(self, redis_url='redis://localhost:6379/0'):
        self.redis = Redis.from_url(redis_url, decode_responses=True)
    
    def get(self, key):
        """Get value from cache."""
        value = self.redis.get(key)
        return json.loads(value) if value else None
    
    def set(self, key, value, ttl=3600):
        """Set value in cache with TTL."""
        self.redis.setex(
            key,
            ttl,
            json.dumps(value, default=str)
        )
    
    def delete(self, key):
        """Delete cache entry."""
        self.redis.delete(key)
    
    def clear_pattern(self, pattern):
        """Clear all keys matching pattern."""
        keys = self.redis.keys(pattern)
        if keys:
            self.redis.delete(*keys)

# Global cache instance
cache = CacheManager()
```

### Step 2: Apply to Service Layer

```python
# backend/core/services.py or backend/layers/report_composition.py

from backend.core.caching import cached, CACHE_TTLS
from functools import wraps

class ReportService:
    
    @cached('cache:report', ttl=CACHE_TTLS['report'])
    def get_report_by_id(self, report_id):
        """Get report (cached for 1 hour)."""
        return Report.query.get(report_id)
    
    @cached('cache:reports_list', ttl=CACHE_TTLS['report'])
    def list_reports_for_tenant(self, tenant_id, page=1):
        """List reports (cached for 1 hour)."""
        return Report.query.filter_by(
            tenant_id=tenant_id
        ).paginate(page=page, per_page=20)
    
    def generate_report(self, scan_id, format='html'):
        """Generate report (never cache this, too dynamic)."""
        scan = Scan.query.get(scan_id)
        # ... generation logic ...
        
        # Invalidate cache when report generated
        from backend.core.caching import cache
        cache.clear_pattern('cache:reports_list*')
        
        return report

class ScanService:
    
    @cached('cache:devices', ttl=CACHE_TTLS['device'])
    def get_devices_for_scan(self, scan_id):
        """Get all devices in scan (cached for 10 minutes)."""
        return Device.query.filter_by(scan_id=scan_id).all()
    
    @cached('cache:vulnerabilities', ttl=CACHE_TTLS['vulnerability'])
    def get_vulnerabilities(self, scan_id, severity=None):
        """Get vulnerabilities (cached for 30 minutes)."""
        query = Vulnerability.query.filter_by(scan_id=scan_id)
        if severity:
            query = query.filter_by(severity=severity)
        return query.all()
```

### Step 3: Use in Routes

```python
# backend/api/reports.py

from backend.core.services import ReportService

report_service = ReportService()

@report_bp.route('/<report_id>', methods=['GET'])
@jwt_required()
def get_report(report_id):
    """Get report details (uses cache)."""
    report = report_service.get_report_by_id(report_id)  # Cached
    
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    return jsonify(report.to_dict())

@report_bp.route('/<report_id>', methods=['DELETE'])
@jwt_required()
def delete_report(report_id):
    """Delete report and invalidate cache."""
    report = Report.query.get(report_id)
    
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    db.session.delete(report)
    db.session.commit()
    
    # Invalidate cache
    from backend.core.caching import cache
    cache.delete(f'cache:report:{report_id}')
    cache.clear_pattern('cache:reports_list*')
    
    return '', 204
```

---

## Testing Integration

### Test Rate Limiting

```python
# tests/integration/test_rate_limiting.py

import pytest
from flask import Flask

def test_rate_limit_exceeded(client):
    """Test request is rejected after rate limit."""
    token = get_test_token()
    
    # Make requests up to limit
    for i in range(5):  # 5 per minute limit
        response = client.post(
            '/api/auth/login',
            json={'username': 'user', 'password': 'pass'},
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code != 429
    
    # Next request should be rate limited
    response = client.post(
        '/api/auth/login',
        json={'username': 'user', 'password': 'pass'},
        headers={'Authorization': f'Bearer {token}'}
    )
    assert response.status_code == 429
    assert 'Rate limit' in response.get_json()['error']
```

### Test Validation

```python
# tests/integration/test_validation.py

def test_invalid_cidr_rejected(client):
    """Test invalid CIDR notation is rejected."""
    response = client.post(
        '/api/scans',
        json={
            'network_range': 'not-a-valid-cidr',
            'scan_name': 'Test'
        },
        headers={'Authorization': f'Bearer {token}'}
    )
    assert response.status_code == 400
    assert 'Invalid CIDR' in str(response.json)

def test_port_range_validated(client):
    """Test port ranges are validated."""
    response = client.post(
        '/api/scans',
        json={
            'network_range': '192.168.1.0/24',
            'ports': [22, 80, 99999]  # 99999 is invalid
        },
        headers={'Authorization': f'Bearer {token}'}
    )
    assert response.status_code == 400
    assert 'port' in str(response.json).lower()
```

### Test Caching

```python
# tests/integration/test_caching.py

def test_cached_report_reused(client, cache):
    """Test report is cached and reused."""
    # First request
    response1 = client.get(
        '/api/reports/report-123',
        headers={'Authorization': f'Bearer {token}'}
    )
    assert response1.status_code == 200
    
    # Verify cache was used
    cached_value = cache.get('cache:report:report-123')
    assert cached_value is not None
    
    # Second request should use cache
    response2 = client.get(
        '/api/reports/report-123',
        headers={'Authorization': f'Bearer {token}'}
    )
    assert response1.json == response2.json  # Same response

def test_cache_invalidated_on_delete(client, cache):
    """Test cache is cleared when report deleted."""
    # Prime cache
    client.get('/api/reports/report-123', headers={'Authorization': f'Bearer {token}'})
    assert cache.get('cache:report:report-123') is not None
    
    # Delete report
    client.delete('/api/reports/report-123', headers={'Authorization': f'Bearer {token}'})
    
    # Verify cache cleared
    assert cache.get('cache:report:report-123') is None
```

---

## Deployment Checklist

- [ ] Rate limiting initialized in `create_app()` before registering blueprints
- [ ] All sensitive endpoints have `@limiter.limit()` decorator
- [ ] All POST/PUT/PATCH routes use `@validate_json()` with appropriate schema
- [ ] All frequently-accessed read operations use `@cached()` decorator
- [ ] Cache is invalidated on CREATE/UPDATE/DELETE operations
- [ ] Database indexes created (see PERFORMANCE.md)
- [ ] Redis connection tested in production environment
- [ ] Rate limit errors return 429 status code
- [ ] Validation errors return 400 status code with detailed error messages
- [ ] Tests verify rate limiting, validation, and caching work correctly

---

## Troubleshooting

### Rate Limit Not Working

```python
# Check limiter is initialized
from backend.core.rate_limiting import limiter
print(limiter)  # Should not be None

# Verify decorator syntax
@limiter.limit("5 per minute")  # Correct format
# @limiter.limit(5)  # WRONG - don't use this
```

### Validation Not Working

```python
# Check schema is imported correctly
from backend.core.request_schemas import ScanCreateSchema

# Try manual validation
try:
    schema = ScanCreateSchema(network_range='192.168.1.0/24')
except Exception as e:
    print(f"Schema error: {e}")
```

### Redis Connection Failed

```bash
# Verify Redis is running
redis-cli ping  # Should return PONG

# Check Redis URL in config
printenv REDIS_URL  # Should have redis:// prefix

# Test connection in Python
from redis import Redis
r = Redis.from_url('redis://localhost:6379/0')
r.ping()  # Should return True
```

---

**Next Steps:**
1. Create `backend/core/validators.py` with the decorator
2. Integrate rate limiting into existing endpoints
3. Add validation schemas to request handlers
4. Apply caching to service layer
5. Run integration tests
6. Deploy to staging environment

---

See also: [PERFORMANCE.md](PERFORMANCE.md), [API.md](API.md), [ARCHITECTURE.md](ARCHITECTURE.md)
