# CCTV VAPT - Performance & Optimization Guide

**Version:** 2.0.0  
**Last Updated:** March 2026  

## Table of Contents

- [Database Optimization](#database-optimization)
- [Caching Strategy](#caching-strategy)
- [Rate Limiting](#rate-limiting)
- [Input Validation](#input-validation)
- [Query Optimization](#query-optimization)
- [Load Testing](#load-testing)
- [Monitoring & Profiling](#monitoring--profiling)

---

## Database Optimization

### Indexing Strategy

**Required Indexes (Already Implemented):**

```python
# See DATABASE_SCHEMA.md for complete DDL

# High-priority indexes
CREATE INDEX idx_scan_tenant ON scan(tenant_id);
CREATE INDEX idx_scan_status ON scan(status);
CREATE INDEX idx_device_scan ON device(scan_id);
CREATE INDEX idx_device_ip ON device(ip_address);
CREATE INDEX idx_device_cctv ON device(is_cctv);
CREATE INDEX idx_vulnerability_device ON vulnerability(device_id);
CREATE INDEX idx_vulnerability_severity ON vulnerability(severity);
CREATE INDEX idx_report_scan ON report(scan_id);
CREATE INDEX idx_report_tenant ON report(tenant_id);

# Performance monitoring
EXPLAIN ANALYZE SELECT * FROM device WHERE scan_id = 'scan-123';
```

### Connection Pooling

**Configuration in backend/core/database.py:**

```python
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_size': 10,              # Connections to keep in pool
    'pool_recycle': 3600,         # Recycle after 1 hour
    'pool_pre_ping': True,        # Test before using
    'max_overflow': 20,           # Allow overflow beyond pool_size
    'echo': False,                # Disable SQL logging in production
}
```

### Query Optimization

**Lazy vs Eager Loading:**

```python
# AVOID: N+1 query problem
devices = Device.query.filter_by(scan_id=scan_id).all()
for device in devices:
    print(device.vulnerabilities)  # Causes N queries

# GOOD: Eager load relationships
from sqlalchemy.orm import joinedload
devices = Device.query.filter_by(scan_id=scan_id) \
    .options(joinedload(Device.vulnerabilities)) \
    .all()
```

**Pagination:**

```python
# AVOID: Loading all results
all_devices = Device.query.all()

# GOOD: Paginate
page = request.args.get('page', 1, type=int)
paginated = Device.query.paginate(page=page, per_page=20)
devices = paginated.items
```

---

## Caching Strategy

### Redis Integration

**Setup:**

```bash
# Start Redis
docker-compose up -d redis

# Verify connection
redis-cli ping  # Should return "PONG"
```

### Caching Layers

**1. Session Cache (24 hours)**

```python
from backend.core.caching import cached, CACHE_TTLS

# Caching user sessions
@cached('cache:user', ttl=CACHE_TTLS['session'])
def get_user(user_id):
    return User.query.get(user_id)
```

**2. Query Cache (10-30 minutes)**

```python
# Cache frequently accessed data
@cached('cache:device', ttl=CACHE_TTLS['device'])
def list_devices_for_scan(scan_id, page=1):
    return Device.query.filter_by(scan_id=scan_id) \
        .paginate(page=page, per_page=20).items
```

**3. Report Cache (1 hour)**

```python
# Cache generated reports
@cached('cache:report', ttl=CACHE_TTLS['report'])
def get_report_content(report_id):
    return Report.query.get(report_id)
```

### Cache Invalidation

```python
# Invalidate scan when it's updated
def update_scan(scan_id, data):
    scan = Scan.query.get(scan_id)
    # ... update logic ...
    
    # Invalidate related caches
    from backend.core.caching import invalidate_cache
    invalidate_cache('cache:scan*')
    invalidate_cache('cache:device*')
    
    db.session.commit()
```

---

## Rate Limiting

### Configuration

**From backend/core/rate_limiting.py:**

```python
# Per-endpoint limits
RATE_LIMITS = {
    'login': '5 per minute',              # Prevent brute force
    'create_scan': '10 per day',          # Prevent abuse
    'generate_report': '20 per day',      # Resource-intensive
    'download_report': '100 per day',     # Generous for legitimate use
    'list_devices': '60 per minute',      # Read-heavy, less strict
}
```

### Applying Rate Limits

**In API endpoints:**

```python
from flask_limiter.util import get_remote_address
from backend.core.rate_limiting import get_limit

@app.route('/api/reports', methods=['POST'])
@limiter.limit("20 per day")
@jwt_required()
def generate_report():
    # Rate limited to 20 reports per day per user
    pass
```

### Testing Rate Limits

```bash
# Generate requests to test limit
for i in {1..25}; do
    curl -H "Authorization: Bearer $TOKEN" \
      -X POST http://localhost:5000/api/reports \
      -H "Content-Type: application/json" \
      -d '{"scan_id":"test"}'
    echo "Request $i"
done
```

---

## Input Validation

### Pydantic Schemas

**From backend/core/request_schemas.py:**

```python
from pydantic import BaseModel, Field, validator

class ScanCreateSchema(BaseModel):
    network_range: str  # CIDR notation
    scan_name: Optional[str] = Field(None, max_length=255)
    ports: Optional[List[int]] = Field(None)
    timeout: Optional[int] = Field(300, ge=30, le=3600)
    
    @validator('network_range')
    def validate_network_range(cls, v):
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError("Invalid CIDR notation")
        return v
```

### Using Validation Decorator

```python
from backend.core.request_schemas import ScanCreateSchema
from backend.enterprise.security.validators import validate_schema

@app.route('/api/scans', methods=['POST'])
@validate_schema(ScanCreateSchema)
def create_scan():
    # request.validated contains validated data
    validated_data = request.validated
    scan = Scan(**validated_data.dict())
    db.session.add(scan)
    db.session.commit()
```

---

## Query Optimization

### Common Patterns

**Pattern 1: Filter by Tenant (Multi-tenancy)**

```python
# ALL queries must filter by tenant_id for security
devices = Device.query.filter(
    Device.scan_id == scan_id,
    Device.tenant_id == current_user.tenant_id
).all()
```

**Pattern 2: Aggregate Queries**

```python
from sqlalchemy import func

# Count vulnerabilities by severity
summary = db.session.query(
    Vulnerability.severity,
    func.count(Vulnerability.vulnerability_id)
).filter(
    Vulnerability.scan_id == scan_id
).group_by(
    Vulnerability.severity
).all()
```

**Pattern 3: Avoid SELECT *

```python
# AVOID: Selects all columns
devices = Device.query.all()

# GOOD: Select only needed columns
devices = db.session.query(
    Device.device_id,
    Device.ip_address,
    Device.is_cctv
).filter(Device.scan_id == scan_id).all()
```

---

## Load Testing

### Using Apache Bench

```bash
# Test API endpoint under load
ab -n 1000 -c 10 http://localhost:5000/api/reports

# -n: Total requests
# -c: Concurrent requests
```

### Using Locust

```python
# locustfile.py
from locust import HttpUser, task, between

class VAP TUser(HttpUser):
    wait_time = between(1, 3)
    
    @task
    def list_reports(self):
        headers = {
            'Authorization': f'Bearer {self.token}',
            'X-Tenant-ID': 'test-tenant'
        }
        self.client.get('/api/reports', headers=headers)
    
    @task
    def generate_report(self):
        headers = {
            'Authorization': f'Bearer {self.token}',
            'X-Tenant-ID': 'test-tenant'
        }
        self.client.post('/api/reports', json={
            'scan_id': 'scan-123',
            'format': 'html'
        }, headers=headers)
```

**Run load test:**

```bash
locust -f locustfile.py --host=http://localhost:5000
```

---

## Monitoring & Profiling

### Application Metrics

**Using Prometheus:**

```python
from prometheus_client import Counter, Histogram

# Metrics
request_count = Counter('vapt_requests_total', 'Total requests', ['method', 'endpoint'])
request_latency = Histogram('vapt_request_latency_seconds', 'Request latency')

@app.before_request
def before_request():
    request.start_time = time.time()
    request_count.labels(method=request.method, endpoint=request.path).inc()

@app.after_request
def after_request(response):
    latency = time.time() - request.start_time
    request_latency.observe(latency)
    return response
```

### Database Profiling

```bash
# Enable SQL logging
export SQLALCHEMY_ECHO=True
python backend/app.py

# This will log all SQL queries
```

### Performance Monitoring

**Endpoint Response Times:**

```python
import time

@app.route('/api/reports')
def list_reports():
    start = time.time()
    
    # ... your code ...
    
    duration = time.time() - start
    logger.info(f"list_reports took {duration:.3f}s")
```

---

## Optimization Checklist

- [ ] All tables have proper indexes (see DATABASE_SCHEMA.md)
- [ ] Connection pooling configured (pool_size=10)
- [ ] Caching enabled for:
  - [ ] User sessions (24h TTL)
  - [ ] Scan lists (10m TTL)
  - [ ] Device lists (10m TTL)
  - [ ] Report data (1h TTL)
- [ ] Rate limiting activated on:
  - [ ] Authentication endpoints
  - [ ] Report generation
  - [ ] Report downloads
- [ ] Input validation using Pydantic schemas
- [ ] Pagination implemented on all list endpoints
- [ ] N+1 queries eliminated (eager loading used)
- [ ] Database connection pooling active
- [ ] Monitoring/alerting configured
- [ ] Load testing completed

---

## Production Recommendations

1. **Database:** PostgreSQL 13+ with 4GB+ RAM
2. **Redis:** Dedicated Redis instance or cluster
3. **Gunicorn:** 4 workers per CPU core
4. **Load Balancer:** Nginx or HAProxy
5. **CDN:** CloudFront or Cloudflare for static assets
6. **Monitoring:** Prometheus + Grafana
7. **Logging:** ELK Stack or CloudWatch
8. **Backups:** Daily automated backups to S3/GCS

---

For setup instructions, see [SETUP.md](SETUP.md)  
For API reference, see [API.md](API.md)  
For database schema, see [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md)
