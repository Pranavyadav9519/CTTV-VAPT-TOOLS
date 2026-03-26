"""
PROFESSIONAL ARCHITECTURE GUIDE - CCTV VAPT TOOL
Complete restructuring for production-ready system

This guide explains the new architecture and how to use it.
"""

# ============================================================================
# NEW PROJECT STRUCTURE (CREATED)
# ============================================================================

"""
backend/
├── core/                          # Core infrastructure
│   ├── __init__.py
│   ├── config.py                 # Configuration management (✓ CREATED)
│   ├── database.py               # Database initialization (✓ CREATED)
│   ├── models.py                 # Database models (✓ CREATED)
│   ├── repositories.py           # Data access layer (✓ CREATED)
│   ├── services.py               # Business logic (✓ CREATED)
│   ├── errors.py                 # Error handling (✓ CREATED)
│   └── utils.py                  # Utilities & helpers (✓ CREATED)
│
├── api/                           # API endpoints (TO CREATE)
│   ├── __init__.py
│   ├── auth.py                   # Authentication endpoints
│   ├── scans.py                  # Scan management endpoints
│   ├── devices.py                # Device endpoints
│   ├── vulnerabilities.py        # Vulnerability endpoints
│   └── reports.py                # Report endpoints
│
├── modules/                       # Scanning & analysis modules (REFACTOR)
│   ├── scanner.py                # Base scanner class
│   ├── network_scanner.py        # Network discovery
│   ├── port_scanner.py           # Port scanning
│   ├── device_identifier.py      # Device identification
│   ├── vulnerability_scanner.py  # Vulnerability detection
│   └── report_generator.py       # Report generation
│
├── tasks/                         # Celery async tasks (TO CREATE)
│   ├── __init__.py
│   ├── scan_tasks.py             # Scan execution tasks
│   └── report_tasks.py           # Report generation tasks
│
├── data/                          # Data files
│   ├── cctv_vulnerabilities.json (EXISTING - Use as-is)
│   └── default_credentials.json  (EXISTING - Use as-is)
│
└── app.py                         # Main application (NEW VERSION)


# ============================================================================
# KEY IMPROVEMENTS IMPLEMENTED
# ============================================================================

### 1. PROPER REST API ARCHITECTURE
   - Clear separation of concerns
   - Controllers → Services → Repositories → Models
   - Stateless, scalable design

### 2. SECURITY HARDENING
   - JWT-based authentication
   - Role-based access control (ADMIN, OPERATOR, VIEWER)
   - Input validation and sanitization
   - SQL injection prevention (ORM-based)
   - CORS properly configured
   - Security headers on all responses
   - Password hashing with salting
   - XSS and CSRF protection

### 3. DATABASE DESIGN
   - Proper relationships with foreign keys
   - Soft-delete for data retention
   - Audit trail logging
   - Transaction management
   - Connection pooling

### 4. ERROR HANDLING
   - Consistent error responses
   - Custom exception hierarchy
   - Request tracking with request IDs
   - Detailed logging

### 5. DATA VALIDATION
   - Request payload validation
   - Email validation
   - IP/Network validation
   - Password strength requirements
   - Input sanitization

### 6. MULTI-TENANCY
   - Tenant isolation
   - Tenant-scoped queries
   - Audit logging per tenant

### 7. MONITORING & LOGGING
   - Structured logging
   - Audit trail for compliance
   - Performance logging
   - Error tracking


# ============================================================================
# ENVIRONMENT CONFIGURATION REQUIRED
# ============================================================================

Create a .env file in project root:

```
# Application
APP_ENV=development
APP_DEBUG=true
SECRET_KEY=your-secret-key-min-32-chars-1234567890abcdefghijklmn
JWT_SECRET_KEY=your-jwt-secret-min-32-chars-1234567890abcdefghijklmn

# Database
DATABASE_URL=sqlite:///vapt_tool.db
# For production: postgresql://user:pass@localhost/vapt_db

# Encryption
ENCRYPTION_KEY=your-encryption-key-min-32-chars-1234567890abcdefghijklmn
AUDIT_LOG_KEY=your-audit-logging-key-min-32-chars-1234567890abcdefgh

# Redis/Celery
REDIS_URL=redis://localhost:6379/0

# Security
CORS_ORIGINS=http://localhost:3000,http://localhost:5000

# Scanning
MAX_CONCURRENT_SCANS=3
MAX_SCAN_HOSTS=1000
SCAN_TIMEOUT_SECONDS=3600

# Logging
LOG_LEVEL=INFO

```


# ============================================================================
# DATABASE SETUP
# ============================================================================

1. Initialize database with Flask CLI:
   
   export FLASK_APP=backend/app.py
   flask db-init

2. Or manually create tables:
   
   from backend.app import create_app
   app = create_app()
   with app.app_context():
       from backend.core.database import db
       db.create_all()

3. Create default admin user:
   
   from backend.app import create_app
   from backend.core.database import seed_db
   app = create_app()
   seed_db(app)


# ============================================================================
# API USAGE EXAMPLES
# ============================================================================

### 1. USER REGISTRATION
POST /api/auth/register
Content-Type: application/json

{
    "email": "user@example.com",
    "username": "testuser",
    "password": "SecurePass123!",
    "tenant_id": "tenant001"
}

### 2. USER LOGIN
POST /api/auth/login
Content-Type: application/json

{
    "username": "testuser",
    "password": "SecurePass123!",
    "tenant_id": "tenant001"
}

Response:
{
    "success": true,
    "data": {
        "access_token": "eyJ0eXAiOiJKV1QiLC...",
        "token_type": "Bearer",
        "user": {...}
    },
    "error": null,
    "request_id": "uuid"
}

### 3. CREATE SCAN
POST /api/scans
Authorization: Bearer <token>
X-Tenant-ID: tenant001
Content-Type: application/json

{
    "network_range": "192.168.1.0/24",
    "scan_type": "network_discovery",
    "description": "CCTV systems scan"
}

### 4. GET SCAN DETAILS
GET /api/scans/SCAN-ABC123DEF456
Authorization: Bearer <token>
X-Tenant-ID: tenant001

### 5. LIST USER SCANS
GET /api/scans?skip=0&limit=50
Authorization: Bearer <token>
X-Tenant-ID: tenant001


# ============================================================================
# NEXT STEPS - FILES TO CREATE
# ============================================================================

1. backend/api/__init__.py
   - Import and register all API blueprints

2. backend/api/auth.py
   - Additional auth endpoints (password reset, etc.)

3. backend/api/scans.py
   -Scan management endpoints

4. backend/api/devices.py
   - Device listing and details

5. backend/api/vulnerabilities.py
   - Vulnerability endpoints

6. backend/api/reports.py
   - Report generation and download

7. backend/tasks/scan_tasks.py
   - Celery tasks for async scanning

8. backend/modules/scanner.py
   - Refactored scanner base class

9. backend/modules/network_scanner.py
   - Improved network scanner

10. backend/modules/vulnerability_scanner.py
    - Enhanced vulnerability detection

11. Tests
    - Unit tests for services
    - Integration tests for API
    - Test fixtures and factories


# ============================================================================
# RUNNING THE APPLICATION
# ============================================================================

### Development Mode

1. Install dependencies:
   pip install -r requirements.txt

2. Set up environment:
   export FLASK_APP=backend/app.py
   export FLASK_ENV=development
   
3. Initialize database:
   flask shell
   >>> from backend.core.database import seed_db
   >>> seed_db(app)

4. Run development server:
   python -m flask run --host 0.0.0.0 --port 5000

5. Or with auto-reload:
   python -m flask run --reload

### Production Mode

1. Use gunicorn or uwsgi
   gunicorn -w 4 -b 0.0.0.0:5000 backend.app:create_app()

2. Use proper database (PostgreSQL)
   DATABASE_URL=postgresql://user:pass@host/db

3. Use Redis for Celery
   REDIS_URL=redis://localhost:6379/0

4. Run Celery worker
   celery -A backend.tasks worker -l info


# ============================================================================
# TESTING
# ============================================================================

Create tests/test_api.py:

```python
import pytest
from backend.app import create_app
from backend.core.database import db

@pytest.fixture
def app():
    app = create_app()
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

def test_health_check(client):
    response = client.get('/api/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] == True
    assert 'version' in data['data']

def test_register_user(client):
    response = client.post('/api/auth/register', json={
        'email': 'test@example.com',
        'username': 'testuser',
        'password': 'SecurePass123!',
        'tenant_id': 'test_tenant'
    })
    assert response.status_code == 201
    data = response.get_json()
    assert data['success'] == True
    assert 'user_id' in data['data']
```

Run tests:
pytest tests/ -v


# ============================================================================
# MIGRATION TO NEW ARCHITECTURE
# ============================================================================

1. Backup existing database
2. Create new database with new schema
3. Export data from old system
4. Transform and import into new schema
5. Test thoroughly
6. Deploy


# ============================================================================
# SECURITY CHECKLIST
# ============================================================================

✓ JWT authentication
✓ Role-based access control
✓ Input validation
✓ Password hashing
✓ SQL injection prevention
✓ CORS configured
✓ Security headers
✓ Audit logging
✓ HTTPS ready (use reverse proxy)
✓ Rate limiting (add redis-based)
✓ Request ID tracking
✓ Error message sanitization
✓ Soft deletes for data retention
✓ Database connection pooling
✓ Environment-based configuration


# ============================================================================
# PERFORMANCE OPTIMIZATION TIPS
# ============================================================================

1. Use database indexing
   - scan_id, user_id, created_at
   - Indexed foreign keys automatically

2. Implement caching
   - Cache scan results
   - Cache device lists
   - Use Redis

3. Pagination
   - Implemented via utils
   - Default 50 items, max 1000

4. Lazy loading
   - Use lazy='dynamic' in relationships
   - Load only what's needed

5. Query optimization
   - Eager load relationships
   - Use select patterns
   - Profile with SQLAlchemy

6. Background jobs
   - Async scanning with Celery
   - Report generation in background


# ============================================================================
# DEPLOYMENT CHECKLIST
# ============================================================================

□ Set all environment variables
□ Use PostgreSQL (not SQLite)
□ Configure Redis
□ Run database migrations
□ Create admin user
□ Set up HTTPS/TLS
□ Configure logging
□ Set up monitoring
□ Configure backup strategy
□ Test failover
□ Document API
□ Create user guide
□ Set up CI/CD


# ============================================================================
# MONITORING AND LOGGING
# ============================================================================

All actions are logged to audit trail:
- User registration/login
- Scan creation/modification
- Vulnerability discovery
- Report generation
- Access logs
- Errors and exceptions

View audit logs:
GET /api/audit-logs?action=scan_created

Log files are in: backend/logs/


# ============================================================================
# TROUBLESHOOTING
# ============================================================================

1. Database connection errors:
   - Check DATABASE_URL
   - Verify database server running
   - Check credentials

2. JWT errors:
   - Verify JWT_SECRET_KEY set
   - Check token format (Bearer <token>)
   - Verify X-Request-ID header

3. Permission errors:
   - Check user role
   - Verify tenant_id matches
   - Check X-Tenant-ID header

4. Scan errors:
   - Check network_range format
   - Verify concurrent scan limit
   - Check scan timeout


For more information, see the complete codebase in backend/core/
"""
