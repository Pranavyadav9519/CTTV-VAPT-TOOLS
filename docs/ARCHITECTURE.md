# CCTV VAPT - System Architecture

**Author:** VAPT Development Team  
**Last Updated:** March 2026  
**Version:** 2.0.0  

## Table of Contents

1. [Overview](#overview)
2. [Layered Architecture](#layered-architecture)
3. [Core Components](#core-components)
4. [Database Design](#database-design)
5. [API Design](#api-design)
6. [Security Architecture](#security-architecture)
7. [Scalability & Performance](#scalability--performance)
8. [Deployment Architecture](#deployment-architecture)

---

## Overview

The CCTV VAPT tool uses a **clean, layered architecture** that separates concerns at different levels:

```
Frontend (React/Vanilla JS)
    ↓
REST API Layer (Flask Blueprints)
    ↓
Service Layer (Business Logic)
    ↓
Repository Layer (Data Access)
    ↓
Database (PostgreSQL/SQLite)
```

### Architecture Principles

- **Separation of Concerns:** Each layer has a specific responsibility
- **DRY (Don't Repeat Yourself):** Reusable services and utilities
- **SOLID Principles:** Single Responsibility, Open/Closed, Liskov Substitution, Interface Segregation, Dependency Inversion
- **Repository Pattern:** Data access abstraction
- **Service Locator Pattern:** Dependency injection at service layer

---

## Layered Architecture

### 1. Presentation Layer (Frontend)

**Location:** `/frontend/`

**Components:**
- HTML templates (`index.html`, `login.html`, etc.)
- CSS stylesheets (`/css/`)
- JavaScript modules (`/js/`)

**Responsibilities:**
- User interface rendering
- Form handling and validation
- API communication
- State management

**Technologies:**
- Vanilla JavaScript (HTML5, CSS3)
- Optional: React/Vue migration possible

---

### 2. API Layer

**Location:** `/backend/api/`

**Key Files:**
- `reports.py` - Report management endpoints
- `scans.py` - Scan initiation and monitoring
- `devices.py` - Device inventory
- `vulnerabilities.py` - Vulnerability querying

**Responsibilities:**
- Request validation (input)
- Authentication/Authorization
- Error handling
- Response formatting
- Rate limiting

**Example Endpoint:**
```python
@reports_bp.route('/api/reports', methods=['POST'])
@jwt_required()
@require_role('admin', 'operator')
def generate_report():
    """Generate new scan report"""
    # Validate input
    # Check permissions (tenant_id)
    # Call service layer
    # Return response
```

---

### 3. Service Layer (Business Logic)

**Location:** `/backend/core/services.py`

**Key Services:**
- `ReportService` - Report generation, storage, retrieval
- `ScanService` - Scan orchestration
- `DeviceService` - Device management
- `VulnerabilityService` - Vulnerability operations

**Responsibilities:**
- Business logic implementation
- Data transformation
- Cross-cutting concerns (logging, caching)
- Orchestration of repositories
- Error handling

**Example Service:**
```python
class ReportService:
    def generate_report(self, scan_id, format='html'):
        # 1. Get scan data from repository
        scan = ScanRepository.get(scan_id)
        
        # 2. Validate scan is complete
        if scan.status != ScanStatus.COMPLETED:
            raise InvalidScanStatus()
        
        # 3. Gather data from multiple repos
        devices = DeviceRepository.find_by_scan(scan_id)
        vulnerabilities = VulnerabilityRepository.find_by_scan(scan_id)
        
        # 4. Format report
        report_content = self._format_report(devices, vulnerabilities, format)
        
        # 5. Save to file and database
        file_path = self._save_report_file(report_content, format)
        report = Report(scan_id=scan_id, file_path=file_path, format=format)
        ReportRepository.create(report)
        
        # 6. Return result
        return report
```

---

### 4. Repository Layer (Data Access)

**Location:** `/backend/core/repositories.py`

**Key Repositories:**
- `ScanRepository` - Scan CRUD operations
- `DeviceRepository` - Device CRUD operations
- `VulnerabilityRepository` - Vulnerability CRUD operations
- `ReportRepository` - Report CRUD operations

**Responsibilities:**
- Database query abstraction
- ORM interactions (SQLAlchemy)
- Query optimization
- Data marshaling

**Example Repository:**
```python
class ScanRepository:
    @staticmethod
    def get(scan_id, tenant_id):
        """Get scan by ID"""
        return db.session.query(Scan).filter(
            Scan.scan_id == scan_id,
            Scan.tenant_id == tenant_id  # Multi-tenancy
        ).first()
    
    @staticmethod
    def find_by_tenant(tenant_id, page=1, limit=20):
        """List scans for tenant with pagination"""
        return db.session.query(Scan).filter(
            Scan.tenant_id == tenant_id
        ).offset((page-1)*limit).limit(limit).all()
    
    @staticmethod
    def create(scan):
        """Create new scan"""
        db.session.add(scan)
        db.session.commit()
        return scan
```

---

### 5. Model Layer (Database)

**Location:** `/backend/core/models.py`

**Key Models:**
- `Scan` - Scan session record
- `Device` - Network device found
- `Port` - Open port on device
- `Vulnerability` - Security issue found
- `Report` - Generated report
- `User` - System user
- `AuditLog` - Compliance logging

**Relationships:**
```
User 1---N Report
Scan 1---N Device
Device 1---N Port
Device 1---N Vulnerability
Scan 1---N Report
```

---

## Core Components

### Network Scanner Module

**File:** `/backend/modules/network_scanner.py`

**Function:** Network discovery and enumeration

**Process:**
1. Parse network range (CIDR notation)
2. Generate IP addresses
3. Probe each IP (ping, ARP, etc.)
4. Record responsive hosts
5. Store in Device table

### Port Scanner Module

**File:** `/backend/modules/port_scanner.py`

**Function:** Port enumeration and service detection

**Process:**
1. Get target IPs from Device table
2. Scan common ports (22, 80, 443, 8080, etc.)
3. Detect service/version
4. Store in Port table

### Vulnerability Scanner Module

**File:** `/backend/modules/vulnerability_scanner.py`

**Function:** Vulnerability matching against known signatures

**Process:**
1. Load vulnerability signatures  
2. For each device/port:
   - Match against signatures
   - Calculate CVSS score
   - Check CVE database
3. Store in Vulnerability table

### Reporting Engine

**File:** `/backend/reporting_engine.py`

**Function:** Report generation in multiple formats

**Supported Formats:**
- HTML - Professional formatted report with CSS styling
- JSON - Machine-readable structured data
- PDF - Printable document (via weasyprint)

---

## Database Design

### Scan Table
```sql
CREATE TABLE scan (
    scan_id UUID PRIMARY KEY,
    network_range VARCHAR(50) NOT NULL,
    status ENUM('pending', 'queued', 'running', 'completed', 'failed'),
    total_hosts_found INT DEFAULT 0,
    vulnerabilities_found INT DEFAULT 0,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    duration_seconds INT,
    tenant_id VARCHAR(100) NOT NULL,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

### Device Table
```sql
CREATE TABLE device (
    device_id UUID PRIMARY KEY,
    ip_address VARCHAR(50) NOT NULL,
    is_cctv BOOLEAN DEFAULT FALSE,
    confidence_score FLOAT,
    os_info VARCHAR(255),
    manufacturer VARCHAR(100),
    scan_id UUID FOREIGN KEY REFERENCES scan,
    tenant_id VARCHAR(100) NOT NULL,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

### Vulnerability Table
```sql
CREATE TABLE vulnerability (
    vulnerability_id UUID PRIMARY KEY,
    device_id UUID FOREIGN KEY REFERENCES device,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity ENUM('critical', 'high', 'medium', 'low', 'info'),
    cvss_score FLOAT,
    cve_id VARCHAR(50),
    remediation TEXT,
    tenant_id VARCHAR(100) NOT NULL,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

---

## API Design

### RESTful Principles

- **Resources:** /api/scans, /api/devices, /api/reports
- **Methods:** GET (read), POST (create), PUT (update), DELETE (remove)
- **Status Codes:** 
  - 200 OK
  - 201 Created
  - 400 Bad Request
  - 401 Unauthorized
  - 403 Forbidden
  - 404 Not Found
  - 500 Internal Server Error

### Request/Response Format

**Request:**
```json
{
  "network_range": "192.168.1.0/24",
  "ports": [22, 80, 443],
  "timeout": 300,
  "tenant_id": "org-001"
}
```

**Response:**
```json
{
  "status": "success",
  "code": 201,
  "data": {
    "scan_id": "scan-123",
    "status": "queued",
    "created_at": "2026-03-26T10:30:00Z"
  }
}
```

---

## Security Architecture

### Authentication

**Type:** JWT (JSON Web Tokens)

**Flow:**
1. User POST credentials to `/api/auth/login`
2. Server validates credentials
3. Server generates JWT token (24-hour expiration)
4. Client includes token in `Authorization: Bearer <token>` header

**Token Payload:**
```json
{
  "user_id": "user-123",
  "tenant_id": "org-001",
  "role": "admin",
  "iat": 1704000000,
  "exp": 1704086400
}
```

### Authorization

**Type:** Role-Based Access Control (RBAC)

**Roles:**
- `admin` - Full system access
- `operator` - Create/manage scans
- `viewer` - Read-only access

**Enforcement:** Decorators on API endpoints
```python
@jwt_required()
@require_role('admin', 'operator')
def generate_report():
    pass
```

### Multi-Tenancy

**Isolation:** Tenant ID in JWT token and request headers

**Enforcement:** Filter all queries by `tenant_id`
```python
Device.query.filter(
    Device.tenant_id == current_tenant_id
).all()
```

### Data Protection

- **Encryption:** TLS/SSL for transport
- **Hashing:** bcrypt for password storage
- **Input Validation:** Pydantic models for all inputs
- **SQL Injection Prevention:** SQLAlchemy ORM
- **Rate Limiting:** Flask-Limiter on API endpoints
- **Audit Logging:** All operations logged with user, timestamp, action

---

## Scalability & Performance

### Database Indexing

**Recommended Indexes:**
```sql
CREATE INDEX idx_device_ip ON device(ip_address);
CREATE INDEX idx_device_scan ON device(scan_id);
CREATE INDEX idx_scan_status ON scan(status);
CREATE INDEX idx_scan_tenant ON scan(tenant_id);
CREATE INDEX idx_vulnerability_device ON vulnerability(device_id);
CREATE INDEX idx_vulnerability_severity ON vulnerability(severity);
```

### Caching Strategy

**Redis Cache Layers:**
1. **Session Cache:** JWT token validation (5-minute TTL)
2. **Query Cache:** Frequent queries (10-minute TTL)
3. **Report Cache:** Generated reports (1-hour TTL)

### Async Processing

**Celery Tasks:**
- `generate_report_async()` - Long-running report generation
- `cleanup_old_reports()` - Scheduled maintenance
- `validate_checksums()` - Data integrity checks

**Configuration:**
```python
CELERY_BROKER_URL = 'redis://localhost:6379'
CELERY_RESULT_BACKEND = 'redis://localhost:6379'
CELERY_TASK_TIME_LIMIT = 3600  # 1 hour max
CELERY_TASK_SOFT_TIME_LIMIT = 3300  # 5 min warning
```

---

## Deployment Architecture

### Local Development

```
┌─────────────┐
│  Frontend   │ http://localhost:3000
│ HTTP Server │
└─────────────┘
       ↓
┌──────────────────┐
│ Flask App        │ http://localhost:5000
│ - API endpoints  │
│ - Services       │
│ - Repositories   │
└──────────────────┘
       ↓
┌──────────────────┐
│  SQLite DB       │ vapt_tool.db
│ (Development)    │
└──────────────────┘
```

### Docker Deployment

```
┌──────────────┐
│   Nginx      │ :80, :443 (reverse proxy)
│  (Optional)  │
└──────────────┘
       ↓
┌──────────────────────────────────┐
│      Docker Compose Network      │
├──────────────────────────────────┤
│                                  │
│  ┌──────────┐  ┌──────────┐    │
│  │ Backend  │  │ Frontend │    │
│  │ Flask    │  │ HTTP     │    │
│  │ :5000    │  │ :3000    │    │
│  └──────────┘  └──────────┘    │
│       ↓               ↓          │
│  ┌──────────┐  ┌──────────┐    │
│  │ Postgres │  │  Redis   │    │
│  │ :5432    │  │ :6379    │    │
│  └──────────┘  └──────────┘    │
│                                  │
└──────────────────────────────────┘
```

### Kubernetes Deployment

```
┌──────────────────────┐
│   Ingress Controller │
└──────────────────────┘
         ↓
[Backend Pod x N] [Frontend Pod x N]
[Database Pod]
[Redis Pod]
[Celery Worker Pod]
```

---

## Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Frontend | Vanilla JS / HTML5 / CSS3 | Latest |
| API | Flask | 2.3.3 |
| ORM | SQLAlchemy | 2.0.36 |
| Database | PostgreSQL / SQLite | 13+ / Latest |
| Cache | Redis | 7.0+ |
| Task Queue | Celery | 5.3.1 |
| Authentication | PyJWT | 2.8.1 |
| Validation | Pydantic | 1.10.12 |
| Testing | Pytest | 7.4.3 |
| Containerization | Docker | Latest |
| Orchestration | Docker Compose / Kubernetes | Latest |

---

## Design Patterns Used

1. **Repository Pattern** - Data access abstraction
2. **Service Locator** - Dependency injection
3. **Decorator Pattern** - Flask decorators for auth/validation
4. **Factory Pattern** - App creation (create_app)
5. **Singleton Pattern** - Database instance, Redis client
6. **Observer Pattern** - Event logging/audit trails
7. **Strategy Pattern** - Multiple report formats
8. **Chain of Responsibility** - Middleware stack

---

## Future Enhancements

- [ ] GraphQL API alternative
- [ ] Real-time WebSocket updates
- [ ] Machine learning for vulnerability detection
- [ ] Active directory/LDAP integration
- [ ] SIEM integration
- [ ] Mobile application
- [ ] Advanced visualization dashboards

---

**For API specifications, see [API.md](API.md)**  
**For database schema details, see [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md)**  
**For setup instructions, see [SETUP.md](SETUP.md)**
