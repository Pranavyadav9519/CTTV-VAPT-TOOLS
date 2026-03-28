# CCTV Vulnerability Assessment Platform (VAPT)

**Version:** 3.0.0 | **Status:** Production Ready | **License:** MIT  
**Architecture:** Single-Tenant | **Type:** Enterprise CCTV Scanner

## 🚀 Quick Start (Local Development)

Get up and running in 5 minutes:

```bash
# 1. Clone and setup
git clone https://github.com/Pranavyadav9519/CTTV-VAPT-TOOLS
cd CTTV-VAPT-TOOLS

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Setup local database
export DATABASE_URL=sqlite:///vapt_dev.db
cd backend && python migrate.py upgrade && cd ..

# 5. Run development server
python backend/run.py
```

**Access at:** `http://localhost:5000` | **WebSocket:** ws://localhost:5000

## 📋 Features

✅ **Single-Tenant Architecture** - Simplified, secure, production-ready  
✅ **Enterprise Security** - JWT authentication, RBAC, authorization gates  
✅ **Async Processing** - Celery + Redis for parallel scan execution  
✅ **Private Network Scanning** - RFC 1918 enforcement (no public IP scans)  
✅ **Professional Reports** - HTML, JSON, PDF with encryption at rest  
✅ **CCTV-Specific** - Device identification, credential testing, fingerprinting  
✅ **Vulnerability Scanning** - Signature-based + behavior-based detection  
✅ **Compliance Ready** - Audit logs, immutable reports, soft deletes  
✅ **Production Deployment** - Docker, Render, Fly.io, Railway ready  

## 📁 Project Structure

```
CCTV-VAPT-TOOLS/
├── backend/
│   ├── enterprise/         # Main app factory & config (SINGLE-TENANT)
│   │   ├── __init__.py     # create_app() factory
│   │   ├── config.py       # Environment config
│   │   ├── extensions.py   # Flask extensions (db, jwt, cache, etc)
│   │   ├── api/            # API blueprints (auth, scans, reports)
│   │   ├── models/         # SQLAlchemy models
│   │   ├── repositories/   # Data access layer
│   │   ├── services/       # Business logic
│   │   ├── tasks/          # Celery async tasks
│   │   ├── security/       # Auth, RBAC, idempotency
│   │   └── storage/        # Report encryption & storage
│   ├── modules/            # Scanning & analysis modules
│   ├── migrations/         # Alembic DB migrations
│   ├── wsgi.py             # Production WSGI entry (gunicorn)
│   ├── run.py              # Development server entry
│   └── celery_app.py       # Celery worker config
├── frontend/               # Vercel-ready React/Vue UI
├── tests/                  # Test suite (unit, integration, e2e)
├── docs/                   # Documentation
├── docker-compose.yml      # Local dev orchestration
├── Dockerfile              # Production backend container
├── requirements.txt        # Python dependencies
└── README.md               # This file
```

## 🔧 Core Modules

### backend/enterprise/ (Single-Tenant Application)

**API Blueprints** (`api/`)
- `auth.py` - Token generation, user validation (no X-Tenant-ID header needed)
- `scans.py` - Scan start (requires `authorization_confirmed: true`), status, history
- `reports.py` - Report download (in-memory streaming, encrypted at rest)

**Data Layer** (`models/`, `repositories/`)
- Models: `Scan`, `Device`, `Report`, `Vulnerability`, `User`, `AuditLog`
- Repositories: `ScanRepository`, `ReportRepository` (NO tenant_id filtering)

**Security** (`security/`)
- `rbac.py` - Role-based access control (operator, viewer, admin)
- `idempotency.py` - Request deduplication (Redis + in-memory fallback)
- `validators.py` - Input validation & sanitization

**Async Tasks** (`tasks/`)
- `scan_worker.py` - Background scan execution (Celery task)
- Registered as: `backend.enterprise.tasks.scan_worker.run_scan`

**Storage & Encryption** (`storage/`, `services/`)
- Report encryption/decryption at rest
- Local or S3-compatible storage support

### backend/modules/
- **network_scanner.py** - Network discovery (Nmap-based)
- **port_scanner.py** - Port scanning and service detection
- **vulnerability_scanner.py** - Signature-based vulnerability matching
- **credential_tester.py** - Default credential testing
- **device_identifier.py** - CCTV device fingerprinting
- **report_generator.py** - Report generation in HTML/JSON/PDF

## 📚 Documentation

**Core Documentation:**
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - System design & decisions (4000+ lines)
- **[API.md](docs/API.md)** - Complete API reference with examples (2500+ lines)
- **[DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md)** - Database design & DDL (2000+ lines)
- **[SETUP.md](docs/SETUP.md)** - Installation & configuration (2500+ lines)
- **[CONTRIBUTING.md](docs/CONTRIBUTING.md)** - Development guidelines (1500+ lines)

**Operations & Performance (Phase 4):**
- **[PERFORMANCE.md](docs/PERFORMANCE.md)** - Optimization, caching, rate limiting, load testing
- **[INTEGRATION.md](docs/INTEGRATION.md)** - Security module integration guide with code examples
- **[PHASE_4_COMPLETION_SUMMARY.md](PHASE_4_COMPLETION_SUMMARY.md)** - Security & performance implementation summary

## 🔐 Security

- JWT-based authentication (no X-Tenant-ID header required)
- Role-based access control (RBAC): operator, viewer, admin
- Authorization gates: `authorization_confirmed: true` required for scans
- Private network only: RFC 1918 enforcement (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Report encryption at rest (AES-256-GCM)
- In-memory streaming for downloads (no temp files on disk)
- SQL injection prevention via SQLAlchemy ORM
- Input validation with Pydantic schemas
- Rate limiting on API endpoints
- Audit logging for compliance
- Soft deletes for data retention

## 📡 API Endpoints (Single-Tenant)

**Authentication**
- `POST /api/v1/auth/token` - Get JWT token
- No X-Tenant-ID header required

**Scans**
- `POST /api/v1/scans/start` - Start a new scan
  - Required: `authorization_confirmed: true`
  - Enforced: Private networks only (unless admin with ALLOW_PUBLIC_SCANS=true)
  - Response: 202 Accepted with task_id
- `GET /api/v1/scans/{scan_id}` - Get scan status
- `GET /api/v1/scans` - List all scans (paginated)

**Reports**
- `GET /api/v1/reports/{report_id}/download` - Download encrypted report
  - Returns: In-memory BytesIO stream (no temp files)
  - Formats: HTML, JSON, PDF
- `GET /api/v1/reports` - List all reports
- `DELETE /api/v1/reports/{report_id}` - Delete report

**WebSocket**
- `WS /ws/scan/{scan_id}` - Real-time scan progress updates



## ⚡ Performance & Optimization

**Rate Limiting** - Prevent abuse and brute force attacks
- Login: 5 per minute | Scan creation: 10 per day | Report generation: 20 per day
- Automatic 429 (Too Many Requests) responses

**Request Validation** - Ensure data integrity with Pydantic schemas
- CIDR notation validation for networks
- Port range validation (1-65535)
- Pagination limit enforcement
- Private network validation (RFC 1918)

**Redis Caching** - Reduce database load and improve response times
- 10-100x faster reads for cached data
- Smart cache invalidation on mutations  
- 7-layer TTL configuration (5 min to 24 hours)
- Session, scan, device, and report caching

**Async Processing** - Celery + Redis for parallel execution
- Background scan execution without blocking API
- Long-running tasks (network discovery, vulnerability scanning)
- WebSocket updates for real-time progress
- 8+ strategic indexes for fast queries
- Connection pooling with pool_size=10
- Eager loading for N+1 prevention
- Pagination on all list endpoints

See **[PERFORMANCE.md](docs/PERFORMANCE.md)** for detailed configuration and **[INTEGRATION.md](docs/INTEGRATION.md)** for implementation examples.

## 🗄️ Database

Supports PostgreSQL (production) or SQLite (development/testing).

```bash
# PostgreSQL (recommended for production)
DATABASE_URL=postgresql://user:password@localhost:5432/vapt_db

# SQLite (development)
DATABASE_URL=sqlite:///vapt_tool.db
```

## 🐳 Docker Deployment

```bash
# Start all services
docker-compose up -d

# PostgreSQL: postgresql://vapt:password@localhost:5432/vapt_db
# Redis: redis://localhost:6379
# Backend: http://localhost:5000
# Frontend: http://localhost:3000
```

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=backend --cov-report=html

# Run specific test category
pytest -m unit
pytest -m integration
pytest -m e2e
```

## 📡 API Endpoints

### Health Check
```
GET /health
```

### Reports
```
GET    /api/reports              # List reports
POST   /api/reports              # Generate new report
GET    /api/reports/<id>         # Get report details
GET    /api/reports/<id>/download # Download report file
DELETE /api/reports/<id>         # Delete report
POST   /api/reports/compare      # Compare two reports
```

See [API.md](docs/API.md) for complete endpoint documentation.

## 🔄 Workflow Example

1. **Initiate Scan**
   ```bash
   POST /api/scans
   {"network_range": "192.168.1.0/24", "ports": [22, 80, 443]}
   ```

2. **Monitor Scan**
   ```bash
   GET /api/scans/<scan_id>
   ```

3. **Generate Report**
   ```bash
   POST /api/reports
   {"scan_id": "scan-123", "format": "html"}
   ```

4. **Download Report**
   ```bash
   GET /api/reports/<report_id>/download
   ```

## 🛠️ Development

### Local Setup
```bash
# 1. Create virtual environment
python -m venv venv
source venv/bin/activate

# 2. Install dev dependencies
pip install -r requirements.txt

# 3. Start PostgreSQL & Redis
docker-compose up -d db redis

# 4. Run migrations
python backend/migrate.py

# 5. Start backend
python backend/app.py

# 6. Start frontend (new terminal)
cd frontend && python -m http.server 3000
```

### Code Quality
```bash
# Format code
black backend/ tests/

# Lint
flake8 backend/ tests/

# Type checking
mypy backend/

# All checks
black --check . && flake8 . && mypy backend
```

## 📊 Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Frontend (HTML/CSS/JS)           │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│           REST API Layer (Flask Blueprint)          │
│  (/api/reports, /api/scans, /api/devices, etc)    │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│       Service Layer (Business Logic)               │
│  (ReportService, ScanService, DeviceService)      │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│       Repository Layer (Data Access)               │
│  (Uses SQLAlchemy ORM)                             │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│    Database (PostgreSQL/SQLite)                    │
│  (Scan, Device, Port, Vulnerability, Report)      │
└─────────────────────────────────────────────────────┘
```

## 🚀 Production Deployment

### Kubernetes
```bash
helm install vapt ./deploy/helm -f values.yaml
```

### Systemd
```bash
sudo cp systemd/vapt.service /etc/systemd/system/
sudo systemctl start vapt
```

### Environment Variables
```bash
APP_ENV=production
DEBUG=False
SECRET_KEY=<generate-with-secrets.token_urlsafe(32)>
JWT_SECRET_KEY=<generate-with-secrets.token_urlsafe(32)>
DATABASE_URL=postgresql://user:password@host:5432/db
REDIS_URL=redis://host:6379/0
```

## 📝 License

MIT License - See LICENSE file

## 👥 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

## 📧 Support

- **Documentation:** [docs/](docs/)
- **Issues:** [GitHub Issues](https://github.com/yourusername/CCTV-VAPT-TOOLS/issues)
- **Discussions:** [GitHub Discussions](https://github.com/yourusername/CCTV-VAPT-TOOLS/discussions)

---

**Made with ❤️ for the security community**