# CCTV Vulnerability Assessment Tool (VAPT)

**Version:** 2.0.0 | **Status:** Production Ready | **License:** MIT

## 🚀 Quick Start

Get up and running in 5 minutes:

```bash
# 1. Clone and setup
git clone https://github.com/yourusername/CCTV-VAPT-TOOLS
cd CCTV-VAPT-TOOLS

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Setup database
export DATABASE_URL=sqlite:///vapt_tool.db
python -c "from backend.app import create_app; app = create_app(); print('Database ready')"

# 5. Run the application
python backend/app.py
```

**Access at:** `http://localhost:5000`

## 📋 Features

✅ **Complete Architecture** - REST API with service/repository layers  
✅ **Enterprise Security** - JWT authentication, RBAC, audit logging  
✅ **Multi-Tenant Support** - Full tenant isolation and data security  
✅ **Async Processing** - Celery workers for background scans  
✅ **Professional Reports** - HTML, JSON, and PDF generation  
✅ **CCTV Scanning** - Network discovery, port scanning, device fingerprinting  
✅ **Vulnerability Detection** - Signature-based vulnerability matching  
✅ **Compliance Ready** - Full audit trail, immutable reports, soft deletes  
✅ **Production Deployment** - Docker & Kubernetes support  

## 📁 Project Structure

```
CCTV-VAPT-TOOLS/
├── backend/
│   ├── core/               # Core modules (config, database, models)
│   ├── api/                # REST API endpoints
│   ├── modules/            # Scanning & processing modules
│   ├── tasks/              # Celery async tasks
│   ├── reports/            # Generated reports (output)
│   └── migrations/         # Database migrations
├── frontend/               # Web UI (HTML/CSS/JS)
├── tests/                  # Test suite (unit, integration, e2e)
├── docs/                   # Documentation
│   ├── ARCHITECTURE.md     # System design
│   ├── API.md              # API reference
│   ├── DATABASE_SCHEMA.md  # Database design
│   ├── SETUP.md            # Installation guide
│   └── CONTRIBUTING.md     # Development guidelines
├── docker-compose.yml      # Container orchestration
├── requirements.txt        # Python dependencies
└── README.md               # This file
```

## 🔧 Core Modules

### backend/core/
- **config.py** - Configuration management (dev, test, prod)
- **database.py** - SQLAlchemy ORM initialization
- **models.py** - Database models (Scan, Device, Vulnerability, Report)
- **repositories.py** - Data access layer
- **services.py** - Business logic layer  
- **errors.py** - Custom exceptions
- **utils.py** - Helper functions

### backend/api/
- **reports.py** - Report management endpoints (generate, list, download, delete)

### backend/modules/
- **network_scanner.py** - Network discovery and scanning
- **port_scanner.py** - Port scanning and service detection
- **vulnerability_scanner.py** - Vulnerability matching
- **credential_tester.py** - Credential testing
- **device_identifier.py** - CCTV device fingerprinting
- **report_generator.py** - Report generation

### backend/tasks/
- **report_tasks.py** - Celery tasks for async report generation

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

- JWT-based authentication with role-based access control (RBAC)
- Multi-tenant isolation with tenant_id filtering
- SQL injection prevention via SQLAlchemy ORM
- Input validation with Pydantic schemas
- Rate limiting on API endpoints (5-100 requests per time window)
- Audit logging for compliance
- Soft deletes for data retention

## ⚡ Performance & Optimization (Phase 4)

**Rate Limiting** - Prevent abuse and brute force attacks
- Login: 5 per minute | Scan creation: 10 per day | Report generation: 20 per day
- Automatic 429 (Too Many Requests) responses

**Request Validation** - Ensure data integrity with Pydantic schemas
- CIDR notation validation for networks
- Port range validation (1-65535)
- Pagination limit enforcement
- Custom validation rules per endpoint

**Redis Caching** - Reduce database load and improve response times
- 10-100x faster reads for cached data
- Smart cache invalidation on mutations
- 7-layer TTL configuration (5 min to 24 hours)
- Session, scan, device, and report caching

**Database Optimization**
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