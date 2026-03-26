# CCTV VAPT - Setup & Installation Guide

**Version:** 2.0.0  
**Last Updated:** March 2026  

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Local Development Setup](#local-development-setup)
3. [Docker Setup](#docker-setup)
4. [Database Configuration](#database-configuration)
5. [Environment Variables](#environment-variables)
6. [Running the Application](#running-the-application)
7. [Verification](#verification)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

- **OS:** Linux, macOS, or Windows 10+
- **CPU:** 2+ cores recommended
- **RAM:** 4GB minimum, 8GB recommended
- **Disk:** 10GB free space

### Required Software

- **Python:** 3.9+ (3.11 recommended)
- **Git:** Latest version
- **Docker:** 20.10+ (for Docker setup)
- **Docker Compose:** 1.29+ (for Docker setup)

### Optional Tools

- **PostgreSQL:** 13+ (if not using Docker)
- **Redis:** 6.0+ (if not using Docker)
- **Node.js:** 16+ (for frontend only)

---

## Local Development Setup

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/CCTV-VAPT-TOOLS.git
cd CCTV-VAPT-TOOLS
```

### 2. Create Python Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Expected output:**
```
Successfully installed Flask-2.3.3 SQLAlchemy-2.0.36 ...
```

### 4. Setup Environment Variables

```bash
# Copy example file
cp .env.example .env

# Edit .env with your settings
nano .env  # or use your editor
```

**Minimal .env configuration:**
```bash
APP_ENV=development
DEBUG=True
SECRET_KEY=dev-secret-key-change-in-production
JWT_SECRET_KEY=jwt-secret-key-change-in-production
DATABASE_URL=sqlite:///vapt_tool.db
REDIS_URL=redis://localhost:6379/0
```

### 5. Initialize Database

```bash
# Create SQLite database
python -c "from backend.app import create_app; create_app()"

# OR if using PostgreSQL, run migrations
python backend/migrate.py
```

**Expected output:**
```
Database initialized successfully
```

### 6. Create Admin User (Optional)

```bash
python -c "
from backend.app import create_app
from backend.core.database import db
from backend.core.models import User

app = create_app()
with app.app_context():
    admin = User(
        username='admin',
        email='admin@example.com',
        password='securepassword',
        role='admin',
        tenant_id='default'
    )
    db.session.add(admin)
    db.session.commit()
    print('Admin user created')
"
```

### 7. Start Backend Server

```bash
# In project root, with venv activated
python backend/app.py
```

**Expected output:**
```
WARNING: This is a development server. Do not use it in production.
* Running on http://127.0.0.1:5000
* Press CTRL+C to quit
```

### 8. Start Frontend (New Terminal)

```bash
# Navigate to frontend
cd frontend

# Start simple HTTP server
python -m http.server 3000
```

**Or with npm (if package installed):**
```bash
npm install http-server
npm start
```

### 9. Access Application

- **Backend API:** http://localhost:5000
- **Frontend:** http://localhost:3000
- **API Docs:** http://localhost:5000/api/docs (if Swagger enabled)

---

## Docker Setup

### Prerequisites for Docker

- Docker Engine running
- Docker Compose installed
- 10GB free disk space

### 1. Build and Start Services

```bash
# Start all containers
docker-compose up -d

# View container status
docker-compose ps

# View logs
docker-compose logs -f backend
```

### 2. Initialize Database in Container

```bash
# Run migrations in database container
docker-compose exec backend python backend/migrate.py

# Create admin user
docker-compose exec backend python -c "
from backend.app import create_app
from backend.core.database import db
from backend.core.models import User

app = create_app()
with app.app_context():
    admin = User(username='admin', email='admin@example.com', 
                 password='admin', role='admin', tenant_id='default')
    db.session.add(admin)
    db.session.commit()
"
```

### 3. Access Services

- **Backend API:** http://localhost:5000
- **Frontend:** http://localhost:3000
- **PostgreSQL:** localhost:5432 (user: vapt, password: password)
- **Redis:** localhost:6379

### 4. Useful Docker Commands

```bash
# Stop all services
docker-compose down

# Stop specific service
docker-compose stop backend

# Restart services
docker-compose restart

# Remove volumes (WARNING: deletes data)
docker-compose down -v

# View service logs
docker-compose logs -f --tail=100 backend

# Execute command in container
docker-compose exec backend bash
```

---

## Database Configuration

### SQLite (Development)

**Setup:**
```bash
# Automatic - created on first run
export DATABASE_URL="sqlite:///vapt_tool.db"
```

**Pros:** No installation, file-based  
**Cons:** Not suitable for production, limited concurrency

### PostgreSQL (Production Recommended)

**Installation:**

```bash
# Ubuntu/Debian
sudo apt-get install postgresql postgresql-contrib

# macOS with Homebrew
brew install postgresql

# Windows
# Download from https://www.postgresql.org/download/windows/
```

**Setup:**

```bash
# Create database and user
sudo -u postgres psql

CREATE USER vapt WITH PASSWORD 'secure_password';
CREATE DATABASE vapt_db OWNER vapt;
GRANT ALL PRIVILEGES ON DATABASE vapt_db TO vapt;
\q
```

**Connection String:**
```
DATABASE_URL=postgresql://vapt:secure_password@localhost:5432/vapt_db
```

**Verify Connection:**
```bash
psql -U vapt -d vapt_db -h localhost
```

### Redis Configuration

**Installation:**

```bash
# Ubuntu/Debian
sudo apt-get install redis-server

# macOS
brew install redis

# Start service
redis-server

# Verify
redis-cli ping  # Should return "PONG"
```

**Configuration:**
```bash
# In .env
REDIS_URL=redis://localhost:6379/0
```

**Docker Alternative:**
```bash
# Use docker-compose (handles Redis automatically)
docker-compose up -d
```

---

## Environment Variables

### Full Environment Configuration

**File:** `.env`

```bash
# ============================================================================
# APPLICATION CONFIGURATION
# ============================================================================
APP_ENV=production                    # development, production, testing
DEBUG=False                           # Never True in production
LOG_LEVEL=INFO                        # DEBUG, INFO, WARNING, ERROR

# ============================================================================
# SECURITY
# ============================================================================
SECRET_KEY=change-this-to-random-string-min-32-chars
JWT_SECRET_KEY=change-this-to-random-string-min-32-chars
JWT_EXPIRATION_HOURS=24               # Token expiration

# ============================================================================
# DATABASE
# ============================================================================
DATABASE_URL=postgresql://user:pass@localhost:5432/vapt_db
# OR for SQLite:
# DATABASE_URL=sqlite:///vapt_tool.db

DATABASE_ECHO=False                   # Log SQL queries
SQLALCHEMY_POOL_SIZE=10
SQLALCHEMY_POOL_RECYCLE=3600
SQLALCHEMY_POOL_PRE_PING=True

# ============================================================================
# REDIS (CACHING & TASK QUEUE)
# ============================================================================
REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=                       # If required

# ============================================================================
# CELERY (ASYNC TASKS)
# ============================================================================
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
CELERY_TASK_TIME_LIMIT=3600           # Hard limit
CELERY_TASK_SOFT_TIME_LIMIT=3300      # Soft limit

# ============================================================================
# SCANNING PARAMETERS
# ============================================================================
MAX_CONCURRENT_SCANS=3
SCAN_TIMEOUT_MINUTES=30
PORT_SCAN_TIMEOUT_SECONDS=5
DEFAULT_PORTS=22,80,443,8080,8443

# ============================================================================
# NOTIFICATIONS (OPTIONAL)
# ============================================================================
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM_EMAIL=noreply@vapt.example.com

# ============================================================================
# REPORTING
# ============================================================================
REPORT_RETENTION_DAYS=90              # Auto-delete reports > N days
REPORT_STORAGE_PATH=/var/reports
MAX_REPORT_SIZE_MB=500
INCLUDE_RECOMMENDATIONS=True

# ============================================================================
# FRONTEND
# ============================================================================
FRONTEND_URL=http://localhost:3000    # CORS allowed origins
API_BASE_URL=http://localhost:5000/api

# ============================================================================
# SECURITY HEADERS
# ============================================================================
CORS_ORIGINS=http://localhost:3000
CORS_ALLOW_CREDENTIALS=True
HSTS_MAX_AGE=31536000                 # 1 year

# ============================================================================
# RATE LIMITING
# ============================================================================
RATELIMIT_ENABLED=True
RATELIMIT_DEFAULT=100/hour            # Default limit
RATELIMIT_LOGIN=5/minute              # Login attempts
RATELIMIT_API=1000/hour               # API calls

# ============================================================================
# LOGGING
# ============================================================================
LOG_FILE=/var/log/vapt.log
LOG_MAX_SIZE_MB=100
LOG_BACKUP_COUNT=10

# ============================================================================
# SENTRY (ERROR TRACKING - OPTIONAL)
# ============================================================================
SENTRY_DSN=
SENTRY_ENVIRONMENT=production
```

### Generate Secure Keys

```bash
# Python
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Or using openssl
openssl rand -hex 32
```

---

## Running the Application

### Development

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# OR
venv\Scripts\activate     # Windows

# Start backend
python backend/app.py

# In another terminal, start frontend
cd frontend && python -m http.server 3000
```

### Production

```bash
# Using Gunicorn (production WSGI server)
gunicorn -w 4 -b 0.0.0.0:5000 backend.app:create_app()

# With systemd service (see deploy/)
sudo systemctl start vapt

# With Docker Compose
docker-compose up -d

# Check status
docker-compose ps
```

---

## Verification

### Health Check

```bash
# Backend health
curl http://localhost:5000/health

# Expected response
{
  "status": "healthy",
  "version": "2.0.0",
  "timestamp": "2026-03-26T10:30:00Z"
}
```

### Database Connection

```bash
# Check database connectivity
python -c "
from backend.core.database import db
from backend.app import create_app

app = create_app()
with app.app_context():
    db.engine.execute('SELECT 1')
    print('Database connected successfully')
"
```

### API Authentication

```bash
# Login and get token
TOKEN=$(curl -s -X POST http://localhost:5000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin","tenant_id":"default"}' \
  | jq -r '.access_token')

echo "Token: $TOKEN"

# Test authenticated request
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/api/reports
```

### Run Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=backend --cov-report=html

# Specific tests
pytest tests/unit/ -v
pytest tests/integration/ -m requires_db
```

---

## Troubleshooting

### Port Already in Use

```bash
# Find process using port 5000
lsof -i :5000

# Kill process
kill -9 <PID>

# Or use different port
PORT=5001 python backend/app.py
```

### Database Connection Error

```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Verify connection string
echo "DATABASE_URL=$DATABASE_URL"

# Test connection
psql -U vapt -d vapt_db -h localhost -c "SELECT 1"
```

### Redis Connection Error

```bash
# Check Redis is running
redis-cli ping

# Start Redis service
sudo systemctl start redis-server

# Or use Docker
docker run -d -p 6379:6379 redis:7
```

### Import Errors

```bash
# Ensure virtual environment is activated
which python  # Should show venv path

# Reinstall requirements
pip install --force-reinstall -r requirements.txt

# Check installed packages
pip list | grep Flask
```

### Permission Denied

```bash
# For Linux/macOS
chmod +x backend/app.py

# For systemd service
sudo usermod -a -G vapt-user www-data
```

### Module Not Found

```bash
#Add project to Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Or run from project root
cd /path/to/CCTV-VAPT-TOOLS
python backend/app.py
```

---

## Next Steps

1. **Configure Email (Optional)** - Set SMTP variables for notifications
2. **Setup Backups** - Configure automated database backups
3. **Enable Monitoring** - Setup Prometheus/Grafana
4. **Configure CI/CD** - Setup GitHub Actions for tests
5. **Security Hardening** - Review .env.example for all options

---

For architecture details, see [ARCHITECTURE.md](ARCHITECTURE.md)  
For API reference, see [API.md](API.md)  
For database design, see [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md)  
For development guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md)
