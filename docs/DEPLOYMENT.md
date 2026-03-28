# Deployment Guide - CCTV VAPT Tool

**Target Platforms:** Render, Fly.io, Railway | **Frontend:** Vercel | **Database:** PostgreSQL

## 🚀 Production Deployment Checklist

- [ ] Backend deployment (Render/Fly.io)
- [ ] Frontend deployment (Vercel)
- [ ] PostgreSQL database configured
- [ ] Redis instance (Upstash or managed)
- [ ] DNS & custom domain setup
- [ ] SSL/TLS certificates (auto-generated)
- [ ] Environment variables configured
- [ ] Monitoring & logging setup

---

## Backend Deployment (Render.com)

### 1. Prerequisites

```bash
# Ensure clean working directory
git status  # Should be clean
git log --oneline -3  # Verify recent commits
```

### 2. Connect Render

1. **Sign in to Render:** https://dashboard.render.com
2. **Create New Web Service**
3. **Connect GitHub:** Select repository `CTTV-VAPT-TOOLS`
4. **Choose Settings:**
   - Name: `cctv-vapt-backend`
   - Environment: `Python`
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn backend.wsgi:app`
   - Instance Type: `Standard` (adjust based on load)

### 3. Environment Variables

Set these in Render dashboard:

```env
# Database
DATABASE_URL=postgresql://user:pass@host:5432/vapt_prod

# API Configuration
FLASK_ENV=production
SECRET_KEY=<generate-secure-key>
JWT_SECRET_KEY=<generate-secure-key>

# CORS Origins
CORS_ORIGINS=https://vapt.yourdomain.com,https://www.yourdomain.com

# Redis (for Celery & caching)
REDIS_URL=redis://default:<password>@<host>:6379

# Celery
CELERY_BROKER_URL=${REDIS_URL}
CELERY_RESULT_BACKEND=${REDIS_URL}

# Scanning Configuration
ALLOW_PUBLIC_SCANS=false
MAX_CONCURRENT_SCANS=5
MAX_SCAN_HOSTS=1024

# Reports
STORAGE_KEY=<generate-32-byte-key>
REPORTS_DIR=/tmp/reports

# Logging
LOG_LEVEL=INFO
SENTRY_DSN=<optional-error-tracking>
```

### 4. Deploy

```bash
# Render auto-deploys on push to main
git push origin main
# Watch deployment in Render dashboard
```

---

## Frontend Deployment (Vercel)

### 1. Prerequisites

```bash
# Verify frontend structure
ls -la frontend/
# Should contain: index.html, package.json, css/, js/
```

### 2. Connect Vercel

1. **Sign in to Vercel:** https://vercel.com
2. **New Project** → Select `CTTV-VAPT-TOOLS`
3. **Configure:**
   - Root Directory: `frontend/`
   - Build Command: (leave empty for static)
   - Output Directory: `.` (default)

### 3. Environment Variables

```env
# API endpoint (matches backend URL)
REACT_APP_API_BASE_URL=https://vapt-backend.render.com
REACT_APP_WS_URL=wss://vapt-backend.render.com
```

### 4. Deploy

```bash
# Vercel auto-deploys on push
git push origin main
```

---

## Database Setup (PostgreSQL)

### Option A: Render Database

1. **Create PostgreSQL database in Render**
2. **Render provides:** `postgresql://user:pass@host:5432/dbname`
3. **Add to backend environment variables**

### Option B: External PostgreSQL (e.g., AWS RDS, DigitalOcean)

```bash
# Create database
createdb vapt_prod

# Apply migrations
export DATABASE_URL=postgresql://user:pass@host:5432/vapt_prod
cd backend
python -m alembic upgrade head
cd ..
```

---

## Redis Setup (Caching & Celery)

### Option A: Upstash (Serverless Redis)

1. **Sign up:** https://upstash.com
2. **Create new Redis database**
3. **Copy connection string:** `redis://default:<token>@<host>:6379`
4. **Set `REDIS_URL` in environment**

### Option B: Render Redis (if available)

1. **Create Redis instance in Render**
2. **Use provided connection URL**

---

## Celery Worker Setup

### Option A: Render Background Jobs

```bash
# In Render, create a Background Worker service:
# - Name: cctv-vapt-worker
# - Start Command: celery -A backend.enterprise.celery_app worker --loglevel=info
# - Environment: Same as backend
```

### Option B: Separate Deployment (Fly.io)

```bash
# Deploy worker to Fly.io
flyctl launch --name cctv-vapt-worker
# Update fly.toml with: celery -A backend.enterprise.celery_app worker
```

---

## DNS & Custom Domain

### 1. Register Domain

- Namecheap, Route53, GoDaddy, etc.

### 2. Point to Services

**For Render Backend:**
```
CNAME api.yourdomain.com → vapt-backend.onrender.com
```

**For Vercel Frontend:**
```
CNAME yourdomain.com → vapt-frontend.vercel.app
```

### 3. SSL/TLS

- **Render:** Auto-generates certificates
- **Vercel:** Auto-generates certificates
- **Custom domain:** Add CAA records for ACME validation

---

## Monitoring & Logging

### 1. Error Tracking (Optional)

```bash
# Setup Sentry for error monitoring
pip install sentry-sdk

# In backend/enterprise/__init__.py:
import sentry_sdk
sentry_sdk.init(dsn=os.getenv('SENTRY_DSN'))
```

### 2. Logs

- **Render:** View logs in dashboard
- **Vercel:** View deployment logs in dashboard
- **PostgreSQL:** Query `audit_logs` table

### 3. Metrics

```bash
# Celery flower (optional monitoring)
pip install flower
celery -A backend.enterprise.celery_app flower
# Access at: http://localhost:5555
```

---

## Post-Deployment Tests

### 1. Health Check

```bash
curl https://api.yourdomain.com/health
# Expected: {"status": "healthy"}
```

### 2. Authentication

```bash
curl -X POST https://api.yourdomain.com/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'
# Expected: {"access_token": "eyJ..."}
```

### 3. Scan Start

```bash
TOKEN="<jwt-token-from-above>"
curl -X POST https://api.yourdomain.com/api/v1/scans/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "operator_name": "test",
    "network_range": "192.168.1.0/24",
    "authorization_confirmed": true
  }'
# Expected: 202 Accepted with task_id
```

### 4. Frontend Access

```bash
curl https://yourdomain.com
# Expected: HTML response (homepage)
```

---

## Troubleshooting

### Backend Not Starting

```bash
# Check logs in Render dashboard
# Common issues:
# - DATABASE_URL not set
# - SECRET_KEY missing
# - Dependencies missing (install requirements.txt)
```

### Celery Tasks Not Running

```bash
# Verify REDIS_URL is set
# Check Celery worker logs
# Ensure worker is deployed (separate service)
```

### CORS Errors

```bash
# Update CORS_ORIGINS in environment variables
# Should match frontend domain: https://yourdomain.com
```

### Database Migrations Failed

```bash
# Manual migration on local machine:
export DATABASE_URL=<production-db-url>
cd backend
python -m alembic upgrade head
cd ..
```

---

## Rollback Procedure

```bash
# If deployment breaks, rollback is automatic in Render/Vercel
# Or manually revert:
git revert HEAD~1
git push origin main
```

---

## Environment Variable Template

```env
# .env.production (DO NOT COMMIT TO GIT)

# Application
FLASK_ENV=production
SECRET_KEY=<generate-with-secrets-module>
JWT_SECRET_KEY=<generate-with-secrets-module>

# Database
DATABASE_URL=postgresql://user:password@host:5432/vapt_prod

# Redis
REDIS_URL=redis://default:password@host:6379

# API Configuration
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com

# Celery
CELERY_BROKER_URL=${REDIS_URL}
CELERY_RESULT_BACKEND=${REDIS_URL}
CELERY_QUEUE=default

# Scanning
ALLOW_PUBLIC_SCANS=false
MAX_CONCURRENT_SCANS=5
MAX_SCAN_HOSTS=1024

# Storage
STORAGE_KEY=<32-byte-key-for-encryption>
REPORTS_DIR=/tmp/reports

# Logging
LOG_LEVEL=INFO
SENTRY_DSN=<optional-sentry-dsn>

# Optional: Monitoring
DATADOG_API_KEY=<optional>
```

---

## Getting Help

- **Render Support:** https://support.render.com
- **Vercel Support:** https://vercel.com/support
- **Flask Docs:** https://flask.palletsprojects.com
- **SQLAlchemy Docs:** https://docs.sqlalchemy.org
- **Celery Docs:** https://docs.celeryproject.io
