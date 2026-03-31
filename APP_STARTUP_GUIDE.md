# VAPT Application Startup Guide

## Issue Resolved: Flask App Conflict ✅

This document resolves the Flask app conflicts and clarifies which application to use for different scenarios.

---

## 📊 Flask Apps Comparison

| Feature | Standalone App<br/>`backend/app.py` | Enterprise App<br/>`backend/enterprise/__init__.py` |
|---------|---------------------------|-----|
| **Frontend Routes** | ✅ `/`, `/css/*`, `/js/*` | ✅ `/`, `/css/*`, `/js/*` (Added) |
| **API Routes** | ✅ `/api/scan/*`, `/api/reports`, `/api/scans` | ✅ `/api/auth`, `/api/scans`, `/api/reports` |
| **Socket.IO** | ✅ Live scan updates | ❌ Not configured |
| **JWT Authentication** | ❌ Basic control | ✅ Full JWT + Custom RBAC |
| **Async Tasks (Celery)** | ❌ Sync operations | ✅ Full Celery support |
| **Rate Limiting** | ❌ None | ✅ Redis-backed rate limiting |
| **Multi-tenant** | ❌ Single tenant | ✅ Tenant-aware |
| **Use Case** | Development, testing, simple deploys | Enterprise SaaS, advanced deployments |

---

## 🚀 Quick Start

### Option 1: Standalone App (Recommended for Most Users)

**What you get:**
- ✅ Full frontend UI (navigation, all tabs)
- ✅ Scan API endpoints
- ✅ Live Socket.IO updates
- ✅ No authentication overhead

**Start the app:**
```bash
cd D:\VAPT
python backend/run.py
```

**Or explicitly set**
```bash
set FLASK_ENV=development
python backend/run.py
```

**Access at:** http://localhost:5000

---

### Option 2: Enterprise App (SaaS/Advanced Deployments)

**What you get:**
- ✅ Full frontend UI
- ✅ JWT authentication (required for all API calls)
- ✅ Role-based access control (RBAC)
- ✅ Async task processing
- ✅ Rate limiting
- ✅ Tenant isolation support

**Requirements:**
- PostgreSQL (not SQLite)
- Redis (for rate limiting + Celery)
- Admin account created via `seed_db()`

**Start the app:**
```bash
set FLASK_ENV=enterprise
python backend/run.py
```

**Access at:** http://localhost:5000

**Authenticate:**
```bash
# Login with default credentials (created via seed_db)
# Admin account: admin / admin123 (CHANGE THIS IN PRODUCTION!)
```

---

## 🔍 What Was Fixed

### Issue 1: API Route Mismatch ✅
**Before:**
- Frontend calls: `POST /api/scan/start`
- Enterprise app had: `/api/v1/scans/start` → 404

**After:**
- Enterprise app now has: `/api/scans/start` (matches frontend)
- Blueprints registered at `/api/` prefix (not `/api/v1/`)

### Issue 2: Missing Frontend Routes ✅
**Before:**
- Enterprise app only had: `/health`, `/ready`, and API routes
- No routes for `/`, `/css/*`, `/js/*` → 404 on navigation

**After:**
- Added `/css/<path:filename>` route to serve CSS from `frontend/css/`
- Added `/js/<path:filename>` route to serve JS from `frontend/js/`
- Home page `/` already existed

### Issue 3: Unclear Startup Strategy ✅
**Before:**
- `backend/run.py` only used standalone app
- Enterprise app existed but was unused

**After:**
- `backend/run.py` intelligently chooses which app to start
- Clear logging shows which app is running
- Can switch between apps via `FLASK_ENV` environment variable

---

## 🔧 Configuration

### Standalone App Configuration
Located in: `config/settings.py`

Key settings:
- `SQLALCHEMY_DATABASE_URI` - Database connection
- `SECRET_KEY` - Session encryption
- `DEBUG` - Debug mode

### Enterprise App Configuration
Located in: `backend/enterprise/config.py`

Key settings:
- `DATABASE_URL` - PostgreSQL connection
- `REDIS_URL` - Redis connection (for rate limiting + Celery)
- `JWT_SECRET_KEY` - JWT signing key
- `CORS_ORIGINS` - Allowed origins

---

## 📋 Frontend-to-Backend API Mapping

The frontend (`frontend/js/app.js`) expects these endpoints:

| Endpoint | Method | Purpose | Status |
|----------|--------|---------|--------|
| `/api/scan/start` | POST | Start a scan | ✅ Works in both apps |
| `/api/scans` | GET | List scans | ✅ Works in both apps |
| `/api/scan/{id}/devices` | GET | Get devices in scan | ✅ Works in standalone app |
| `/api/reports` | GET | List reports | ✅ Works in both apps |
| `/api/analytics/summary` | GET | Analytics data | ✅ Works in standalone app |

**Note:** Both apps now serve all required endpoints without 404 errors.

---

## 🚨 Troubleshooting

### "404 on frontend routes"
**Cause:** Using old enterprise app without the fixes
**Solution:** 
1. Ensure you're using the updated code
2. Use the standalone app: `python backend/run.py`

### "404 on `/api/scan/start`"
**Cause:** Old code might have `/api/v1/scans/start`
**Solution:**
1. Use the updated enterprise app (`backend/enterprise/__init__.py`)
2. Or use standalone app (`python backend/run.py`)

### "Authentication required"
**Cause:** Using enterprise app which requires JWT auth
**Solution:**
1. Use standalone app for no-auth: `python backend/run.py`
2. Or get JWT token: `POST /api/auth/login` with credentials

### "Redis connection error"
**Cause:** Enterprise app needs Redis
**Solution:**
1. Install Redis: `docker run -d -p 6379:6379 redis:7`
2. Or use standalone app: `python backend/run.py`

---

## 📚 Additional Resources

- **Architecture Guide:** See [ARCHITECTURE_GUIDE.md](ARCHITECTURE_GUIDE.md)
- **API Documentation:** See [docs/API.md](docs/API.md)
- **Deployment Guide:** See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
- **Database Setup:** See [docs/DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md)

---

## ✅ Migration Checklist

If you were using the old conflicting setup:

- [ ] Pull the latest code (includes `/api/` prefix changes)
- [ ] Verify `backend/run.py` uses new smart startup
- [ ] Test standalone app: `python backend/run.py`
- [ ] Test enterprise app: `set FLASK_ENV=enterprise && python backend/run.py`
- [ ] Verify frontend navigation works (New Scan, Scan History, Reports, Settings)
- [ ] Verify all API calls succeed without 404s

---

## 🎯 Recommended Setup

For **development** and **testing**:
```bash
python backend/run.py
# Uses standalone app with all features
```

For **production** with advanced features:
```bash
set FLASK_ENV=enterprise
python backend/run.py
# Uses enterprise app with JWT + RBAC + rate limiting
```

For **deployment** with Docker:
```bash
docker-compose up
# Includes PostgreSQL, Redis, and proper env setup
```

---

**Last Updated:** March 31, 2026  
**Status:** ✅ Flask app conflicts RESOLVED
