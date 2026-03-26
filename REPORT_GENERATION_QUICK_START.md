# Report Generation System - Quick Start Guide

## What's New

Complete **production-grade report generation** system with real database integration has been implemented.

## Components Implemented

### 1. Enhanced ReportService (backend/core/services.py)
- `generate_report()` - Creates reports from real database data
- `_gather_scan_data()` - Queries all scan information from DB
- `_format_html_report()` - Generates styled HTML reports
- `get_report()`, `list_reports()`, `delete_report()` - Report CRUD operations

### 2. Report API Endpoints (backend/api/reports.py - NEW FILE)
```
POST   /api/reports                    - Generate new report
GET    /api/reports                    - List all reports (paginated)
GET    /api/reports/<report_id>        - Get report details
GET    /api/reports/<report_id>/download - Download report file
DELETE /api/reports/<report_id>        - Delete report
POST   /api/reports/compare            - Compare two reports
GET    /api/reports/stats              - Report statistics
```

### 3. Async Celery Tasks (backend/tasks/report_tasks.py - NEW FILE)
- `generate_report_async()` - Background report generation with retries
- `generate_multiple_format_reports()` - Batch report generation
- `cleanup_old_reports()` - Auto-delete old reports (Scheduled)
- `cleanup_orphaned_report_files()` - Remove orphaned files
- `archive_reports()` - Archive old reports
- `validate_report_checksums()` - Detect file corruption (Scheduled)

### 4. Database Integration
- Reports stored in `Report` model with metadata
- Real data queries from:
  - Scan, Device, Port, Vulnerability tables
  - AuditLog for compliance tracking
  - Tenant isolation on all queries

### 5. HTML Report Template
Professional styled reports with:
- Color-coded severity indicators (Critical, High, Medium, Low)
- Executive summary with statistics
- Device inventory with detailed info
- Vulnerability listing with remediation
- Print-friendly CSS styling
- Compliance footer

### 6. Comprehensive Documentation
- `REPORT_GENERATION_SYSTEM.md` - Complete implementation guide (11 sections)
  - Architecture overview
  - API reference with examples
  - Celery task documentation
  - Database integration details
  - Deployment instructions
  - Troubleshooting guide

## Quick Start - Generate Your First Report

### 1. Via REST API

```bash
# Generate report
curl -X POST http://localhost:5000/api/reports \
  -H "Authorization: Bearer <token>" \
  -H "X-Tenant-ID: tenant-001" \
  -H "Content-Type: application/json" \
  -d '{"scan_id": 42, "report_format": "html"}'

# Response includes report_id
# Use report_id to download

curl -X GET http://localhost:5000/api/reports/abc123/download \
  -H "Authorization: Bearer <token>" \
  -H "X-Tenant-ID: tenant-001" \
  -o report.html
```

### 2. Via Python

```python
from backend.core.services import ReportService

# Synchronous
report_data, success = ReportService.generate_report(
    scan_id=42,
    report_format='html',
    user_id=3,
    tenant_id='tenant-001'
)

if success:
    print(f"Report ID: {report_data['report_id']}")
```

### 3. Async (Background)

```python
from backend.tasks.report_tasks import generate_report_async

# Queue task  
task = generate_report_async.delay(
    scan_id=42,
    report_format='html',
    user_id=3,
    tenant_id='tenant-001'
)

# Check status
print(f"Task ID: {task.id}")
print(f"Status: {task.state}")
```

## Data Sources

Reports pull **real data** from:
- **Scans**: Network range, dates, operator name, status
- **Devices**: IP/MAC, manufacturer, device type, CCTV detection
- **Ports**: Port numbers, services, banners
- **Vulnerabilities**: Title, severity, CVSS, CVE ID, remediation
- **Audit Logs**: Who generated the report, when, success/failure

## Report Formats Supported

| Format | Usage | Storage |
|--------|-------|---------|
| **JSON** | Data export, API integration | backend/reports/*.json |
| **HTML** | Email, web viewing, presentation | backend/reports/*.html |
| **PDF** | Browser print-to-PDF conversion | Generated on demand |

## Security Features

✓ **Multi-tenant isolation** - X-Tenant-ID header validation
✓ **JWT authentication** - All endpoints require valid token
✓ **Role-based access** - Delete restricted to admin/operator
✓ **Audit logging** - All report actions logged
✓ **Immutable reports** - Cannot delete compliance reports
✓ **Checksum verification** - SHA256 validation on each report
✓ **Soft deletes** - Compliance retention of deleted reports

## File Storage

- **Location**: `backend/reports/`  (configurable)
- **Naming**: `VAPT_Report_{report_id}.{format}`
- **Checksums**: SHA256 stored in database
- **Cleanup**: Automatic after 90 days (configurable)
- **Archival**: Can archive to `backend/reports_archive/`

## Configuration

### Environment Variables

```bash
# Report settings
REPORT_STORAGE_PATH=backend/reports
REPORT_RETENTION_DAYS=90
REPORT_TIMEOUT=300

# Celery (async tasks)
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
```

### Database Connection

PostgreSQL (recommended):
```
postgresql://user:pass@localhost:5432/vapt_db
```

SQLite (development):
```
sqlite:///vapt.db
```

## Monitoring & Maintenance

```bash
# Check recent reports
curl http://localhost/api/reports \
  -H "Authorization: Bearer <token>" \
  -H "X-Tenant-ID: tenant-001"

# Get report statistics
curl http://localhost/api/reports/stats \
  -H "Authorization: Bearer <token>" \
  -H "X-Tenant-ID: tenant-001"

# Validate checksums (async)
# Run via Celery: validate_report_checksums.delay()

# Clean old reports (async)
# Run via Celery: cleanup_old_reports.delay(days_old=90)
```

## Troubleshooting

**Report generation fails?**
- Check scan status is COMPLETED: `SELECT status FROM scans WHERE id = ?`
- Verify tenant_id matches request header
- Check disk space: `df -h backend/reports/`

**Download returns 404?**
- Verify report exists: `SELECT * FROM reports WHERE report_id = ?`
- Check file exists on disk: `ls backend/reports/`
- Run cleanup orphaned: `cleanup_orphaned_report_files.delay()`

**Celery tasks hanging?**
- Check Redis: `redis-cli ping`
- Check worker: `celery -A backend.enterprise.celery_app inspect active`
- Restart worker: `systemctl restart celery`

## Next Steps

1. **Start generating reports** via API endpoints
2. **Monitor** report generation and storage metrics
3. **Configure** cleanup schedule (via Celery Beat)
4. **Set up** archival for compliance retention
5. **Integrate** report comparison for trend analysis
6. **Add** custom report templates if needed

## Files Created/Modified

| File | Type | Purpose |
|------|------|---------|
| backend/core/services.py | Modified | Enhanced ReportService |
| backend/api/reports.py | NEW | Report API endpoints |
| backend/tasks/report_tasks.py | NEW | Celery async tasks |
| backend/tasks/__init__.py | NEW | Task module exports |
| backend/app.py | Modified | Register reports blueprint |
| REPORT_GENERATION_SYSTEM.md | NEW | Comprehensive documentation |

## Support

For detailed information, see:
- `REPORT_GENERATION_SYSTEM.md` - Complete implementation guide
- API Endpoints - Swagger/OpenAPI via `/api/docs` (if enabled)
- Database schema - ER diagram in `ARCHITECTURE_GUIDE.md`
- Examples - Python code samples in documentation

---

**Status**: ✅ Complete and ready for production use
**Last Updated**: March 26, 2026
**Version**: 1.0.0
