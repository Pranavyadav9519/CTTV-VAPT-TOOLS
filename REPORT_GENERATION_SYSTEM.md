"""
COMPREHENSIVE REPORT GENERATION DOCUMENTATION
Production-Grade Implementation Guide
"""

# ============================================================================
# TABLE OF CONTENTS
# ============================================================================

1. OVERVIEW
2. ARCHITECTURE
3. REPORT SERVICE
4. API ENDPOINTS
5. CELERY TASKS
6. HTML REPORT TEMPLATE
7. DATABASE INTEGRATION
8. CONFIGURATION
9. USAGE EXAMPLES
10. DEPLOYMENT
11. TROUBLESHOOTING

# ============================================================================
# 1. OVERVIEW - CCTV VAPT Report Generation System
# ============================================================================

## Purpose
Provides enterprise-grade report generation for vulnerability assessment scans
with multiple formats (JSON,HTML), async processing, and audit logging.

## Key Features
✓ Real-time database queries for actual scan data
✓ Multiple report formats (JSON, HTML with full styling)
✓ Async background processing via Celery
✓ File-based storage with checksum verification
✓ Comprehensive audit logging
✓ Multi-tenant support with tenant isolation  
✓ Immutable reports for compliance
✓ Report versioning and comparison
✓ Automatic cleanup of old reports
✓ API-first design

## Technology Stack
- ReportService: Core business logic
- ReportAPI: RESTful endpoints with flask blueprints
- ReportTasks: Celery async processing
- Database: SQLAlchemy ORM with PostgreSQL
- Storage: File system + database metadata
- Security: JWT auth, role-based access, audit logging

# ============================================================================
# 2. ARCHITECTURE - High-Level Design
# ============================================================================

## Layered Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                     CLIENT / API CONSUMER                      │
└─────────────────────────────┬─────────────────────────────────┘
                              │
┌─────────────────────────────▼─────────────────────────────────┐
│              REPORT API BLUEPRINT (Flask)                      │
│  - /api/reports (POST, GET)                                   │
│  - /api/reports/<id> (GET, DELETE)                            │
│  - /api/reports/<id>/download (GET)                           │
│  - /api/reports/compare (POST)                                │
│  - /api/reports/stats (GET)                                   │
└─────────────────────────────┬─────────────────────────────────┘
                              │
┌─────────────────────────────▼─────────────────────────────────┐
│            REPORT SERVICE (Business Logic)                     │
│  - generate_report()                                           │
│  - _gather_scan_data()                                        │
│  - _format_html_report()                                      │
│  - get_report()                                               │
│  - list_reports()                                             │
│  - delete_report()                                            │
└─────────────────────────────┬─────────────────────────────────┘
                              │
┌─────────────────────────────▼─────────────────────────────────┐
│         REPOSITORY LAYER (Data Access)                         │
│  - ReportRepository.get_by_report_id()                        │
│  - ReportRepository.get_reports_by_scan()                     │
│  - AuditLogRepository.log_action()                            │
└─────────────────────────────┬─────────────────────────────────┘
                              │
┌─────────────────────────────▼─────────────────────────────────┐
│           DATABASE MODELS (ORM Entities)                       │
│  - Report: report_id, scan_id, format, file_path, checksum   │
│  - Scan: scan_id, status, network_range, devices_found       │
│  - Device: ip_address, vulnerabilities[], ports[]            │
│  - Vulnerability: title, severity, cvss_score, cve_id        │
│  - AuditLog: action, resource_type, details, timestamp       │
└─────────────────────────────┬─────────────────────────────────┘
                              │
┌─────────────────────────────▼─────────────────────────────────┐
│              FILE SYSTEM & DATABASE                            │
│  - backend/reports/VAPT_Report_*.json                         │
│  - backend/reports/VAPT_Report_*.html                         │
│  - PostgreSQL/SQLite: reports table                           │
└───────────────────────────────────────────────────────────────┘
```

## Data Flow: Scanner → DB → Report → File

```
1. Scan runs and completes
   └─> Devices, Ports, Vulnerabilities stored in DB

2. User requests report generation (via API)
   └─> Report Service queries all related data from DB

3. Service formats data into JSON/HTML
   └─> Writes file to backend/reports/

4. Report metadata stored in DB
   └─> report_id, file_path, checksum for audit trail

5. File available for download via API
   └─> Content-type appropriate to format
```

# ============================================================================
# 3. REPORT SERVICE - Detailed Implementation
# ============================================================================

## ReportService Class Location
File: backend/core/services.py
Import: from backend.core.services import ReportService

## Main Methods

### generate_report()
Purpose: Create comprehensive report and save to database
Signature: 
  def generate_report(scan_id: int, report_format: str, user_id: Optional[int], 
                     tenant_id: Optional[str]) -> Tuple[Optional[Dict], bool]

Returns:
  - On success: (report_data_dict, True)
  - On failure: (None, False)

Process:
  1. Validates scan exists and is completed
  2. Gathers all scan data from database
  3. Formats based on report_format parameter
  4. Creates report file in backend/reports/
  5. Calculates SHA256 checksum
  6. Saves metadata to Report table
  7. Logs action to AuditLog

Example:
  report_data, success = ReportService.generate_report(
      scan_id=42,
      report_format='html',
      user_id=3,
      tenant_id='tenant-001'
  )
  if success:
      print(f"Report ID: {report_data['report_id']}")

### _gather_scan_data()
Purpose: Query database for complete scan information
Returns: Dictionary with nested structure of all scan data

Data Gathered:
  - Scan metadata (ID, operator, duration, timestamps)
  - Summary statistics (host count, CCTV device count)
  - Severity breakdown (critical, high, medium, low)
  - All discovered devices with:
    - IP address, MAC, manufacturer, device type
    - CCTV detection status, confidence score
    - All open ports with service detection
    - All vulnerabilities with details

Structure:
  {
    'report_id': 'abc123',
    'operator': 'operator_name',
    'network_range': '192.168.1.0/24',
    'duration_seconds': 3600,
    'devices': [
      {
        'ip_address': '192.168.1.100',
        'mac_address': '00:11:22:33:44:55',
        'device_type': 'ip_camera',
        'vulnerabilities': [
          {
            'title': 'Default Credentials',
            'severity': 'critical',
            'cvss_score': 9.8,
            'cve_id': 'CVE-2024-XXXXX'
          }
        ]
      }
    ],
    'summary': {
      'total_hosts': 50,
      'cctv_devices': 8,
      'vulnerabilities': 23,
      'severity_breakdown': {
        'critical': 5,
        'high': 8,
        'medium': 7,
        'low': 3
      }
    }
  }

### _format_html_report()
Purpose: Convert raw data to formatted HTML with styling
Returns: Complete HTML string ready to write to file

Features:
  - Professional styling with CSS
  - Color-coded severity indicators
  - Responsive grid layout
  - Executive summary section
  - Detailed device inventory
  - Vulnerability listings with metadata
  - Risk assessment summary
  - Footer with compliance notices

Output: production-ready HTML file suitable for:
  - Email distribution
  - Web viewing
  - PDF conversion via browser print
  - Stakeholder presentation

### get_report()
Purpose: Retrieve report metadata from database
Returns: Report data dictionary or None if not found

Validation:
  - Checks tenant_id matches (multi-tenant isolation)
  - Soft-delete filtering (deleted reports not returned)
  - Cannot access deleted reports

### list_reports()
Purpose: Retrieve multiple reports with pagination and filtering
Signature:
  def list_reports(tenant_id: str, scan_id: Optional[int],
                  limit: int, offset: int) -> Tuple[List[Dict], int, bool]

Returns:
  - Tuple of (report_list, total_count, success_bool)
  - Paginated results for UI display
  - Total count for pagination controls

### delete_report()
Purpose: Soft-delete a report (mark as deleted, don't remove)
Returns: Tuple of (success, deleted_bool)

Restrictions:
  - Cannot delete if is_immutable = True
  - Only soft-delete (preserved for audit trail)
  - Logs deletion to AuditLog

# ============================================================================
# 4. API ENDPOINTS - Complete Reference
# ============================================================================

## Base URL
/api/reports

## Authentication
All endpoints require:
- JWT token in Authorization header
- X-Tenant-ID header for multi-tenant isolation

## Headers Required
```
Authorization: Bearer <jwt_token>
X-Tenant-ID: <tenant_id>
Content-Type: application/json (for POST/PUT)
```

## 1. POST /api/reports - Generate New Report
**Purpose**: Create and save a report for a completed scan
**Authentication**: Required (@require_auth)
**Authorization**: Required tenant header

Request Body:
```json
{
  "scan_id": 42,
  "report_format": "html|json"
}
```

Response (201 Created):
```json
{
  "success": true,
  "data": {
    "report_id": "abc123def456",
    "scan_id": 42,
    "format": "html",
    "file_path": "/path/to/report.html",
    "file_size": 24567,
    "generated_by": "operator1",
    "generated_at": "2026-03-26T10:30:00"
  }
}
```

Error Cases:
- 400: Invalid report_format
- 403: Scan belongs to different tenant
- 404: Scan not found
- 400: Scan not completed yet
- 500: Generation failed

## 2. GET /api/reports - List Reports
**Purpose**: Retrieve all reports for tenant with pagination
**Authentication**: Required
**Authorization**: Tenant-scoped

Query Parameters:
- scan_id (optional): Filter by specific scan
- limit (optional): Results per page (default 20, max 100)
- offset (optional): Pagination offset (default 0)

Response (200 OK):
```json
{
  "success": true,
  "data": {
    "reports": [
      {
        "report_id": "abc123",
        "scan_id": 42,
        "format": "json",
        "file_size": 5242,
        "generated_by": "operator1",
        "generated_at": "2026-03-26T10:30:00"
      }
    ],
    "total": 42,
    "limit": 20,
    "offset": 0
  }
}
```

## 3. GET /api/reports/<report_id> - Get Report Details
**Purpose**: Retrieve specific report metadata
**Authentication**: Required
**Authorization**: Tenant-scoped

Response (200 OK):
```json
{
  "success": true,
  "data": {
    "report_id": "abc123",
    "scan_id": 42,
    "format": "json",
    "file_path": "backend/reports/VAPT_Report_abc123.json",
    "checksum": "sha256hash...",
    "generated_by": "operator1",
    "is_immutable": true,
    "generated_at": "2026-03-26T10:30:00"
  }
}
```

Error Cases:
- 404: Report not found or access denied

## 4. GET /api/reports/<report_id>/download - Download Report File
**Purpose**: Download the actual report file
**Authentication**: Required
**Authorization**: Tenant-scoped

Response:
- 200 OK with file content
- Content-Type: application/json or text/html based on format
- Content-Disposition: attachment; filename="report.ext"
- Logs download action to audit log

## 5. DELETE /api/reports/<report_id> - Delete Report
**Purpose**: Soft-delete a report
**Authentication**: Required
**Authorization**: Admin or Operator role only

Response (200 OK):
```json
{
  "success": true,
  "data": {
    "report_id": "abc123",
    "status": "deleted"
  }
}
```

Error Cases:
- 403: Cannot delete immutable reports
- 403: User lacks required role
- 404: Report not found

## 6. POST /api/reports/compare - Compare Two Reports
**Purpose**: Show differences between two scans
**Authentication**: Required

Request Body:
```json
{
  "report_id_1": "abc123",
  "report_id_2": "def456"
}
```

Response (200 OK):
```json
{
  "success": true,
  "data": {
    "new_vulnerabilities_count": 5,
    "resolved_vulnerabilities_count": 2,
    "new_vulnerabilities": [
      ["192.168.1.100", "Default Credentials", "CVE-2024-XXXXX"]
    ],
    "resolved_vulnerabilities": [
      ["192.168.1.50", "XSS Vulnerability", null]
    ]
  }
}
```

## 7. GET /api/reports/stats - Report Statistics
**Purpose**: Get aggregate statistics about all reports
**Authentication**: Required
**Authorization**: Tenant-scoped

Response (200 OK):
```json
{
  "success": true,
  "data": {
    "total_reports": 42,
    "by_format": {
      "json": 20,
      "html": 15,
      "pdf": 7
    },
    "recent_reports": [
      {
        "report_id": "abc123",
        "scan_id": 42,
        "generated_at": "2026-03-26T10:30:00"
      }
    ]
  }
}
```

# ============================================================================
# 5. CELERY ASYNC TASKS - Background Processing
# ============================================================================

## File Location
backend/tasks/report_tasks.py

## Task Registration
Tasks are auto-registered via:
```python
from backend.tasks.report_tasks import generate_report_async
```

## Available Tasks

### 1. generate_report_async()
Purpose: Generate report asynchronously with retry logic
Usage:
```python
from backend.enterprise.celery_app import celery_app
from backend.tasks.report_tasks import generate_report_async

# Queue task
task = generate_report_async.delay(
    scan_id=42,
    report_format='html',
    user_id=3,
    tenant_id='tenant-001'
)

# Check status
task_id = task.id
# Get result: task.get(timeout=300)
```

Features:
- Auto-retry on failure (max 3 retries)
- 60-second retry delay
- Logs success/failure to AuditLog

### 2. generate_multiple_format_reports()
Purpose: Generate reports in multiple formats (JSON, HTML, PDF)
Usage:
```python
task = generate_multiple_format_reports.delay(
    scan_id=42,
    formats=['json', 'html'],
    user_id=3,
    tenant_id='tenant-001'
)
```

Returns: Status for each format with task IDs for monitoring

### 3. cleanup_old_reports()
Purpose: Soft-delete reports older than specified days
Usage:
```python
task = cleanup_old_reports.delay(days_old=90)
```

Behavior:
- Finds reports older than threshold
- Soft-deletes (marks is_deleted=True)
- Optionally deletes files from disk
- Non-immutable reports only
- Logs statistics

Scheduling: Use Celery Beat for daily execution

### 4. cleanup_orphaned_report_files()
Purpose: Remove files without database records
Usage:
```python
task = cleanup_orphaned_report_files.delay()
```

Behavior:
- Scans backend/reports/ directory
- Finds files not in Report table
- Deletes orphaned files
- Returns count of deleted files

### 5. archive_reports()
Purpose: Archive old reports to separate location
Usage:
```python
task = archive_reports.delay(
    days_old=30,
    archive_path='backend/reports_archive'
)
```

Behavior:
- Copies reports older than threshold
- Maintains original file structure
- Adds archive timestamp to metadata
- Useful for compliance retention

### 6. validate_report_checksums()
Purpose: Detect file corruption
Usage:
```python
task = validate_report_checksums.delay()
```

Behavior:
- Recalculates SHA256 for all reports
- Compares with stored checksum
- Reports mismatches
- Identifies missing files
- Returns validation summary

Scheduling: Weekly via Celery Beat

## Celery Configuration

Environment Variables Required:
```
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
```

Beat Schedule (in config):
```python
CELERY_BEAT_SCHEDULE = {
    'cleanup-reports': {
        'task': 'tasks.cleanup_old_reports',
        'schedule': crontab(hour=2, minute=0),  # 2 AM daily
        'args': (90,)
    },
    'validate-checksums': {
        'task': 'tasks.validate_report_checksums',
        'schedule': crontab(day_of_week=0, hour=3, minute=0),  # Weekly
    }
}
```

## Task Monitoring

Get Task Status:
```python
from celery.result import AsyncResult

task = AsyncResult(task_id)
print(task.state)  # PENDING, STARTED, SUCCESS, FAILURE
print(task.result)  # Result data or exception
```

# ============================================================================
# 6. HTML REPORT TEMPLATE - Design & Styling
# ============================================================================

## Template Structure

The HTML report is auto-generated by ReportService._format_html_report()
and includes:

### Header Section
- Professional branding
- Scan metadata (network range, operator, dates)
- Report generation timestamp

### Executive Summary
- Four color-coded severity boxes (Critical, High, Medium, Low)
- Count of each severity level
- Visual emphasis on critical findings

### Key Statistics
- Total hosts discovered
- CCTV devices identified
- Total vulnerabilities found
- Affected devices count

### Device Inventory
Detailed listing of each discovered device:
- IP address & device type
- MAC address
- Manufacturer
- Confidence score
- CCTV badge if applicable

### Vulnerability Details
For each device with vulnerabilities:
- Vulnerability title
- CVE identifier
- CVSS score
- Severity level (color-coded)
- Remediation guidance

### Professional Styling
- Responsive grid layout
- Color scheme: Blues, Reds, Oranges
- Print-friendly formatting
- Semantic HTML5 structure
- Accessibility considerations

### Footer
- Report ID
- Generation timestamp
- Compliance notices
- Confidentiality warnings

## Customization

To modify HTML template, edit _format_html_report() in:
File: backend/core/services.py
Search for: def _format_html_report()

Template uses f-strings, so modify inline CSS/HTML as needed.

# ============================================================================
# 7. DATABASE INTEGRATION - Real Data Source
# ============================================================================

## Data Retrieval Flow

```
Report Request
    ↓
ReportService.generate_report()
    ↓
_gather_scan_data()
    ↓
Query Scan by ID
    → SELECT * FROM scans WHERE id = ?
    ↓
Query Devices by Scan
    → SELECT * FROM devices WHERE scan_id = ?
    ↓
Query Ports per Device
    → SELECT * FROM ports WHERE device_id = ?
    ↓
Query Vulnerabilities per Device
    → SELECT * FROM vulnerabilities WHERE device_id = ?
    ↓
Aggregate & Format
    ↓
File Write + DB Save
```

## Key Database Queries

### Get Complete Scan Data
```python
from backend.core.models import Scan, Device, Vulnerability
from backend.core.repositories import ScanRepository, DeviceRepository

scan = ScanRepository.get_by_id(scan_id)
devices = DeviceRepository.get_devices_by_scan(scan_id)

for device in devices:
    vulns = VulnerabilityRepository.get_vulnerabilities_by_device(device.id)
```

### Real Data Validation
ReportService automatically:
1. Verifies scan exists
2. Checks scan status == COMPLETED
3. Verifies tenant_id matches (security)
4. Soft-delete filtering (only active records)
5. Counts by severity from actual data

## Database Models Used

Scan Model:
- id: int
- scan_id: str
- tenant_id: str
- network_range: str
- total_hosts_found: int
- cctv_devices_found: int
- vulnerabilities_found: int
- status: ScanStatus enum
- started_at: datetime
- completed_at: datetime

Device Model:
- id: int
- scan_id: int(FK)
- ip_address: str
- mac_address: str
- manufacturer: str
- device_type: str
- is_cctv: bool
- confidence_score: float

Vulnerability Model:
- id: int
- device_id: int(FK)
- title: str
- severity: SeverityLevel enum
- cvss_score: float
- cve_id: str
- remediation: str

Report Model:
- id: int
- report_id: str (unique)
- scan_id: int(FK)
- tenant_id: str
- title: str
- format: str (json, html, pdf)
- file_path: str
- file_size: int
- checksum: str (SHA256)
- generated_by: str
- is_immutable: bool
- generated_at: datetime

AuditLog Model:
- id: int
- user_id: int(FK)
- action: str
- resource_type: str
- resource_id: str
- details: JSON
- status: str
- timestamp: datetime

# ============================================================================
# 8. CONFIGURATION - Environment & Settings
# ============================================================================

## Environment Variables

```bash
# Report Storage
REPORT_STORAGE_PATH=backend/reports
REPORT_MAX_SIZE=100MB
REPORT_RETENTION_DAYS=90

# Report Generation
REPORT_TIMEOUT=300  # seconds
REPORT_CHUNK_SIZE=1000  # devices per chunk

# Celery Configuration
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
CELERY_TASK_SOFT_TIME_LIMIT=600
CELERY_TASK_TIME_LIMIT=900

# Audit Logging
AUDIT_LOG_ENABLED=True
AUDIT_LOG_DETAILS_ENABLED=True

# Multi-Tenancy
TENANT_ISOLATION_ENABLED=True
```

## Flask Configuration

```python
# In backend/core/config.py

class Config:
    # Report settings
    REPORT_DIR = Path('backend/reports')
    REPORT_ARCHIVE_DIR = Path('backend/reports_archive')
    REPORT_MAX_SIZE = 100 * 1024 * 1024  # 100MB
    
    # Cleanup settings
    REPORT_RETENTION_DAYS = 90
    CLEANUP_SCHEDULE_HOUR = 2  # 2 AM
    
    # Validation
    VALIDATE_CHECKSUMS_WEEKLY = True
```

## Database Configuration

PostgreSQL recommended for production:
```
postgresql://user:pass@localhost:5432/vapt_db
```

SQLite for development:
```
sqlite:///vapt.db
```

# ============================================================================
# 9. USAGE EXAMPLES - Code Samples
# ============================================================================

## Example 1: API Usage - Generate Report

```bash
# POST request to generate report
curl -X POST http://localhost:5000/api/reports \
  -H "Authorization: Bearer <jwt_token>" \
  -H "X-Tenant-ID: tenant-001" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": 42,
    "report_format": "html"
  }'

# Response
{
  "success": true,
  "data": {
    "report_id": "abc123def456",
    "scan_id": 42,
    "format": "html",
    "file_size": 24567,
    "generated_at": "2026-03-26T10:30:00"
  }
}
```

## Example 2: API Usage - Download Report

```bash
curl -X GET http://localhost:5000/api/reports/abc123def456/download \
  -H "Authorization: Bearer <jwt_token>" \
  -H "X-Tenant-ID: tenant-001" \
  -o report.html

# File saved as report.html
```

## Example 3: Python - Generate Report Synchronously

```python
from backend.core.services import ReportService
from flask import Flask

app = Flask(__name__)

with app.app_context():
    report_data, success = ReportService.generate_report(
        scan_id=42,
        report_format='json',
        user_id=3,
        tenant_id='tenant-001'
    )
    
    if success:
        print(f"Generated report: {report_data['report_id']}")
        print(f"File: {report_data['file_path']}")
        print(f"Checksum: {report_data.get('checksum')}")
```

## Example 4: Python - Generate Report Asynchronously

```python
from backend.tasks.report_tasks import generate_report_async
from backend.enterprise.celery_app import celery_app

# Queue task
task = generate_report_async.delay(
    scan_id=42,
    report_format='html',
    user_id=3,
    tenant_id='tenant-001'
)

print(f"Task queued: {task.id}")

# Check status
import time
for i in range(10):
    print(f"Status: {task.state}")
    if task.state == 'SUCCESS':
        result = task.result
        print(f"Result: {result}")
        break
    time.sleep(1)
```

## Example 5: Python - List Reports with Pagination

```python
from backend.core.services import ReportService

reports, total, success = ReportService.list_reports(
    tenant_id='tenant-001',
    scan_id=None,  # None = all scans
    limit=20,
    offset=0
)

if success:
    for report in reports:
        print(f"{report['report_id']}: {report['file_size']} bytes")
    print(f"Total: {total}")
```

## Example 6: Python - Compare Two Reports

```python
# Via API (recommended)
import requests

response = requests.post(
    'http://localhost:5000/api/reports/compare',
    headers={
        'Authorization': f'Bearer {token}',
        'X-Tenant-ID': 'tenant-001'
    },
    json={
        'report_id_1': 'abc123',
        'report_id_2': 'def456'
    }
)

comparison = response.json()['data']
print(f"New vulnerabilities: {comparison['new_vulnerabilities_count']}")
print(f"Resolved: {comparison['resolved_vulnerabilities_count']}")
```

# ============================================================================
# 10. DEPLOYMENT - Production Setup
# ============================================================================

## Docker Deployment

Dockerfile snippet:
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .

# Volumes for reports
VOLUME /app/backend/reports
VOLUME /app/backend/reports_archive

# Create report directories
RUN mkdir -p backend/reports backend/reports_archive

CMD ["gunicorn", "-b", "0.0.0.0:5000", "wsgi:app"]
```

Docker Compose snippet:
```yaml
services:
  app:
    build: .
    ports:
      - 5000:5000
    environment:
      CELERY_BROKER_URL: redis://redis:6379/0
      DATABASE_URL: postgresql://user:pass@postgres:5432/vapt
    volumes:
      - ./backend/reports:/app/backend/reports
      - ./backend/reports_archive:/app/backend/reports_archive
    depends_on:
      - postgres
      - redis
      - celery

  celery:
    build: .
    command: celery -A backend.enterprise.celery_app worker -l info
    environment:
      CELERY_BROKER_URL: redis://redis:6379/0
    depends_on:
      - redis

  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: vapt
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - 6379:6379

volumes:
  postgres_data:
```

## Kubernetes Deployment (Helm Values)

```yaml
# values.yaml
replication:
  count: 3

storage:
  reports:
    size: 10Gi
    path: /app/backend/reports
  archive:
    size: 50Gi
    path: /app/backend/reports_archive

celery:
  workers: 5
  replicas: 3

resources:
  requests:
    cpu: "500m"
    memory: "512Mi"
  limits:
    cpu: "2"
    memory: "2Gi"
```

## File System Permissions

```bash
# Create report directories
mkdir -p /var/vapt/reports
mkdir -p /var/vapt/reports_archive

# Set permissions
chmod 750 /var/vapt/reports
chown vapt:vapt /var/vapt/reports

# Enable write access for web server user
chmod 775 /var/vapt/reports
```

## Monitoring

Prometheus metrics to track:
```
report_generation_duration_seconds
report_generation_errors_total
report_file_size_bytes
report_checksum_validation_failures
celery_task_duration_seconds
```

# ============================================================================
# 11. TROUBLESHOOTING - Common Issues & Solutions
# ============================================================================

## Issue 1: Report Generation Fails with "Scan Not Found"
**Symptom**: 404 error when trying to generate report
**Cause**: Scan ID doesn't exist or already deleted
**Solution**:
  1. Verify scan exists: SELECT * FROM scans WHERE id = ?
  2. Check tenant_id matches request
  3. Confirm scan status = COMPLETED
  4. Check for soft-delete flag (is_deleted = false)

## Issue 2: File Path Not Found on Download
**Symptom**: "Report file not found on disk" error
**Cause**: File deleted or path incorrect
**Solution**:
  1. Verify file exists at stored path
  2. Check file permissions (readable by app user)
  3. Check disk space available
  4. Run cleanup orphaned files to fix
  5. Regenerate report

## Issue 3: Checksum Mismatch Detected
**Symptom**: Validation error indicating file corruption
**Cause**: File modified after generation or disk corruption
**Solution**:
  1. Back up the report file immediately
  2. Mark report as corrupted in metadata
  3. Notify audit trail
  4. Regenerate report from original scan data
  5. Replace corrupted file

## Issue 4: Celery Task Never Completes
**Symptom**: Task status stays "PENDING" or "STARTED"
**Cause**: Celery worker not running, Redis down, or stuck task
**Solution**:
  1. Check Celery worker status: celery -A backend.enterprise.celery_app inspect active
  2. Verify Redis connection: redis-cli ping
  3. Check task queue: celery -A backend.enterprise.celery_app inspect registered
  4. Check logs: docker logs <celery_container>
  5. Restart worker: systemctl restart celery

## Issue 5: Out of Disk Space for Reports
**Symptom**: Report generation fails with "No space left on device"
**Cause**: Reports directory full (old reports not cleaned up)
**Solution**:
  1. Run cleanup task immediately: cleanup_old_reports.delay(days_old=7)
  2. Run archive task: archive_reports.delay(days_old=30)
  3. Check disk usage: du -sh backend/reports
  4. Delete old archived reports if needed
  5. Configure automated cleanup to run more frequently

## Issue 6: Multi-Tenant Data Leak
**Symptom**: User can access another tenant's reports
**Cause**: Missing tenant_id filter in queries
**Solution**:
  1. Verify all queries filter by tenant_id
  2. Check @require_tenant_header decorator applied
  3. Review database query results for tenant isolation
  4. Audit who accessed which reports (check AuditLog)
  5. Regenerate reports if sensitive data exposed

## Issue 7: Report Service Import Errors
**Symptom**: "Cannot import ReportService" or module not found
**Cause**: Python path issues or missing dependencies
**Solution**:
  1. Verify PYTHONPATH includes project root
  2. Check all required packages installed: pip install -r requirements.txt
  3. Verify file locations: ls -la backend/core/services.py
  4. Check naming: ensure "services.py" not "service.py"
  5. Reload Python interpreter/restart app

## Issue 8: HTML Report Not Rendering Correctly
**Symptom**: Styling broken or layout messed up in browser
**Cause**: CSS issues or incompatible browser
**Solution**:
  1. Open in modern browser (Chrome 90+, Firefox 88+)
  2. Check browser console for errors (F12)
  3. Verify CSS variables loaded
  4. Try exporting to PDF (often better rendering)
  5. Check for special characters breaking HTML
  6. Review HTML source for syntax errors

## Issue 9: Database Connection Pool Exhausted
**Symptom**: Errors after generating multiple reports
**Cause**: Too many concurrent report generation requests
**Solution**:
  1. Check database pool settings in config
  2. Increase pool_size and max_overflow:
     pool_size=20, max_overflow=40
  3. Implement request queuing
  4. Use async Celery tasks instead of sync
  5. Monitor active connections: SELECT count(*) FROM pg_stat_activity

## Issue 10: Report Comparison Returns Empty
**Symptom**: No differences shown between two reports
**Cause**: Both reports identical or vulnerability data not structured correctly
**Solution**:
  1. Verify both reports exist and are readable
  2. Check vulnerability data structure in JSON
  3. Manually compare scan results: SELECT * FROM vulnerabilities WHERE scan_id IN (?, ?)
  4. Ensure CVE IDs populated correctly
  5. Check if both scans have vulnerabilities to compare

## Logging & Debugging

Enable detailed logging:
```python
# In config.py
LOGGING_LEVEL = logging.DEBUG

# In code
import logging
logger = logging.getLogger(__name__)
logger.debug(f"Report data: {scan_data}")
logger.info(f"Report generated: {report_id}")
logger.error(f"Generation failed: {error}")
```

Check logs:
```bash
# Docker
docker logs <container_id> | grep -i report

# Files
tail -f /var/log/vapt/app.log
tail -f /var/log/vapt/celery.log
```

Database queries for debugging:
```sql
-- Check recent reports
SELECT * FROM reports ORDER BY generated_at DESC LIMIT 10;

-- Check report downloads
SELECT * FROM audit_logs WHERE action = 'report_downloaded' ORDER BY timestamp DESC;

-- Check failed generations
SELECT * FROM audit_logs WHERE action = 'report_generated' AND status = 'failure';

-- Verify file paths exist
SELECT report_id, file_path FROM reports WHERE file_path IS NOT NULL LIMIT 5;
```

# ============================================================================
# CONCLUSION
# ============================================================================

This comprehensive report generation system provides:

✓ Real database integration for actual scan data
✓ Professional HTML and JSON report formatting
✓ Production-grade async processing with Celery
✓ Multi-tenant security with tenant isolation
✓ Audit trail for compliance requirements
✓ File management with checksums
✓ API-first design for enterprise integration
✓ Scalable architecture for high-volume deployments

For questions or issues, refer to the troubleshooting section or check logs.
"""
