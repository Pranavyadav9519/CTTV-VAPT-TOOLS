# VAPT Backend Codebase Analysis

**Date:** March 28, 2026  
**Focus:** Database models, scan data structure, API endpoints, and analytics recommendations

---

## 1. DATABASE MODELS & STRUCTURE

### 1.1 MODEL RELATIONSHIPS DIAGRAM

```
User (1) ──→ (M) Scan
User (1) ──→ (M) AuditLog
Scan (1) ──→ (M) Device
Scan (1) ──→ (M) Report
Scan (1) ──→ (M) AuditLog
Device (1) ──→ (M) Port
Device (1) ──→ (M) Vulnerability
Port (1) ──→ (M) Vulnerability
```

---

## 2. DETAILED MODEL STRUCTURE

### 2.1 USER Model
**File:** `backend/core/models.py` (Line 86-143)

**Purpose:** User account management with authentication and role-based access control

**Fields:**
- `id` (Integer, PK) - Primary key
- `email` (String[255], unique, indexed) - User email address
- `username` (String[100], unique, indexed) - Login username
- `password_hash` (String[512]) - PBKDF2:SHA256 hashed password
- `first_name` (String[100]) - User's first name
- `last_name` (String[100]) - User's last name
- `role` (Enum[UserRole]) - admin, operator, viewer
- `is_active` (Boolean) - Account status
- `is_verified` (Boolean) - Email verification status
- `last_login` (DateTime) - Last authentication timestamp
- `last_ip` (String[45]) - IP address of last login
- `failed_login_attempts` (Integer) - Failed login counter
- `locked_until` (DateTime) - Account lockout expiration
- `tenant_id` (String[36], indexed) - Multi-tenant isolation
- `created_at` (DateTime, indexed) - Record creation timestamp
- `updated_at` (DateTime) - Record update timestamp
- `is_deleted` (Boolean) - Soft delete flag

**Key Methods:**
- `set_password(password: str)` - Hash and validate password (min 8 chars)
- `check_password(password: str) → bool` - Verify password hash
- `can_access_scan(scan) → bool` - Role-based access check
- `to_dict() → dict` - JSON serialization

**Relationships:**
- `scans` (1→M) - Linked to Scan records via `user_id`
- `audit_logs` (1→M) - Linked to AuditLog records

---

### 2.2 SCAN Model
**File:** `backend/core/models.py` (Line 148-228)

**Purpose:** Represents a vulnerability assessment scan session

**Fields:**
- `id` (Integer, PK) - Primary key
- `scan_id` (String[50], unique, indexed) - Unique scan identifier
- `user_id` (Integer, FK → users.id) - Operator who initiated scan
- `tenant_id` (String[36], indexed) - Multi-tenant isolation
- `status` (Enum[ScanStatus]) - pending, queued, running, completed, failed, cancelled
- `scan_type` (String[50]) - Type of scan (default: "network_discovery")
- `network_range` (String[50]) - CIDR notation (e.g., "192.168.1.0/24")
- `description` (Text) - Scan description/notes
- `started_at` (DateTime) - Scan start timestamp
- `completed_at` (DateTime) - Scan completion timestamp
- `total_hosts_found` (Integer) - Count of discovered hosts
- `cctv_devices_found` (Integer) - Count of CCTV devices identified
- `vulnerabilities_found` (Integer) - Total vulnerability count
- `critical_count` (Integer) - Critical severity vulnerabilities
- `high_count` (Integer) - High severity vulnerabilities
- `medium_count` (Integer) - Medium severity vulnerabilities
- `low_count` (Integer) - Low severity vulnerabilities
- `error_message` (Text) - Error details if scan failed
- `celery_task_id` (String[36], indexed) - Async task reference
- `progress_percent` (Integer) - Scan progress (0-100)
- `created_at` (DateTime, indexed) - Record creation timestamp
- `updated_at` (DateTime) - Record update timestamp
- `is_deleted` (Boolean) - Soft delete flag

**Key Methods:**
- `get_severity_breakdown() → dict` - Returns {critical, high, medium, low} counts
- `mark_running()` - Update status to RUNNING, set started_at
- `mark_completed()` - Update status to COMPLETED, set completed_at
- `mark_failed(error_msg: str)` - Update status to FAILED, record error message
- `to_dict() → dict` - JSON serialization with severity breakdown

**Relationships:**
- `devices` (1→M) - Cascade delete
- `reports` (1→M) - Cascade delete
- `audit_logs` (1→M) - Linked scan activity
- `operator` (←1) - Reference to User record

**Sample Data Flow:**
```
Scan Created (status=PENDING)
↓ (Task Queued)
Scan Updated (status=QUEUED, celery_task_id=xxx)
↓ (Task Starts)
Scan Updated (status=RUNNING, started_at=2026-03-28T10:30:00)
↓ (Devices Discovered)
Devices Created (scan_id=X)
↓ (Ports Scanned)
Ports Created (device_id=X)
↓ (Vulnerabilities Found)
Vulnerabilities Created
↓ (Scan Completes)
Scan Updated (status=COMPLETED, completed_at=2026-03-28T10:45:00, counts updated)
```

---

### 2.3 DEVICE Model
**File:** `backend/core/models.py` (Line 233-287)

**Purpose:** Represent discovered network devices (cameras, DVRs, etc.)

**Fields:**
- `id` (Integer, PK) - Primary key
- `scan_id` (Integer, FK → scans.id) - Associated scan
- `tenant_id` (String[36], indexed) - Multi-tenant isolation
- `ip_address` (String[45]) - IPv4/IPv6 address
- `mac_address` (String[17]) - MAC address (XX:XX:XX:XX:XX:XX format)
- `hostname` (String[255]) - DNS hostname or device name
- `manufacturer` (String[100]) - Device manufacturer (Hikvision, Dahua, etc.)
- `device_type` (Enum[DeviceType]) - ip_camera, dvr, nvr, encoder, unknown
- `model` (String[100]) - Device model number
- `firmware_version` (String[50]) - Firmware/OS version string
- `os_info` (String[255]) - Operating system details
- `is_cctv` (Boolean) - CCTV confidence flag
- `confidence_score` (Float) - Identification confidence (0.0-1.0)
- `last_seen` (DateTime) - Last discovery/verification timestamp
- `tags` (String[500]) - Comma-separated custom tags
- `created_at` (DateTime, indexed) - Record creation timestamp
- `updated_at` (DateTime) - Record update timestamp
- `is_deleted` (Boolean) - Soft delete flag

**Key Methods:**
- `to_dict() → dict` - JSON serialization with port/vulnerability counts

**Relationships:**
- `ports` (1→M) - Cascade delete
- `vulnerabilities` (1→M) - Cascade delete
- `scan` (←1) - Reference to Scan record

**Data Example:**
```json
{
  "id": 1,
  "ip_address": "192.168.1.100",
  "mac_address": "00:1A:2B:3C:4D:5E",
  "hostname": "camera-main-entrance",
  "manufacturer": "Hikvision",
  "device_type": "ip_camera",
  "model": "DS-2CD2143G0-I",
  "firmware_version": "V5.4.0_20200520",
  "is_cctv": true,
  "confidence_score": 0.98
}
```

---

### 2.4 PORT Model
**File:** `backend/core/models.py` (Line 292-324)

**Purpose:** Track open/accessible ports on devices

**Fields:**
- `id` (Integer, PK) - Primary key
- `device_id` (Integer, FK → devices.id) - Associated device
- `port_number` (Integer) - TCP/UDP port number (1-65535)
- `protocol` (String[10]) - tcp, udp
- `state` (String[20]) - open, closed, filtered
- `service_name` (String[50]) - Service name (http, https, telnet, ssh, etc.)
- `service_version` (String[100]) - Service/application version
- `banner` (Text) - Service banner/greeting text
- `is_encrypted` (Boolean) - SSL/TLS encryption status
- `scanned_at` (DateTime) - Port scan timestamp
- `created_at` (DateTime, indexed) - Record creation timestamp
- `updated_at` (DateTime) - Record update timestamp
- `is_deleted` (Boolean) - Soft delete flag

**Key Methods:**
- `to_dict() → dict` - JSON serialization with vulnerability count

**Relationships:**
- `vulnerabilities` (1→M) - Related vulnerabilities
- `device` (←1) - Reference to Device record

**Sample Data:**
```json
{
  "id": 1,
  "port_number": 80,
  "protocol": "tcp",
  "state": "open",
  "service_name": "http",
  "service_version": "GoAhead/2.5.0",
  "is_encrypted": false,
  "vulnerability_count": 3
}
```

---

### 2.5 VULNERABILITY Model
**File:** `backend/core/models.py` (Line 329-398)

**Purpose:** Store vulnerability findings with comprehensive vulnerability intelligence

**Fields:**
- `id` (Integer, PK) - Primary key
- `device_id` (Integer, FK → devices.id) - Affected device
- `port_id` (Integer, FK → ports.id, nullable) - Associated port (if applicable)
- `vuln_id` (String[50], unique, indexed) - Unique vulnerability identifier
- `title` (String[255]) - Vulnerability title
- `description` (Text) - Detailed description
- `severity` (Enum[SeverityLevel]) - critical, high, medium, low, info
- `cvss_score` (Float) - CVSS v3.1 score (0.0-10.0)
- `cvss_vector` (String[100]) - CVSS v3.1 vector string
- `cve_id` (String[20], indexed) - CVE identifier (e.g., "CVE-2021-12345")
- `cwe_id` (String[20]) - CWE identifier (e.g., "CWE-79")
- `affected_component` (String[100]) - Component/service affected
- `remediation` (Text) - Remediation steps/recommendations
- `references` (Text) - JSON array of reference URLs
- `proof_of_concept` (Text) - PoC/exploitation details
- `detected_at` (DateTime) - Detection timestamp
- `verified` (Boolean) - Manual verification status
- `false_positive` (Boolean) - False positive flag
- `risk_score` (Float) - Contextual risk score (0-100)
- `created_at` (DateTime, indexed) - Record creation timestamp
- `updated_at` (DateTime) - Record update timestamp
- `is_deleted` (Boolean) - Soft delete flag

**Key Methods:**
- `get_references() → list` - Parse JSON references
- `to_dict() → dict` - JSON serialization

**Relationships:**
- `device` (←1) - Reference to Device record
- `port` (←1) - Optional reference to Port record

**Data Example:**
```json
{
  "id": 1,
  "vuln_id": "VULN-001",
  "title": "Weak SSH Encryption (DES/3DES)",
  "severity": "high",
  "cvss_score": 7.5,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
  "cve_id": "CVE-2023-12345",
  "cwe_id": "CWE-696",
  "affected_component": "OpenSSH 5.1",
  "remediation": "Upgrade SSH to version 7.0+ and disable weak ciphers",
  "verified": true,
  "false_positive": false,
  "risk_score": 82.5
}
```

---

### 2.6 REPORT Model
**File:** `backend/core/models.py` (Line 403-445)

**Purpose:** Store generated vulnerability assessment reports

**Fields:**
- `id` (Integer, PK) - Primary key
- `report_id` (String[50], unique, indexed) - Unique report identifier
- `scan_id` (Integer, FK → scans.id) - Associated scan
- `tenant_id` (String[36], indexed) - Multi-tenant isolation
- `title` (String[255]) - Report title
- `format` (String[10]) - json, html, pdf
- `file_path` (String[500]) - Full path to report file
- `file_size` (Integer) - File size in bytes
- `generated_by` (String[100]) - User/system that generated report
- `checksum` (String[64], unique) - SHA256 integrity hash
- `is_immutable` (Boolean) - Immutability status (default: true)
- `generated_at` (DateTime) - Report generation timestamp
- `created_at` (DateTime, indexed) - Record creation timestamp
- `updated_at` (DateTime) - Record update timestamp
- `is_deleted` (Boolean) - Soft delete flag

**Key Methods:**
- `to_dict() → dict` - JSON serialization

**Relationships:**
- `scan` (←1) - Reference to Scan record

**Sample Data:**
```json
{
  "report_id": "RPT-20260328-001",
  "scan_id": 1,
  "title": "CCTV VAPT Assessment - 2026-03-28",
  "format": "html",
  "file_path": "/var/reports/VAPT_Report_1_20260328_103000.html",
  "file_size": 524288,
  "generated_by": "system",
  "is_immutable": true,
  "generated_at": "2026-03-28T10:30:00"
}
```

---

### 2.7 AUDIT LOG Model
**File:** `backend/core/models.py` (Line 450-504)

**Purpose:** Compliance audit trail for all system actions

**Fields:**
- `id` (Integer, PK) - Primary key
- `user_id` (Integer, FK → users.id, nullable) - Acting user
- `scan_id` (Integer, FK → scans.id, nullable) - Related scan
- `tenant_id` (String[36], indexed) - Multi-tenant isolation
- `action` (String[100], indexed) - Action type (e.g., "scan_started", "report_generated")
- `resource_type` (String[50]) - Resource type (scan, device, vulnerability, report)
- `resource_id` (String[100]) - Resource identifier
- `details` (Text) - JSON object with action details
- `ip_address` (String[45]) - Request IP address
- `user_agent` (String[500]) - User agent string
- `status` (String[20]) - success, failure, error
- `error_message` (Text) - Error details if failed
- `timestamp` (DateTime, indexed) - Action timestamp
- `created_at` (DateTime, indexed) - Record creation timestamp
- `updated_at` (DateTime) - Record update timestamp
- `is_deleted` (Boolean) - Soft delete flag

**Key Methods:**
- `get_details() → dict` - Parse JSON details
- `to_dict() → dict` - JSON serialization

**Relationships:**
- `user` (←1) - Reference to User record
- `scan` (←1) - Reference to Scan record

**Sample Logs:**
```json
{
  "action": "scan_started",
  "resource_type": "scan",
  "resource_id": "SCAN-20260328-001",
  "details": {"network_range": "192.168.1.0/24"},
  "status": "success",
  "timestamp": "2026-03-28T10:00:00"
}
```

---

## 3. CURRENT API ENDPOINTS

### 3.1 Reports API Endpoints
**File:** `backend/api/reports.py`

#### 3.1.1 Generate Report
```
POST /api/reports
Content-Type: application/json
X-Tenant-ID: tenant-uuid

Request Body:
{
  "scan_id": 1,
  "report_format": "json|html|pdf"
}

Response: 201 Created
{
  "success": true,
  "data": {
    "report_id": "abc123def456",
    "scan_id": 1,
    "format": "json",
    "file_path": "/path/to/report.json",
    "file_size": 5242,
    "generated_at": "2026-03-26T10:30:00"
  }
}
```

**Requirements:**
- User must be authenticated (@require_auth)
- Tenant header required (@require_tenant_header)
- Scan must exist and belong to tenant
- Scan status must be COMPLETED
- Report format must be json, html, or pdf

---

#### 3.1.2 List Reports
```
GET /api/reports?scan_id=1&limit=20&offset=0
X-Tenant-ID: tenant-uuid

Response: 200 OK
{
  "success": true,
  "data": {
    "reports": [...],
    "total": 42,
    "limit": 20,
    "offset": 0
  }
}
```

**Parameters:**
- `scan_id` (integer, optional) - Filter by specific scan
- `limit` (integer, default: 20, max: 100) - Pagination limit
- `offset` (integer, default: 0) - Pagination offset

---

#### 3.1.3 Get Report Details
```
GET /api/reports/<report_id>
X-Tenant-ID: tenant-uuid

Response: 200 OK
{
  "success": true,
  "data": {
    "report_id": "abc123",
    "scan_id": 1,
    "format": "json",
    "file_path": "/path/to/report.json",
    "file_size": 5242,
    "checksum": "sha256hash...",
    "generated_by": "operator1",
    "is_immutable": true,
    "generated_at": "2026-03-26T10:30:00"
  }
}
```

---

#### 3.1.4 Download Report File
```
GET /api/reports/<report_id>/download
X-Tenant-ID: tenant-uuid

Response: 200 OK (file download)
Content-Type: application/json | text/html | application/pdf

Side Effects:
- Logs action to AuditLog table (report_downloaded)
```

---

#### 3.1.5 Delete Report
```
DELETE /api/reports/<report_id>
X-Tenant-ID: tenant-uuid

Response: 200 OK
{
  "success": true,
  "data": {
    "report_id": "abc123",
    "status": "deleted"
  }
}
```

**Requirements:**
- User must have admin or operator role (@require_role)
- Cannot delete immutable reports (returns 403 Forbidden)
- Soft delete (is_deleted flag set to true)

---

#### 3.1.6 Compare Reports
```
POST /api/reports/compare
Content-Type: application/json
X-Tenant-ID: tenant-uuid

Request Body:
{
  "report_id_1": "abc123",
  "report_id_2": "def456"
}

Response: 200 OK
{
  "success": true,
  "data": {
    "comparison": {...},
    "changes": {...},
    "new_vulnerabilities": [...],
    "resolved_vulnerabilities": [...]
  }
}
```

---

### 3.2 Scan Report Routes
**File:** `backend/report_routes.py`

#### 3.2.1 Generate Report for Scan
```
POST /api/scan/<scan_id>/report

Response: 201 Created
{
  "success": true,
  "message": "Report generated successfully",
  "report_id": 1,
  "scan_id": 1,
  "generated_at": "2026-03-28T10:30:00",
  "formats": {
    "json": "/path/to/report.json",
    "html": "/path/to/report.html"
  },
  "preview": {
    "executive": [...],
    "risk_level": {...},
    "statistics": {...},
    "recommendations": [...]
  }
}
```

**Process:**
1. Fetch scan from database
2. Verify scan status is COMPLETED
3. Serialize scan devices and vulnerabilities
4. Count severity distribution
5. Execute 6-layer reporting pipeline
6. Export to JSON and HTML formats
7. Save report metadata to database
8. Return report with export links and preview

---

#### 3.2.2 Get Report for Scan
```
GET /api/scan/<scan_id>/report

Response: 200 OK
{
  "id": 1,
  "scan_id": 1,
  "report_type": "comprehensive",
  "generated_at": "2026-03-28T10:30:00",
  "content": {...},
  "exports": {
    "json": "/path/to/report.json",
    "html": "/path/to/report.html"
  }
}
```

---

#### 3.2.3 Export Report
```
GET /api/scan/<scan_id>/report/export/<format>
(format: json | html)

Response: 200 OK (file download)
Content-Type: application/json | text/html
```

---

#### 3.2.4 List All Reports
```
GET /api/reports

Response: 200 OK
{
  "total": 42,
  "reports": [
    {
      "id": 1,
      "scan_id": 1,
      "report_type": "comprehensive",
      "generated_at": "2026-03-28T10:30:00"
    },
    ...
  ]
}
```

---

## 4. DATA AGGREGATION & FLOW

### 4.1 6-Layer Reporting Pipeline
**File:** `backend/reporting_engine.py`

#### Layer 1: Raw Scan Data Ingestion
- Input: Scan result dictionary from database
- Output: Validated raw data dictionary
- Extracts: scan_metadata, discovery, devices, severity_summary

#### Layer 2: Data Normalization Engine
- Input: Raw data from Layer 1
- Output: Normalized unified schema
- Normalizes: assets, vulnerabilities, statistics, risk_summary
- Calculations: Port extraction, vulnerability aggregation

#### Layer 3: Risk Intelligence Engine
- Input: Normalized data from Layer 2
- Output: Enriched data with risk analysis
- Adds:
  - Overall risk score (0-100)
  - Risk rating (Critical, High, Medium, Low)
  - Critical assets identification
  - Remediation recommendations

#### Layer 4: Report Composition Engine
- Input: Enriched data from Layer 3
- Output: Three report types:
  1. Executive Summary (business-focused)
  2. Technical Report (detailed findings)
  3. Compliance Report (regulatory focus)

#### Layer 5: Output Distribution
- Input: Composed reports
- Output: Multiple export formats
- Formats: JSON, HTML, PDF

#### Layer 6: Database Persistence
- Input: Generated report data
- Storage: Report metadata in database
- Files: Stored in backend/reports directory

### 4.2 Data Flow Example
```
Scan Completed (status=COMPLETED)
  ↓
API Call: POST /api/reports
  ↓
Layer 1 (Ingestion)
  - Load: 3 devices, 15 vulnerabilities
  - Extract: severity counts (2 critical, 5 high, 8 medium)
  ↓
Layer 2 (Normalization)
  - Normalize assets
  - Extract open ports
  - Flatten vulnerability structure
  ↓
Layer 3 (Risk Intelligence)
  - Calculate risk score: 85/100 (HIGH)
  - Identify critical assets: Device 1 (Hikvision NVR with 2 critical vulns)
  - Generate recommendations: 3 items
  ↓
Layer 4 (Composition)
  - Executive Report: Business summary
  - Technical Report: Detailed findings
  - Compliance Report: Regulatory mapping
  ↓
Layer 5 (Distribution)
  - Export JSON: 145 KB
  - Export HTML: 340 KB
  - Export PDF: 520 KB
  ↓
Layer 6 (Persistence)
  - Save Report row to database
  - Store files in filesystem
  - Return report metadata to API
```

---

## 5. CURRENT DATA AVAILABLE IN SYSTEM

### 5.1 Scan-Level Data
Per scan record:
- Scan ID, status, type, operator
- Network range scanned
- Start/completion timestamps
- Severity counts (critical, high, medium, low)
- Total hosts found
- CCTV devices found
- Total vulnerabilities found
- Progress percentage
- Associated devices and reports

### 5.2 Device-Level Data
Per device record:
- IP address, MAC address, hostname
- Manufacturer, model, firmware version
- Device type (camera, DVR, NVR, encoder)
- CCTV identification confidence
- Associated ports and vulnerabilities
- Last seen timestamp
- Custom tags

### 5.3 Port-Level Data
Per port record:
- Port number, protocol (TCP/UDP)
- Port state (open, closed, filtered)
- Service name and version
- Service banner/response
- Encryption status (SSL/TLS)

### 5.4 Vulnerability-Level Data
Per vulnerability record:
- Vulnerability ID, CVE, CWE
- Title, description, severity
- CVSS score and vector
- Affected component
- Remediation steps
- References and PoC
- Verification status
- False positive flag
- Contextual risk score
- Affected device and port

### 5.5 Report-Level Data
Per report record:
- Report ID, scan ID, format
- File path and size
- Generated timestamp
- Generator user/system
- File integrity checksum
- Immutability status

### 5.6 Audit Trail Data
Per action:
- User, action type, timestamp
- Resource affected and type
- Request IP, user agent
- Action status (success/failure)
- Error details if applicable

---

## 6. ANALYTICS COLUMNS RECOMMENDATIONS

### 6.1 CRITICAL: Scan Model Additions

#### Recommended Columns:
```python
# Duration tracking
scan_duration_seconds = db.Column(db.Integer)  # Computed: completed_at - started_at
scan_duration_minutes = db.Column(db.Decimal(5,2))  # For reporting

# Remediation tracking
remediation_status = db.Column(db.String(50), default="pending")  
# Values: pending, in_progress, completed, deferred
remediation_deadline = db.Column(db.DateTime)
remediation_completion_date = db.Column(db.DateTime)

# Risk analytics
overall_risk_score = db.Column(db.Float)  # 0-100 scale
risk_rating = db.Column(db.String(20))  # critical, high, medium, low
avg_dev_risk_score = db.Column(db.Float)

# Device analytics
unique_cctv_devices = db.Column(db.Integer)
unique_manufactures = db.Column(db.Integer)
devices_affected_by_critical = db.Column(db.Integer)

# Vulnerability analytics  
unique_cve_ids = db.Column(db.Integer)
verified_vulns = db.Column(db.Integer)
false_positive_vulns = db.Column(db.Integer)

# Performance
avg_scan_time_by_network = db.Column(db.Decimal(10,2))
device_discovery_rate = db.Column(db.Float)  # devices found / expected

# Remediation metrics
critical_remediated = db.Column(db.Integer, default=0)
high_remediated = db.Column(db.Integer, default=0)
```

**Usage:** Trend analysis, SLA tracking, performance benchmarking

---

### 6.2 IMPORTANT: Device Model Additions

#### Recommended Columns:
```python
# Vulnerability summary
total_vulnerabilities = db.Column(db.Integer, default=0)
critical_vuln_count = db.Column(db.Integer, default=0)
high_vuln_count = db.Column(db.Integer, default=0)
device_risk_score = db.Column(db.Float, default=0.0)

# Remediation tracking
remediation_status = db.Column(db.String(50), default="pending")
last_remediation_date = db.Column(db.DateTime)
remediation_notes = db.Column(db.Text)

# CCTV-specific
is_monitored = db.Column(db.Boolean, default=False)
monitoring_location = db.Column(db.String(255))
firmware_last_updated = db.Column(db.DateTime)
firmware_update_available = db.Column(db.Boolean, default=False)

# Access tracking
last_accessed_via_web = db.Column(db.DateTime)
web_services_found = db.Column(db.Integer, default=0)
```

**Usage:** Device inventory management, risk-based prioritization

---

### 6.3 CRITICAL: Vulnerability Model Additions

#### Recommended Columns:
```python
# Remediation tracking
is_remediated = db.Column(db.Boolean, default=False)
remediation_date = db.Column(db.DateTime)
time_to_remediation = db.Column(db.Integer)  # Days between discovery and remediation
remediation_notes = db.Column(db.Text)
remediation_verified = db.Column(db.Boolean, default=False)

# Risk context
exploitability_rating = db.Column(db.String(20))  # High, Medium, Low
exploit_available = db.Column(db.Boolean, default=False)
active_exploitation = db.Column(db.Boolean, default=False)

# Temporal tracking
first_discovered = db.Column(db.DateTime, default=datetime.utcnow)
days_since_discovery = db.Column(db.Integer)  # Computed field
published_date = db.Column(db.DateTime)  # CVE publication date

# Status tracking
status = db.Column(db.String(50), default="open")  # open, in_progress, resolved
assigned_to = db.Column(db.String(100))  # Remediation team
priority = db.Column(db.String(20))  # P1, P2, P3, P4

# Severity context
business_impact = db.Column(db.Float)  # 0-10 scale
exploitability_ease = db.Column(db.Float)  # 0-10 scale
```

**Usage:** Vulnerability lifecycle tracking, SLA compliance, remediation metrics

---

### 6.4 VALUABLE: Report Model Additions

#### Recommended Columns:
```python
# Access tracking
access_count = db.Column(db.Integer, default=0)
last_accessed_at = db.Column(db.DateTime)
downloads = db.Column(db.Integer, default=0)

# Export tracking
json_downloaded = db.Column(db.Boolean, default=False)
html_downloaded = db.Column(db.Boolean, default=False)
pdf_downloaded = db.Column(db.Boolean, default=False)
export_count = db.Column(db.Integer, default=0)

# Quality metrics
completeness_score = db.Column(db.Float)  # 0-100
detail_level = db.Column(db.String(20))  # summary, detailed, comprehensive
```

**Usage:** Report usage analytics, training/adoption metrics

---

### 6.5 VALUABLE: AuditLog Model Additions

#### Recommended Columns:
```python
# Performance tracking
response_time_ms = db.Column(db.Integer)  # Milliseconds
request_size_bytes = db.Column(db.Integer)
response_size_bytes = db.Column(db.Integer)

# Categorization
category = db.Column(db.String(50))  # authentication, scanning, reporting, configuration
severity = db.Column(db.String(20))  # info, warning, error, critical

# Security context
is_privileged_action = db.Column(db.Boolean, default=False)
requires_approval = db.Column(db.Boolean, default=False)
approval_status = db.Column(db.String(50))
```

**Usage:** Performance monitoring, security auditing, compliance

---

## 7. IMPLEMENTATION PRIORITY MATRIX

| Model | Column | Priority | Impact | Effort | Benefit |
|-------|--------|----------|--------|--------|---------|
| Scan | scan_duration_seconds | CRITICAL | High | Low | Trend analysis |
| Scan | overall_risk_score | CRITICAL | High | Medium | Dashboard display |
| Scan | remediation_status | CRITICAL | High | Medium | SLA tracking |
| Device | total_vulnerabilities | CRITICAL | High | Low | Device prioritization |
| Device | device_risk_score | HIGH | High | Medium | Risk ranking |
| Vulnerability | is_remediated | CRITICAL | High | Low | Remediation tracking |
| Vulnerability | time_to_remediation | IMPORTANT | High | Medium | MTTR metrics |
| Vulnerability | exploitability_rating | HIGH | Medium | Medium | Risk context |
| Report | access_count | MEDIUM | Low | Low | Usage analytics |
| AuditLog | response_time_ms | MEDIUM | Medium | Low | Performance monitoring |

---

## 8. AGGREGATION QUERY PATTERNS

### 8.1 Dashboard Summary Query
```sql
SELECT 
  COUNT(DISTINCT s.id) as total_scans,
  COUNT(DISTINCT d.id) as total_devices,
  COUNT(DISTINCT v.id) as total_vulns,
  SUM(CASE WHEN v.severity='critical' THEN 1 ELSE 0 END) as critical_count,
  SUM(CASE WHEN v.severity='high' THEN 1 ELSE 0 END) as high_count,
  AVG(s.overall_risk_score) as avg_risk_score,
  COUNT(DISTINCT CASE WHEN v.is_remediated=false THEN v.id END) as open_vulns
FROM scans s
LEFT JOIN devices d ON s.id = d.scan_id
LEFT JOIN vulnerabilities v ON d.id = v.device_id
WHERE s.status = 'COMPLETED'
  AND s.tenant_id = ?
  AND s.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
```

### 8.2 Risk-Based Device Prioritization
```sql
SELECT 
  d.id, d.ip_address, d.manufacturer,
  COUNT(v.id) as vuln_count,
  SUM(CASE WHEN v.severity='critical' THEN 1 ELSE 0 END) as critical_count,
  AVG(v.cvss_score) as avg_cvss,
  d.device_risk_score
FROM devices d
LEFT JOIN vulnerabilities v ON d.id = v.device_id AND v.is_deleted=false
GROUP BY d.id
ORDER BY d.device_risk_score DESC, critical_count DESC
LIMIT 20
```

### 8.3 Remediation Progress Tracking
```sql
SELECT 
  DATE(v.remediation_date) as remediation_date,
  COUNT(CASE WHEN v.is_remediated=true THEN 1 END) as remediated_count,
  TIME_TO_DAYS(v.remediation_date) - TIME_TO_DAYS(v.first_discovered) as avg_days_to_remediation
FROM vulnerabilities v
WHERE v.scan_id = ?
GROUP BY DATE(v.remediation_date)
ORDER BY remediation_date
```

---

## 9. SUMMARY & RECOMMENDATIONS

### What's Currently Stored
✅ **Comprehensive Scan Results:**
- Device discovery (IP, MAC, type, manufacturer)
- Port information (number, service, version)
- Vulnerability details (CVE, CVSS, severity, remediation)
- Risk assessment (severity distribution)

✅ **Audit Trail:**
- User actions with timestamps
- Resource changes and status updates
- Security events and access logs

✅ **Report Generation:**
- 6-layer pipeline with risk analysis
- Multiple export formats (JSON, HTML, PDF)
- Immutable report storage

### Critical Gaps for Analytics
❌ **No Remediation Tracking:** Cannot track whether vulnerabilities have been fixed
❌ **No Duration Metrics:** Cannot measure scan time trends
❌ **No Risk Scoring:** No way to prioritize devices by overall risk
❌ **Limited Time Series:** No historical trend data collection
❌ **No Access Metrics:** Cannot track who uses reports

### Immediate Actions
1. **Add remediation columns** to Vulnerability model (is_remediated, remediation_date)
2. **Add risk scoring** to Scan and Device models  
3. **Add time tracking** to Scan (duration_seconds, completion date)
4. **Create analytic views** for dashboard queries
5. **Implement audit log retention** with performance metrics

### Long-Term Improvements
1. Time-series database (InfluxDB/Prometheus) for trend analysis
2. Data warehouse for historical analytics and reporting
3. Automated remediation workflow integration
4. Risk model refinement based on organizational context
5. Integration with external threat intelligence feeds

---

**Document Generated:** March 28, 2026
**Codebase Version:** Single-Tenant Refactor Complete
**Analysis Scope:** backend/core/models.py, backend/api/reports.py, backend/reporting_engine.py
