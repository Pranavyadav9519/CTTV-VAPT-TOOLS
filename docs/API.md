# CCTV VAPT - API Reference

**Version:** 2.0.0  
**Base URL:** `http://localhost:5000/api`  
**Authentication:** JWT Bearer Token  

## Table of Contents

- [Authentication](#authentication)
- [Health & Status](#health--status)
- [Scans](#scans)
- [Devices](#devices)
- [Vulnerabilities](#vulnerabilities)
- [Reports](#reports)
- [Error Responses](#error-responses)

---

## Authentication

### Login

**Endpoint:** `POST /auth/login`

**Request:**
```json
{
  "username": "admin",
  "password": "secure_password",
  "tenant_id": "org-001"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJ0eXAiOi...",
  "token_type": "bearer",
  "expires_in": 86400
}
```

**Usage:** Include token in all subsequent requests:
```
Authorization: Bearer eyJ0eXAiOi...
X-Tenant-ID: org-001
```

---

## Health & Status

### Health Check

**Endpoint:** `GET /health`

**Response (200 OK):**
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "timestamp": "2026-03-26T10:30:00Z"
}
```

---

## Scans

### List Scans

**Endpoint:** `GET /scans`

**Query Parameters:**
- `page` (optional, default: 1) - Page number
- `limit` (optional, default: 20) - Results per page
- `status` (optional) - Filter by status (pending, running, completed, failed)

**Headers:**
```
Authorization: Bearer <token>
X-Tenant-ID: org-001
```

**Response (200 OK):**
```json
{
  "data": [
    {
      "scan_id": "scan-123",
      "network_range": "192.168.1.0/24",
      "status": "completed",
      "total_hosts_found": 5,
      "vulnerabilities_found": 12,
      "scan_date": "2026-03-26T10:00:00Z",
      "duration_seconds": 1800
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 45
  }
}
```

### Create Scan

**Endpoint:** `POST /scans`

**Headers:**
```
Authorization: Bearer <token>
X-Tenant-ID: org-001
Content-Type: application/json
```

**Request:**
```json
{
  "network_range": "192.168.1.0/24",
  "ports": [22, 80, 443, 8080],
  "timeout": 300,
  "scan_name": "Office Network Scan",
  "description": "Weekly vulnerability assessment"
}
```

**Response (201 Created):**
```json
{
  "scan_id": "scan-456",
  "status": "queued",
  "network_range": "192.168.1.0/24",
  "created_at": "2026-03-26T10:30:00Z"
}
```

### Get Scan Details

**Endpoint:** `GET /scans/<scan_id>`

**Response (200 OK):**
```json
{
  "scan_id": "scan-456",
  "network_range": "192.168.1.0/24",
  "status": "running",
  "total_hosts_found": 3,
  "vulnerabilities_found": 0,
  "progress": 45,
  "estimated_completion": "2026-03-26T11:15:00Z",
  "created_at": "2026-03-26T10:30:00Z",
  "started_at": "2026-03-26T10:31:00Z"
}
```

---

## Devices

### List Devices

**Endpoint:** `GET /devices`

**Query Parameters:**
- `scan_id` (required) - Filter by scan
- `is_cctv` (optional) - Filter CCTV devices only

**Response (200 OK):**
```json
{
  "data": [
    {
      "device_id": "dev-001",
      "ip_address": "192.168.1.100",
      "is_cctv": true,
      "confidence_score": 0.95,
      "os_info": "Linux Hikvision Firmware v4.x",
      "manufacturer": "Hikvision",
      "open_ports": [80, 443, 8080],
      "scan_id": "scan-456"
    }
  ]
}
```

### Get Device Details

**Endpoint:** `GET /devices/<device_id>`

**Response (200 OK):**
```json
{
  "device_id": "dev-001",
  "ip_address": "192.168.1.100",
  "is_cctv": true,
  "confidence_score": 0.95,
  "description": "IP Camera - Main Building",
  "vulnerabilities": [
    {
      "vulnerability_id": "vuln-001",
      "title": "Default Credentials",
      "severity": "high",
      "cvss_score": 7.5
    }
  ]
}
```

---

## Vulnerabilities

### List Vulnerabilities

**Endpoint:** `GET /vulnerabilities`

**Query Parameters:**
- `device_id` (optional) - Filter by device
- `severity` (optional) - critical, high, medium, low, info
- `scan_id` (optional) - Filter by scan

**Response (200 OK):**
```json
{
  "data": [
    {
      "vulnerability_id": "vuln-001",
      "device_id": "dev-001",
      "title": "Default Credentials",
      "description": "Device uses default username/password",
      "severity": "high",
      "cvss_score": 7.5,
      "cve_id": "CVE-2021-12345",
      "remediation": "Change default credentials immediately",
      "discovered_at": "2026-03-26T10:45:00Z"
    }
  ],
  "summary": {
    "critical": 2,
    "high": 5,
    "medium": 8,
    "low": 3,
    "info": 1
  }
}
```

---

## Reports

### Generate Report

**Endpoint:** `POST /reports`

**Headers:**
```
Authorization: Bearer <token>
X-Tenant-ID: org-001
Content-Type: application/json
```

**Request:**
```json
{
  "scan_id": "scan-456",
  "format": "html",
  "title": "Quarterly Security Assessment",
  "include_recommendations": true
}
```

**Format Options:**
- `html` - Professional HTML report
- `json` - Machine-readable JSON
- `pdf` - Printable PDF document

**Response (202 Accepted):**
```json
{
  "report_id": "report-789",
  "scan_id": "scan-456",
  "status": "generating",
  "format": "html",
  "created_at": "2026-03-26T11:00:00Z"
}
```

### List Reports

**Endpoint:** `GET /reports`

**Query Parameters:**
- `page` (optional, default: 1)
- `limit` (optional, default: 20)
- `format` (optional) - html, json, pdf

**Response (200 OK):**
```json
{
  "data": [
    {
      "report_id": "report-789",
      "scan_id": "scan-456",
      "scan_name": "Office Network Scan",
      "format": "html",
      "file_size": 2048576,
      "generated_at": "2026-03-26T11:15:00Z",
      "expires_at": "2026-04-26T11:15:00Z",
      "created_by": "admin"
    }
  ]
}
```

### Get Report Details

**Endpoint:** `GET /reports/<report_id>`

**Response (200 OK):**
```json
{
  "report_id": "report-789",
  "scan_id": "scan-456",
  "format": "html",
  "file_path": "/reports/2026/03/report-789.html",
  "file_size": 2048576,
  "checksum": "sha256:abc123...",
  "generated_at": "2026-03-26T11:15:00Z",
  "expires_at": "2026-04-26T11:15:00Z",
  "accessed_count": 5,
  "last_accessed": "2026-03-26T12:30:00Z"
}
```

### Download Report

**Endpoint:** `GET /reports/<report_id>/download`

**Response:** File download (Content-Type varies by format)
- HTML: `text/html`
- JSON: `application/json`
- PDF: `application/pdf`

**Example:**
```bash
curl -H "Authorization: Bearer <token>" \
  -H "X-Tenant-ID: org-001" \
  https://vapt.example.com/api/reports/report-789/download \
  -o report.html
```

### Compare Reports

**Endpoint:** `POST /reports/compare`

**Request:**
```json
{
  "report_id_1": "report-456",
  "report_id_2": "report-789"
}
```

**Response (200 OK):**
```json
{
  "comparison": {
    "total_vulnerabilities": {
      "previous": 15,
      "current": 12,
      "change": -3
    },
    "critical_vulnerabilities": {
      "previous": 2,
      "current": 1,
      "change": -1
    },
    "new_vulnerabilities": [
      {
        "vulnerability_id": "vuln-999",
        "title": "SSL/TLS Misconfiguration",
        "severity": "high"
      }
    ],
    "fixed_vulnerabilities": [
      {
        "vulnerability_id": "vuln-001",
        "title": "Default Credentials",
        "severity": "critical"
      }
    ]
  }
}
```

### Delete Report

**Endpoint:** `DELETE /reports/<report_id>`

**Headers:**
```
Authorization: Bearer <token>
X-Tenant-ID: org-001
```

**Requires:** `admin` or `operator` role

**Response (204 No Content):**
```
(Empty body)
```

**Error Response (403 Forbidden):**
```json
{
  "error": "insufficient_permissions",
  "message": "Only admins and operators can delete reports"
}
```

---

## Error Responses

### 400 Bad Request

**Cause:** Invalid input or malformed request

**Response:**
```json
{
  "error": "validation_error",
  "message": "Invalid input",
  "details": {
    "network_range": "Invalid CIDR notation"
  }
}
```

### 401 Unauthorized

**Cause:** Missing or invalid JWT token

**Response:**
```json
{
  "error": "unauthorized",
  "message": "Missing or invalid authentication token"
}
```

### 403 Forbidden

**Cause:** Insufficient permissions or cross-tenant access

**Response:**
```json
{
  "error": "forbidden",
  "message": "User does not have permission to access this resource"
}
```

### 404 Not Found

**Cause:** Resource does not exist

**Response:**
```json
{
  "error": "not_found",
  "message": "Report with ID 'report-999' not found"
}
```

### 429 Too Many Requests

**Cause:** Rate limit exceeded

**Response:**
```json
{
  "error": "rate_limit_exceeded",
  "message": "Too many requests. Please try again later.",
  "retry_after": 60
}
```

### 500 Internal Server Error

**Cause:** Server-side error

**Response:**
```json
{
  "error": "internal_error",
  "message": "An unexpected error occurred",
  "request_id": "req-abc123"
}
```

---

## Common Request/Response Patterns

### Pagination

All list endpoints support pagination:

**Request:**
```
GET /api/reports?page=2&limit=25
```

**Response:**
```json
{
  "data": [...],
  "pagination": {
    "page": 2,
    "limit": 25,
    "total": 100,
    "pages": 4,
    "has_next": true,
    "has_previous": true
  }
}
```

### Filtering

**Request:**
```
GET /api/vulnerabilities?severity=high&device_id=dev-001
```

### Status Codes Summary

| Code | Meaning |
|------|---------|
| 200 | OK - Successful request |
| 201 | Created - Resource created |
| 202 | Accepted - Async task queued |
| 204 | No Content - Successful deletion |
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Auth required |
| 403 | Forbidden - Permission denied |
| 404 | Not Found - Resource not found |
| 429 | Too Many Requests - Rate limited |
| 500 | Server Error - Internal error |

---

## Examples

### Complete Workflow Example

```bash
# 1. Authenticate
TOKEN=$(curl -s -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"pass","tenant_id":"org-001"}' \
  | jq -r '.access_token')

# 2. Create scan
SCAN=$(curl -s -X POST http://localhost:5000/api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: org-001" \
  -H "Content-Type: application/json" \
  -d '{"network_range":"192.168.1.0/24","ports":[22,80,443]}' \
  | jq -r '.scan_id')

# 3. Monitor scan
curl -s http://localhost:5000/api/scans/$SCAN \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: org-001" | jq '.status'

# 4. Generate report
REPORT=$(curl -s -X POST http://localhost:5000/api/reports \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: org-001" \
  -H "Content-Type: application/json" \
  -d "{\"scan_id\":\"$SCAN\",\"format\":\"html\"}" \
  | jq -r '.report_id')

# 5. Download report
curl -s http://localhost:5000/api/reports/$REPORT/download \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: org-001" \
  -o report.html
```

---

For architecture details, see [ARCHITECTURE.md](ARCHITECTURE.md)  
For setup instructions, see [SETUP.md](SETUP.md)  
For database schema, see [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md)
