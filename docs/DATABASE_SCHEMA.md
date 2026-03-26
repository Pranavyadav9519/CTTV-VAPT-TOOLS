# CCTV VAPT - Database Schema

**Version:** 2.0.0  
**Database Engines:** PostgreSQL (production), SQLite (development)  
**ORM:** SQLAlchemy 2.0.36  

## Overview

The VAPT database uses a normalized relational schema optimized for:
- Multi-tenant security (tenant_id filtering)
- Audit compliance (created_at, updated_at, audit logs)
- Query performance (strategic indexing)
- Data integrity (foreign keys, constraints)

---

## Entity-Relationship Diagram

```
┌─────────────┐     ┌────────┐     ┌────────────┐
│    User     │────▶│  Scan  │◀────│   Report   │
├─────────────┤     └────────┘     └────────────┘
│ user_id (PK)│          │ 1
│ username    │          │ N
│ email       │          ▼
│ role        │      ┌────────┐
│ tenant_id   │      │ Device │
└─────────────┘      └────────┘
                          │ 1
                          │ N
                          ▼
                    ┌──────────────┐
                    │Vulnerability │
                    └──────────────┘
```

---

## Tables

### user

User accounts with role-based access control.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| user_id | UUID | PRIMARY KEY | Unique user identifier |
| username | VARCHAR(100) | UNIQUE, NOT NULL | Login username |
| email | VARCHAR(255) | UNIQUE, NOT NULL | Email address |
| password_hash | TEXT | NOT NULL | bcrypt hashed password |
| role | ENUM | NOT NULL | admin, operator, viewer |
| is_active | BOOLEAN | DEFAULT TRUE | Account status |
| tenant_id | VARCHAR(100) | NOT NULL | Multi-tenant isolation |
| created_at | TIMESTAMP | DEFAULT NOW() | Account creation |
| updated_at | TIMESTAMP | DEFAULT NOW() | Last modified |

**Indexes:**
```sql
CREATE INDEX idx_user_username ON user(username);
CREATE INDEX idx_user_tenant ON user(tenant_id);
CREATE INDEX idx_user_role ON user(role);
```

---

### tenant

Organization/tenant records for multi-tenancy.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| tenant_id | VARCHAR(100) | PRIMARY KEY | Organization ID |
| name | VARCHAR(255) | NOT NULL | Organization name |
| description | TEXT | | Additional info |
| subscription_level | ENUM | NOT NULL | free, standard, enterprise |
| is_active | BOOLEAN | DEFAULT TRUE | Activation status |
| max_scans_per_month | INT | | Quota limit |
| storage_quota_gb | INT | | Storage limit |
| created_at | TIMESTAMP | DEFAULT NOW() | Creation date |
| updated_at | TIMESTAMP | DEFAULT NOW() | Last modified |

---

### scan

Scan sessions - represents a network assessment.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| scan_id | UUID | PRIMARY KEY | Unique scan identifier |
| tenant_id | VARCHAR(100) | NOT NULL, FK | Multi-tenant |
| network_range | VARCHAR(50) | NOT NULL | Target CIDR (192.168.0/24) |
| scan_name | VARCHAR(255) | | User-friendly name |
| scan_type | VARCHAR(50) | | network, external, internal |
| status | ENUM | DEFAULT 'pending' | pending, queued, running, completed, failed, cancelled |
| total_hosts_probed | INT | DEFAULT 0 | IPs scanned |
| total_hosts_found | INT | DEFAULT 0 | Responsive hosts |
| open_ports_found | INT | DEFAULT 0 | Total open ports |
| vulnerabilities_found | INT | DEFAULT 0 | Issues discovered |
| scan_date | TIMESTAMP | DEFAULT NOW() | Start time |
| completed_date | TIMESTAMP | | Completion time |
| duration_seconds | INT | | Scan duration |
| created_by | UUID | FK user | User who initiated |
| notes | TEXT | | Additional notes |
| created_at | TIMESTAMP | DEFAULT NOW() | Record creation |
| updated_at | TIMESTAMP | DEFAULT NOW() | Record modified |

**Indexes:**
```sql
CREATE INDEX idx_scan_tenant ON scan(tenant_id);
CREATE INDEX idx_scan_status ON scan(status);
CREATE INDEX idx_scan_date ON scan(scan_date);
CREATE INDEX idx_scan_creator ON scan(created_by);
```

---

### device

Network devices discovered during scans.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| device_id | UUID | PRIMARY KEY | Unique device ID |
| scan_id | UUID | NOT NULL, FK | Source scan |
| tenant_id | VARCHAR(100) | NOT NULL, FK | Multi-tenant |
| ip_address | VARCHAR(50) | NOT NULL | IPv4 or IPv6 |
| hostname | VARCHAR(255) | | DNS hostname |
| is_cctv | BOOLEAN | DEFAULT FALSE | CCTV device flag |
| device_type | ENUM | | ip_camera, dvr, nvr, encoder, unknown |
| os_info | VARCHAR(255) | | Operating system |
| os_version | VARCHAR(100) | | OS version |
| manufacturer | VARCHAR(255) | | Device manufacturer |
| model | VARCHAR(255) | | Device model |
| mac_address | VARCHAR(50) | | MAC address |
| confidence_score | FLOAT | DEFAULT 0.0 | Identification confidence (0-1.0) |
| last_seen | TIMESTAMP | | Last activity |
| description | TEXT | | User notes |
| created_at | TIMESTAMP | DEFAULT NOW() | Record creation |
| updated_at | TIMESTAMP | DEFAULT NOW() | Record modified |

**Indexes:**
```sql
CREATE INDEX idx_device_scan ON device(scan_id);
CREATE INDEX idx_device_tenant ON device(tenant_id);
CREATE INDEX idx_device_ip ON device(ip_address);
CREATE INDEX idx_device_cctv ON device(is_cctv);
CREATE INDEX idx_device_manufacturer ON device(manufacturer);
```

---

### port

Open ports discovered on devices.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| port_id | UUID | PRIMARY KEY | Unique port record |
| device_id | UUID | NOT NULL, FK | Device this port is on |
| port_number | INT | NOT NULL (0-65535) | Network port |
| protocol | ENUM | NOT NULL | tcp, udp |
| service_name | VARCHAR(100) | | Service name (http, ssh, ftp) |
| service_version | VARCHAR(255) | | Software version |
| state | ENUM | DEFAULT 'open' | open, closed, filtered |
| banner | TEXT | | Service banner/greeting |
| confidence | FLOAT | DEFAULT 0.0 | Detection confidence |
| created_at | TIMESTAMP | DEFAULT NOW() | Discovery time |

**Indexes:**
```sql
CREATE INDEX idx_port_device ON port(device_id);
CREATE INDEX idx_port_number ON port(port_number);
CREATE INDEX idx_port_service ON port(service_name);
```

---

### vulnerability

Security issues found during assessment.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| vulnerability_id | UUID | PRIMARY KEY | Unique vuln ID |
| device_id | UUID | NOT NULL, FK | Affected device |
| port_id | UUID |  FK | Related port (optional) |
| scan_id | UUID | NOT NULL, FK | Source scan |
| tenant_id | VARCHAR(100) | NOT NULL, FK | Multi-tenant |
| title | VARCHAR(500) | NOT NULL | Vulnerability title |
| description | TEXT | | Detailed description |
| severity | ENUM | NOT NULL | critical, high, medium, low, info |
| cvss_score | FLOAT | | CVSS v3 score (0-10) |
| cvss_vector | VARCHAR(255) | | CVSS v3 vector |
| cve_id | VARCHAR(50) | | CVE identifier |
| cpe | VARCHAR(255) | | CPE if applicable |
| vulnerability_source | VARCHAR(100) | | nvd, vendor, custom |
| category | VARCHAR(100) | | CWE category |
| first_discovered | TIMESTAMP | DEFAULT NOW() | First detection |
| last_verified | TIMESTAMP | | Last confirmation |
| remediation | TEXT | | Fix recommendations |
| affected_component | VARCHAR(255) | | Vulnerable software |
| affected_version | VARCHAR(100) | | Version info |
| is_exploitable | BOOLEAN | DEFAULT FALSE | Exploit exists |
| exploitability | VARCHAR(50) | | Easy, Moderate, Difficult |
| status | ENUM | DEFAULT 'new' | new, confirmed, false_positive, resolved |
| assigned_to | UUID | FK user | Assignment |
| notes | TEXT | | Internal notes |
| created_at | TIMESTAMP | DEFAULT NOW() | Record creation |
| updated_at | TIMESTAMP | DEFAULT NOW() | Record modified |

**Indexes:**
```sql
CREATE INDEX idx_vuln_device ON vulnerability(device_id);
CREATE INDEX idx_vuln_scan ON vulnerability(scan_id);
CREATE INDEX idx_vuln_severity ON vulnerability(severity);
CREATE INDEX idx_vuln_cve ON vulnerability(cve_id);
CREATE INDEX idx_vuln_status ON vulnerability(status);
```

---

### report

Generated assessment reports.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| report_id | UUID | PRIMARY KEY | Unique report ID |
| scan_id | UUID | NOT NULL, FK | Associated scan |
| tenant_id | VARCHAR(100) | NOT NULL, FK | Multi-tenant |
| format | ENUM | NOT NULL | html, json, pdf |
| file_path | VARCHAR(500) | NOT NULL | Storage path |
| file_size | INT | | Bytes |
| checksum | VARCHAR(256) | | SHA-256 hash |
| is_immutable | BOOLEAN | DEFAULT TRUE | Cannot be modified |
| title | VARCHAR(500) | | Report title |
| include_conclusions | BOOLEAN | DEFAULT TRUE | Include summary |
| include_recommendations | BOOLEAN | DEFAULT TRUE | Include fixes |
| generated_by | UUID | FK user | Report generator |
| generated_at | TIMESTAMP | DEFAULT NOW() | Generation time |
| expires_at | TIMESTAMP | | Expiration deadline |
| access_count | INT | DEFAULT 0 | Download count |
| last_accessed | TIMESTAMP | | Last download |
| is_deleted | BOOLEAN | DEFAULT FALSE | Soft delete flag |
| created_at | TIMESTAMP | DEFAULT NOW() | Record creation |
| updated_at | TIMESTAMP | DEFAULT NOW() | Record modified |

**Indexes:**
```sql
CREATE INDEX idx_report_scan ON report(scan_id);
CREATE INDEX idx_report_tenant ON report(tenant_id);
CREATE INDEX idx_report_generated ON report(generated_at);
CREATE INDEX idx_report_format ON report(format);
CREATE INDEX idx_report_expires ON report(expires_at);
```

---

### audit_log

Compliance audit trail for all operations.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| audit_id | UUID | PRIMARY KEY | Unique log ID |
| tenant_id | VARCHAR(100) | NOT NULL | Multi-tenant |
| user_id | UUID | | Who performed action |
| action | VARCHAR(100) | NOT NULL | create, read, update, delete |
| resource_type | VARCHAR(100) | NOT NULL | scan, device, report |
| resource_id | VARCHAR(255) | NOT NULL | Which record |
| old_values | JSONB | | Previous state |
| new_values | JSONB | | New state |
| changes | JSONB | | What changed |
| ip_address | VARCHAR(50) | | Client IP |
| user_agent | VARCHAR(500) | | Browser info |
| status | ENUM | | success, failure |
| error_message | TEXT | | If failure |
| timestamp | TIMESTAMP | DEFAULT NOW() | When occurred |

**Indexes:**
```sql
CREATE INDEX idx_audit_tenant ON audit_log(tenant_id);
CREATE INDEX idx_audit_user ON audit_log(user_id);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);
```

---

## Schema Creation DDL

### PostgreSQL

```sql
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enums
CREATE TYPE user_role AS ENUM ('admin', 'operator', 'viewer');
CREATE TYPE scan_status AS ENUM ('pending', 'queued', 'running', 'completed', 'failed', 'cancelled');
CREATE TYPE severity_level AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE device_type AS ENUM ('ip_camera', 'dvr', 'nvr', 'encoder', 'unknown');
CREATE TYPE port_state AS ENUM ('open', 'closed', 'filtered');
CREATE TYPE vuln_status AS ENUM ('new', 'confirmed', 'false_positive', 'resolved');

-- User Table
CREATE TABLE "user" (
    user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255),
    password_hash TEXT NOT NULL,
    role user_role NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    tenant_id VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scan Table
CREATE TABLE scan (
    scan_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(100) NOT NULL,
    network_range VARCHAR(50) NOT NULL,
    scan_name VARCHAR(255),
    scan_type VARCHAR(50),
    status scan_status DEFAULT 'pending',
    total_hosts_probed INT DEFAULT 0,
    total_hosts_found INT DEFAULT 0,
    open_ports_found INT DEFAULT 0,
    vulnerabilities_found INT DEFAULT 0,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_date TIMESTAMP,
    duration_seconds INT,
    created_by UUID REFERENCES "user"(user_id),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Device Table
CREATE TABLE device (
    device_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scan(scan_id) ON DELETE CASCADE,
    tenant_id VARCHAR(100) NOT NULL,
    ip_address VARCHAR(50) NOT NULL,
    hostname VARCHAR(255),
    is_cctv BOOLEAN DEFAULT FALSE,
    device_type device_type,
    os_info VARCHAR(255),
    os_version VARCHAR(100),
    manufacturer VARCHAR(255),
    model VARCHAR(255),
    mac_address VARCHAR(50),
    confidence_score FLOAT DEFAULT 0.0,
    last_seen TIMESTAMP,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Port Table
CREATE TABLE port (
    port_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES device(device_id) ON DELETE CASCADE,
    port_number INT NOT NULL CHECK (port_number >= 0 AND port_number <= 65535),
    protocol VARCHAR(10) NOT NULL,
    service_name VARCHAR(100),
    service_version VARCHAR(255),
    state port_state DEFAULT 'open',
    banner TEXT,
    confidence FLOAT DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Vulnerability Table
CREATE TABLE vulnerability (
    vulnerability_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES device(device_id) ON DELETE CASCADE,
    port_id UUID REFERENCES port(port_id) ON DELETE SET NULL,
    scan_id UUID NOT NULL REFERENCES scan(scan_id) ON DELETE CASCADE,
    tenant_id VARCHAR(100) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity severity_level NOT NULL,
    cvss_score FLOAT,
    cvss_vector VARCHAR(255),
    cve_id VARCHAR(50),
    cpe VARCHAR(255),
    vulnerability_source VARCHAR(100),
    category VARCHAR(100),
    first_discovered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_verified TIMESTAMP,
    remediation TEXT,
    affected_component VARCHAR(255),
    affected_version VARCHAR(100),
    is_exploitable BOOLEAN DEFAULT FALSE,
    exploitability VARCHAR(50),
    status vuln_status DEFAULT 'new',
    assigned_to UUID REFERENCES "user"(user_id) ON DELETE SET NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Report Table
CREATE TABLE report (
    report_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scan(scan_id) ON DELETE CASCADE,
    tenant_id VARCHAR(100) NOT NULL,
    format VARCHAR(50) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    file_size INT,
    checksum VARCHAR(256),
    is_immutable BOOLEAN DEFAULT TRUE,
    title VARCHAR(500),
    include_conclusions BOOLEAN DEFAULT TRUE,
    include_recommendations BOOLEAN DEFAULT TRUE,
    generated_by UUID REFERENCES "user"(user_id) ON DELETE SET NULL,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    access_count INT DEFAULT 0,
    last_accessed TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit Log Table
CREATE TABLE audit_log (
    audit_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(100) NOT NULL,
    user_id UUID REFERENCES "user"(user_id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    old_values JSONB,
    new_values JSONB,
    changes JSONB,
    ip_address VARCHAR(50),
    user_agent VARCHAR(500),
    status VARCHAR(50),
    error_message TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Indexes
CREATE INDEX idx_scan_tenant ON scan(tenant_id);
CREATE INDEX idx_scan_status ON scan(status);
CREATE INDEX idx_scan_date ON scan(scan_date);
CREATE INDEX idx_device_scan ON device(scan_id);
CREATE INDEX idx_device_ip ON device(ip_address);
CREATE INDEX idx_device_cctv ON device(is_cctv);
CREATE INDEX idx_vulnerability_device ON vulnerability(device_id);
CREATE INDEX idx_vulnerability_severity ON vulnerability(severity);
CREATE INDEX idx_vulnerability_cve ON vulnerability(cve_id);
CREATE INDEX idx_report_scan ON report(scan_id);
CREATE INDEX idx_report_tenant ON report(tenant_id);
CREATE INDEX idx_report_expires ON report(expires_at);
CREATE INDEX idx_audit_tenant ON audit_log(tenant_id);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
```

---

## Data Retention & Compliance

**Soft Delete:** Reports and scans use soft deletes (is_deleted flag)

**Audit Logging:** All operations logged in audit_log table

**Data Retention Policy:**
- Scans: 2 years
- Devices: 2 years
- Vulnerabilities: 3 years (compliance)
- Reports: Based on subscription level
- Audit Logs: 5 years (regulatory requirement)

---

## Performance Tuning

**Connection Pooling:**
```python
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True
}
```

**Query Optimization:**
- Use eager loading for related objects
- Implement pagination for large result sets
- Cache frequently accessed data in Redis

**Recommended Production Configuration:**
```
- PostgreSQL 13+ with 4GB+ RAM
- Connection pool size: 20-50
- Maintenance: VACUUM/ANALYZE weekly
- Backups: Daily automated backups
```

---

For setup instructions, see [SETUP.md](SETUP.md)  
For API reference, see [API.md](API.md)  
For architecture details, see [ARCHITECTURE.md](ARCHITECTURE.md)
