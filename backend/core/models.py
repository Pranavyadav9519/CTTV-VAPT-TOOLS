"""
Comprehensive Database Models with proper relationships
Includes User, Scan, Device, Port, Vulnerability, Report, and AuditLog models
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from werkzeug.security import generate_password_hash, check_password_hash
from backend.core.database import db
import json


# ============================================================================
# ENUMS
# ============================================================================

class UserRole(Enum):
    """User role enumeration"""
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class ScanStatus(Enum):
    """Scan status enumeration"""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DeviceType(Enum):
    """Device type enumeration"""
    IP_CAMERA = "ip_camera"
    DVR = "dvr"
    NVR = "nvr"
    ENCODER = "encoder"
    UNKNOWN = "unknown"


# ============================================================================
# BASE MODEL
# ============================================================================

class BaseModel(db.Model):
    """Base model with common fields"""
    __abstract__ = True

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)

    def to_dict(self):
        """Convert model to dictionary"""
        return {
            'id': self.id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }

    def soft_delete(self):
        """Soft delete the record"""
        self.is_deleted = True
        return self


# ============================================================================
# USER MODEL
# ============================================================================

class User(BaseModel):
    """User account model with security features"""
    __tablename__ = "users"

    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(512), nullable=False)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    role = db.Column(db.Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    last_login = db.Column(db.DateTime)
    last_ip = db.Column(db.String(45))
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    tenant_id = db.Column(db.String(36), nullable=False, index=True)

    # Relationships
    scans = db.relationship("Scan", backref="operator", lazy="dynamic", cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", backref="user", lazy="dynamic")

    def set_password(self, password: str):
        """Hash and set password"""
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password: str) -> bool:
        """Verify password hash"""
        return check_password_hash(self.password_hash, password)

    def can_access_scan(self, scan: 'Scan') -> bool:
        """Check if user can access a specific scan"""
        if self.role == UserRole.ADMIN:
            return True
        if self.role == UserRole.OPERATOR:
            return scan.user_id == self.id
        if self.role == UserRole.VIEWER:
            return scan.user_id == self.id
        return False

    def to_dict(self):
        """Convert to dictionary"""
        data = super().to_dict()
        data.update({
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'role': self.role.value if self.role else None,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'last_login': self.last_login.isoformat() if self.last_login else None,
        })
        return data


# ============================================================================
# SCAN MODEL
# ============================================================================

class Scan(BaseModel):
    """Vulnerability scan session model"""
    __tablename__ = "scans"

    scan_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    tenant_id = db.Column(db.String(36), nullable=False, index=True)
    status = db.Column(db.Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    scan_type = db.Column(db.String(50), default="network_discovery", nullable=False)
    network_range = db.Column(db.String(50))
    description = db.Column(db.Text)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    total_hosts_found = db.Column(db.Integer, default=0)
    cctv_devices_found = db.Column(db.Integer, default=0)
    vulnerabilities_found = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)
    celery_task_id = db.Column(db.String(36), index=True)
    progress_percent = db.Column(db.Integer, default=0)

    # Relationships
    devices = db.relationship("Device", backref="scan", lazy="dynamic", cascade="all, delete-orphan")
    reports = db.relationship("Report", backref="scan", lazy="dynamic", cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", backref="scan", lazy="dynamic")

    def get_severity_breakdown(self) -> dict:
        """Get severity breakdown"""
        return {
            'critical': self.critical_count,
            'high': self.high_count,
            'medium': self.medium_count,
            'low': self.low_count,
        }

    def mark_running(self):
        """Mark scan as running"""
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.utcnow()

    def mark_completed(self):
        """Mark scan as completed"""
        self.status = ScanStatus.COMPLETED
        self.completed_at = datetime.utcnow()

    def mark_failed(self, error_msg: str):
        """Mark scan as failed"""
        self.status = ScanStatus.FAILED
        self.error_message = error_msg
        self.completed_at = datetime.utcnow()

    def to_dict(self):
        """Convert to dictionary"""
        data = super().to_dict()
        data.update({
            'scan_id': self.scan_id,
            'status': self.status.value if self.status else None,
            'scan_type': self.scan_type,
            'network_range': self.network_range,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'total_hosts_found': self.total_hosts_found,
            'cctv_devices_found': self.cctv_devices_found,
            'vulnerabilities_found': self.vulnerabilities_found,
            'severity_breakdown': self.get_severity_breakdown(),
            'progress_percent': self.progress_percent,
        })
        return data


# ============================================================================
# DEVICE MODEL
# ============================================================================

class Device(BaseModel):
    """Discovered device model"""
    __tablename__ = "devices"

    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    tenant_id = db.Column(db.String(36), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False)
    mac_address = db.Column(db.String(17))
    hostname = db.Column(db.String(255))
    manufacturer = db.Column(db.String(100))
    device_type = db.Column(db.Enum(DeviceType), default=DeviceType.UNKNOWN)
    model = db.Column(db.String(100))
    firmware_version = db.Column(db.String(50))
    os_info = db.Column(db.String(255))
    is_cctv = db.Column(db.Boolean, default=False, nullable=False)
    confidence_score = db.Column(db.Float, default=0.0)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    tags = db.Column(db.String(500))  # Comma-separated tags

    # Relationships
    ports = db.relationship("Port", backref="device", lazy="dynamic", cascade="all, delete-orphan")
    vulnerabilities = db.relationship("Vulnerability", backref="device", lazy="dynamic", cascade="all, delete-orphan")

    def to_dict(self):
        """Convert to dictionary"""
        data = super().to_dict()
        data.update({
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'hostname': self.hostname,
            'manufacturer': self.manufacturer,
            'device_type': self.device_type.value if self.device_type else None,
            'model': self.model,
            'firmware_version': self.firmware_version,
            'os_info': self.os_info,
            'is_cctv': self.is_cctv,
            'confidence_score': self.confidence_score,
            'port_count': self.ports.count(),
            'vulnerability_count': self.vulnerabilities.count(),
        })
        return data


# ============================================================================
# PORT MODEL
# ============================================================================

class Port(BaseModel):
    """Open port model"""
    __tablename__ = "ports"

    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=False)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default="tcp")
    state = db.Column(db.String(20), default="open")  # open, closed, filtered
    service_name = db.Column(db.String(50))
    service_version = db.Column(db.String(100))
    banner = db.Column(db.Text)
    is_encrypted = db.Column(db.Boolean, default=False)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    vulnerabilities = db.relationship("Vulnerability", backref="port", lazy="dynamic")

    def to_dict(self):
        """Convert to dictionary"""
        data = super().to_dict()
        data.update({
            'port_number': self.port_number,
            'protocol': self.protocol,
            'state': self.state,
            'service_name': self.service_name,
            'service_version': self.service_version,
            'is_encrypted': self.is_encrypted,
            'vulnerability_count': self.vulnerabilities.count(),
        })
        return data


# ============================================================================
# VULNERABILITY MODEL
# ============================================================================

class Vulnerability(BaseModel):
    """Vulnerability finding model"""
    __tablename__ = "vulnerabilities"

    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=False)
    port_id = db.Column(db.Integer, db.ForeignKey("ports.id"))
    vuln_id = db.Column(db.String(50), unique=True, index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.Enum(SeverityLevel), nullable=False)
    cvss_score = db.Column(db.Float)
    cvss_vector = db.Column(db.String(100))
    cve_id = db.Column(db.String(20), index=True)
    cwe_id = db.Column(db.String(20))
    affected_component = db.Column(db.String(100))
    remediation = db.Column(db.Text)
    references = db.Column(db.Text)  # JSON array
    proof_of_concept = db.Column(db.Text)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    verified = db.Column(db.Boolean, default=False)
    false_positive = db.Column(db.Boolean, default=False)
    risk_score = db.Column(db.Float)  # Contextual risk score (0-100)

    def get_references(self) -> list:
        """Parse JSON references"""
        try:
            return json.loads(self.references) if self.references else []
        except:
            return []

    def to_dict(self):
        """Convert to dictionary"""
        data = super().to_dict()
        data.update({
            'vuln_id': self.vuln_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value if self.severity else None,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'cve_id': self.cve_id,
            'cwe_id': self.cwe_id,
            'affected_component': self.affected_component,
            'remediation': self.remediation,
            'references': self.get_references(),
            'verified': self.verified,
            'false_positive': self.false_positive,
            'risk_score': self.risk_score,
        })
        return data


# ============================================================================
# REPORT MODEL
# ============================================================================

class Report(BaseModel):
    """Generated report model"""
    __tablename__ = "reports"

    report_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    tenant_id = db.Column(db.String(36), nullable=False, index=True)
    title = db.Column(db.String(255))
    format = db.Column(db.String(10))  # json, html, pdf
    file_path = db.Column(db.String(500))
    file_size = db.Column(db.Integer)
    generated_by = db.Column(db.String(100))
    checksum = db.Column(db.String(64), unique=True)
    is_immutable = db.Column(db.Boolean, default=True)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        """Convert to dictionary"""
        data = super().to_dict()
        data.update({
            'report_id': self.report_id,
            'title': self.title,
            'format': self.format,
            'file_size': self.file_size,
            'generated_by': self.generated_by,
            'is_immutable': self.is_immutable,
            'generated_at': self.generated_at.isoformat() if self.generated_at else None,
        })
        return data


# ============================================================================
# AUDIT LOG MODEL
# ============================================================================

class AuditLog(BaseModel):
    """Audit trail for compliance"""
    __tablename__ = "audit_logs"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"))
    tenant_id = db.Column(db.String(36), nullable=False, index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.String(100))
    details = db.Column(db.Text)  # JSON
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    status = db.Column(db.String(20))  # success, failure, error
    error_message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    def get_details(self) -> dict:
        """Parse JSON details"""
        try:
            return json.loads(self.details) if self.details else {}
        except:
            return {}

    def to_dict(self):
        """Convert to dictionary"""
        data = super().to_dict()
        data.update({
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': self.get_details(),
            'ip_address': self.ip_address,
            'status': self.status,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
        })
        return data
