"""
Database Models for VAPT Tool
Stores scan history, discovered devices, vulnerabilities, and audit logs
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
import json

db = SQLAlchemy()


class Scan(db.Model):
    """Scan session model"""

    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    operator_name = db.Column(db.String(100), nullable=False)
    status = db.Column(
        db.String(20), default="pending"
    )  # pending, running, completed, failed
    scan_type = db.Column(db.String(50), default="network_discovery")
    network_range = db.Column(db.String(50))
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    total_hosts_found = db.Column(db.Integer, default=0)
    cctv_devices_found = db.Column(db.Integer, default=0)
    vulnerabilities_found = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)

    # Relationships
    devices = db.relationship(
        "Device", backref="scan", lazy="dynamic", cascade="all, delete-orphan"
    )
    audit_logs = db.relationship(
        "AuditLog", backref="scan", lazy="dynamic", cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "operator_name": self.operator_name,
            "status": self.status,
            "scan_type": self.scan_type,
            "network_range": self.network_range,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "total_hosts_found": self.total_hosts_found,
            "cctv_devices_found": self.cctv_devices_found,
            "vulnerabilities_found": self.vulnerabilities_found,
            "severity_breakdown": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
        }


class Device(db.Model):
    """Discovered device model"""

    __tablename__ = "devices"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    mac_address = db.Column(db.String(17))
    hostname = db.Column(db.String(255))
    manufacturer = db.Column(db.String(100))
    device_type = db.Column(db.String(50))  # camera, dvr, nvr, unknown
    model = db.Column(db.String(100))
    firmware_version = db.Column(db.String(50))
    is_cctv = db.Column(db.Boolean, default=False)
    confidence_score = db.Column(db.Float, default=0.0)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    ports = db.relationship(
        "Port", backref="device", lazy="dynamic", cascade="all, delete-orphan"
    )
    vulnerabilities = db.relationship(
        "Vulnerability", backref="device", lazy="dynamic", cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "manufacturer": self.manufacturer,
            "device_type": self.device_type,
            "model": self.model,
            "firmware_version": self.firmware_version,
            "is_cctv": self.is_cctv,
            "confidence_score": self.confidence_score,
            "discovered_at": (
                self.discovered_at.isoformat() if self.discovered_at else None
            ),
            "ports": [port.to_dict() for port in self.ports],
            "vulnerabilities": [vuln.to_dict() for vuln in self.vulnerabilities],
        }


class Port(db.Model):
    """Open port model"""

    __tablename__ = "ports"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=False)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default="tcp")
    state = db.Column(db.String(20), default="open")
    service_name = db.Column(db.String(50))
    service_version = db.Column(db.String(100))
    banner = db.Column(db.Text)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "port_number": self.port_number,
            "protocol": self.protocol,
            "state": self.state,
            "service_name": self.service_name,
            "service_version": self.service_version,
            "banner": self.banner,
        }


class Vulnerability(db.Model):
    """Vulnerability model"""

    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=False)
    vuln_id = db.Column(db.String(50))
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))  # critical, high, medium, low, info
    cvss_score = db.Column(db.Float)
    cve_id = db.Column(db.String(20))
    cwe_id = db.Column(db.String(20))
    affected_component = db.Column(db.String(100))
    remediation = db.Column(db.Text)
    references = db.Column(db.Text)  # JSON array
    proof_of_concept = db.Column(db.Text)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    verified = db.Column(db.Boolean, default=False)
    false_positive = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "vuln_id": self.vuln_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "affected_component": self.affected_component,
            "remediation": self.remediation,
            "references": json.loads(self.references) if self.references else [],
            "discovered_at": (
                self.discovered_at.isoformat() if self.discovered_at else None
            ),
            "verified": self.verified,
        }


class AuditLog(db.Model):
    """Audit log for compliance"""

    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    operator = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    target = db.Column(db.String(255))
    details = db.Column(db.Text)  # JSON
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    status = db.Column(db.String(20))  # success, failure, error
    error_message = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "operator": self.operator,
            "action": self.action,
            "target": self.target,
            "details": json.loads(self.details) if self.details else {},
            "status": self.status,
            "error_message": self.error_message,
        }


# =============================================================================
# NORMALIZED DATA MODELS FOR REPORTING PIPELINE
# =============================================================================


class NormalizedAsset(db.Model):
    """Normalized asset data for reporting pipeline"""

    __tablename__ = "normalized_assets"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    asset_type = db.Column(db.String(50))  # camera, dvr, nvr, network_device
    ip_address = db.Column(db.String(45), nullable=False)
    hostname = db.Column(db.String(255))
    mac_address = db.Column(db.String(17))
    manufacturer = db.Column(db.String(100))
    model = db.Column(db.String(100))
    firmware_version = db.Column(db.String(50))
    os_info = db.Column(db.String(100))
    criticality = db.Column(db.String(20))  # critical, high, medium, low
    network_segment = db.Column(db.String(50))  # internal, dmz, external
    authentication_state = db.Column(
        db.String(20)
    )  # authenticated, unauthenticated, mixed
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    normalized_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    ports = db.relationship(
        "NormalizedPort", backref="asset", lazy="dynamic", cascade="all, delete-orphan"
    )
    vulnerabilities = db.relationship(
        "NormalizedVulnerability",
        backref="asset",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    def to_dict(self):
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "firmware_version": self.firmware_version,
            "os_info": self.os_info,
            "criticality": self.criticality,
            "network_segment": self.network_segment,
            "authentication_state": self.authentication_state,
            "ports": [port.to_dict() for port in self.ports],
            "vulnerabilities": [vuln.to_dict() for vuln in self.vulnerabilities],
        }


class NormalizedPort(db.Model):
    """Normalized port data"""

    __tablename__ = "normalized_ports"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(
        db.Integer, db.ForeignKey("normalized_assets.id"), nullable=False
    )
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default="tcp")
    service_name = db.Column(db.String(50))
    service_version = db.Column(db.String(100))
    state = db.Column(db.String(20), default="open")
    banner = db.Column(db.Text)
    is_encrypted = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "port_number": self.port_number,
            "protocol": self.protocol,
            "service_name": self.service_name,
            "service_version": self.service_version,
            "state": self.state,
            "banner": self.banner,
            "is_encrypted": self.is_encrypted,
        }


class NormalizedVulnerability(db.Model):
    """Normalized vulnerability data with contextual risk"""

    __tablename__ = "normalized_vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(
        db.Integer, db.ForeignKey("normalized_assets.id"), nullable=False
    )
    vulnerability_id = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    evidence = db.Column(db.Text)
    cvss_score = db.Column(db.Float)
    severity = db.Column(db.String(20))  # critical, high, medium, low, info
    cve_id = db.Column(db.String(20))
    cwe_id = db.Column(db.String(20))
    affected_component = db.Column(db.String(100))
    exploit_available = db.Column(db.Boolean, default=False)
    remediation = db.Column(db.Text)
    references = db.Column(db.Text)  # JSON array
    risk_rating = db.Column(db.String(20))  # critical, high, medium, low
    risk_score = db.Column(db.Float)  # 0-100 contextual risk score
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "vulnerability_id": self.vulnerability_id,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "affected_component": self.affected_component,
            "exploit_available": self.exploit_available,
            "remediation": self.remediation,
            "references": json.loads(self.references) if self.references else [],
            "risk_rating": self.risk_rating,
            "risk_score": self.risk_score,
        }


class ReportTemplate(db.Model):
    """Report templates with versioning"""

    __tablename__ = "report_templates"

    id = db.Column(db.Integer, primary_key=True)
    template_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    template_type = db.Column(db.String(20))  # executive, technical, compliance
    format = db.Column(db.String(10))  # pdf, html, json
    version = db.Column(db.String(20), default="1.0")
    template_content = db.Column(db.Text)  # Jinja2 template
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def to_dict(self):
        return {
            "template_id": self.template_id,
            "name": self.name,
            "description": self.description,
            "template_type": self.template_type,
            "format": self.format,
            "version": self.version,
            "is_active": self.is_active,
        }


class Report(db.Model):
    """Generated reports"""

    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.String(50), unique=True, nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    title = db.Column(db.String(255))
    format = db.Column(db.String(10))  # pdf, html, json
    template_id = db.Column(db.String(50))  # Reference to template used
    file_path = db.Column(db.String(500))
    file_size = db.Column(db.Integer)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    generated_by = db.Column(db.String(100))
    checksum = db.Column(db.String(64))  # SHA-256
    is_immutable = db.Column(db.Boolean, default=True)  # Audit-ready

    def to_dict(self):
        return {
            "id": self.id,
            "report_id": self.report_id,
            "scan_id": self.scan_id,
            "title": self.title,
            "format": self.format,
            "template_id": self.template_id,
            "file_size": self.file_size,
            "generated_at": self.generated_at.isoformat(),
            "generated_by": self.generated_by,
            "is_immutable": self.is_immutable,
        }
