"""Scan Model - Single Tenant"""

import enum
from datetime import datetime
from backend.enterprise.extensions import db


class ScanStatus(enum.Enum):
    QUEUED = "queued"
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(36), nullable=False, index=True, default="default")
    scan_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    operator_name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.Enum(ScanStatus), default=ScanStatus.PENDING)
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
    celery_task_id = db.Column(db.String(36))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, default=False)

    devices = db.relationship(
        "Device",
        backref="scan",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "operator_name": self.operator_name,
            "status": self.status.value if self.status else None,
            "scan_type": self.scan_type,
            "network_range": self.network_range,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
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
