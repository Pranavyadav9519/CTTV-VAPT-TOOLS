"""Device Model"""

from datetime import datetime
from backend.enterprise.extensions import db


class Device(db.Model):
    __tablename__ = "devices"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(36), nullable=False, index=True, default="default")
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    mac_address = db.Column(db.String(17))
    hostname = db.Column(db.String(255))
    manufacturer = db.Column(db.String(100))
    device_type = db.Column(db.String(50))
    model = db.Column(db.String(100))
    firmware_version = db.Column(db.String(50))
    is_cctv = db.Column(db.Boolean, default=False)
    confidence_score = db.Column(db.Float, default=0.0)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, default=False)

    ports = db.relationship(
        "Port",
        backref="device",
        lazy="dynamic",
        cascade="all, delete-orphan"
    )
    vulnerabilities = db.relationship(
        "Vulnerability",
        backref="device",
        lazy="dynamic",
        cascade="all, delete-orphan"
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
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
            "ports": [port.to_dict() for port in self.ports],
            "vulnerabilities": [vuln.to_dict() for vuln in self.vulnerabilities],
        }
