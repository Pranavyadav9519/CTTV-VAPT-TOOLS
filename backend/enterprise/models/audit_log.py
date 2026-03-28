"""Audit Log Model with HMAC Integrity"""

import os
import json
import hmac
import hashlib
from datetime import datetime
from backend.enterprise.extensions import db


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(36), nullable=False, index=True, default="default")
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    action = db.Column(db.String(100), nullable=False)
    target = db.Column(db.String(255))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    status = db.Column(db.String(20))
    error_message = db.Column(db.Text)
    integrity_hash = db.Column(db.String(64))

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._generate_integrity_hash()

    def _generate_integrity_hash(self):
        if not self.integrity_hash:
            key = f"{self.tenant_id}:{self.action}:{self.timestamp}".encode()
            secret = os.environ.get("AUDIT_LOG_KEY")
            if not secret:
                raise RuntimeError("AUDIT_LOG_KEY must be set for audit log integrity")
            self.integrity_hash = hmac.new(
                secret.encode(),
                key,
                hashlib.sha256
            ).hexdigest()

    def verify_integrity(self) -> bool:
        expected = f"{self.tenant_id}:{self.action}:{self.timestamp}".encode()
        secret = os.environ.get("AUDIT_LOG_KEY")
        if not secret:
            raise RuntimeError("AUDIT_LOG_KEY must be set for audit log integrity")
        expected_hash = hmac.new(
            secret.encode(),
            expected,
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(self.integrity_hash, expected_hash)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "action": self.action,
            "target": self.target,
            "details": json.loads(self.details) if self.details else {},
            "ip_address": self.ip_address,
            "status": self.status,
            "error_message": self.error_message,
        }

    @staticmethod
    def compute_hmac(event_data):
        secret = os.environ.get("AUDIT_LOG_KEY")
        if not secret:
            raise RuntimeError("AUDIT_LOG_KEY must be set for audit log integrity")
        return hmac.new(secret.encode(), event_data.encode(), hashlib.sha256).hexdigest()

    @classmethod
    def log_event(cls, tenant_id, event_type, event_data):
        event_json = json.dumps(event_data, sort_keys=True)
        hmac_sig = cls.compute_hmac(event_json)
        entry = cls(
            tenant_id=tenant_id,
            action=event_type,
            details=event_json,
            integrity_hash=hmac_sig
        )
        db.session.add(entry)
        db.session.commit()
        return entry
