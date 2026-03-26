"""Report Model with Immutable Storage"""

from datetime import datetime
from app.extensions import db


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(36), nullable=False, index=True)
    report_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    title = db.Column(db.String(255))
    format = db.Column(db.String(10))
    file_path = db.Column(db.String(500))
    file_size = db.Column(db.Integer)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    generated_by = db.Column(db.String(100))
    checksum = db.Column(db.String(64))
    is_immutable = db.Column(db.Boolean, default=True)
    encryption_key = db.Column(db.String(256))
    is_deleted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @staticmethod
    def save_to_s3(tenant_id, report_type, data, s3_client, kms_client):
        import time
        key = f"reports/{tenant_id}/{report_type}/{int(time.time())}.json"
        try:
            encrypted = kms_client.encrypt(data.encode())
            s3_client.put_object(Bucket=s3_client.bucket, Key=key, Body=encrypted)
            return key
        except Exception as exc:
            raise RuntimeError(f"Failed to save report to S3: {exc}")

    def to_dict(self):
        return {
            "id": self.id,
            "report_id": self.report_id,
            "scan_id": self.scan_id,
            "title": self.title,
            "format": self.format,
            "file_size": self.file_size,
            "generated_at": self.generated_at.isoformat() if self.generated_at else None,
            "generated_by": self.generated_by,
            "is_immutable": self.is_immutable,
        }
