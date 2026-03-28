from datetime import datetime
from backend.enterprise.extensions import db


class BaseModel(db.Model):
    __abstract__ = True
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(36), nullable=False, index=True, default="default")
    idempotency_key = db.Column(db.String(128), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, default=False)

    def soft_delete(self):
        self.is_deleted = True
        return self
