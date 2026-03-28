"""User Model with RBAC Support"""

import enum
from datetime import datetime
from backend.enterprise.extensions import db


class UserRole(enum.Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(36), nullable=False, index=True, default="default")
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(UserRole), default=UserRole.VIEWER)
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    scans = db.relationship("Scan", backref="user", lazy="dynamic")

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role.value,
            "is_active": self.is_active,
            "is_verified": self.is_verified,
            "created_at": (
                self.created_at.isoformat() if self.created_at else None
            ),
            "last_login": (
                self.last_login.isoformat() if self.last_login else None
            ),
        }

    def has_permission(self, permission: str) -> bool:
        role_permissions = {
            UserRole.ADMIN: ["read", "write", "delete", "scan", "report"],
            UserRole.OPERATOR: ["read", "write", "scan", "report"],
            UserRole.VIEWER: ["read"],
        }
        return permission in role_permissions.get(self.role, [])
