"""
Database Models
"""

from app.models.user import User, UserRole
from app.models.scan import Scan, ScanStatus
from app.models.device import Device
from app.models.port import Port
from app.models.vulnerability import Vulnerability
from app.models.audit_log import AuditLog
from app.models.report import Report
try:
    from app.models.idempotency import IdempotencyKey
except Exception:  # idempotency model may live elsewhere or be optional in tests
    IdempotencyKey = None

__all__ = [
    "User",
    "UserRole",
    "Scan",
    "ScanStatus",
    "Device",
    "Port",
    "Vulnerability",
    "AuditLog",
    "Report",
]

if IdempotencyKey is not None:
    __all__.append("IdempotencyKey")

