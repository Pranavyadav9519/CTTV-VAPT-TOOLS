"""
Repository Pattern Implementation
Clean data access layer with proper error handling
"""

from typing import List, Optional, Dict, Any
from sqlalchemy import and_, or_, desc
from sqlalchemy.exc import SQLAlchemyError
import logging

from backend.core.database import db
from backend.core.models import (
    User, Scan, Device, Port, Vulnerability, Report, AuditLog, ScanStatus
)

logger = logging.getLogger(__name__)


class BaseRepository:
    """Base repository with common CRUD operations"""

    model = None

    @classmethod
    def create(cls, **kwargs) -> Optional[Any]:
        """Create a new record"""
        try:
            instance = cls.model(**kwargs)
            db.session.add(instance)
            db.session.commit()
            logger.debug(f"Created {cls.model.__name__} record")
            return instance
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Error creating {cls.model.__name__}: {e}")
            raise

    @classmethod
    def get_by_id(cls, id: int) -> Optional[Any]:
        """Get record by ID"""
        try:
            return cls.model.query.filter_by(id=id, is_deleted=False).first()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching {cls.model.__name__} by ID: {e}")
            raise

    @classmethod
    def update(cls, id: int, **kwargs) -> Optional[Any]:
        """Update a record"""
        try:
            instance = cls.get_by_id(id)
            if not instance:
                return None

            for key, value in kwargs.items():
                if hasattr(instance, key):
                    setattr(instance, key, value)

            db.session.commit()
            logger.debug(f"Updated {cls.model.__name__} record {id}")
            return instance
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Error updating {cls.model.__name__}: {e}")
            raise

    @classmethod
    def delete(cls, id: int) -> bool:
        """Soft delete a record"""
        try:
            instance = cls.get_by_id(id)
            if not instance:
                return False

            instance.soft_delete()
            db.session.commit()
            logger.debug(f"Soft deleted {cls.model.__name__} record {id}")
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Error deleting {cls.model.__name__}: {e}")
            raise

    @classmethod
    def get_all(cls, skip: int = 0, limit: int = 100) -> List[Any]:
        """Get all active records with pagination"""
        try:
            return cls.model.query.filter_by(is_deleted=False).offset(skip).limit(limit).all()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching all {cls.model.__name__}: {e}")
            raise


class UserRepository(BaseRepository):
    """User data access"""
    model = User

    @classmethod
    def get_by_email(cls, email: str) -> Optional[User]:
        """Get user by email"""
        try:
            return User.query.filter_by(email=email, is_deleted=False).first()
        except SQLAlchemyError as e:
            logger.error(f"Error finding user by email: {e}")
            raise

    @classmethod
    def get_by_username(cls, username: str) -> Optional[User]:
        """Get user by username"""
        try:
            return User.query.filter_by(username=username, is_deleted=False).first()
        except SQLAlchemyError as e:
            logger.error(f"Error finding user by username: {e}")
            raise

    @classmethod
    def get_active_users(cls, tenant_id: str) -> List[User]:
        """Get all active users for tenant"""
        try:
            return User.query.filter(
                User.tenant_id == tenant_id,
                User.is_active == True,
                User.is_deleted == False
            ).all()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching active users: {e}")
            raise


class ScanRepository(BaseRepository):
    """Scan data access"""
    model = Scan

    @classmethod
    def get_by_scan_id(cls, scan_id: str, tenant_id: str) -> Optional[Scan]:
        """Get scan by scan_id"""
        try:
            return Scan.query.filter(
                Scan.scan_id == scan_id,
                Scan.tenant_id == tenant_id,
                Scan.is_deleted == False
            ).first()
        except SQLAlchemyError as e:
            logger.error(f"Error finding scan: {e}")
            raise

    @classmethod
    def get_scans_by_user(cls, user_id: int, tenant_id: str, skip: int = 0, limit: int = 100) -> List[Scan]:
        """Get all scans for a user"""
        try:
            return Scan.query.filter(
                Scan.user_id == user_id,
                Scan.tenant_id == tenant_id,
                Scan.is_deleted == False
            ).order_by(desc(Scan.created_at)).offset(skip).limit(limit).all()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching user scans: {e}")
            raise

    @classmethod
    def get_active_scans(cls, tenant_id: str) -> List[Scan]:
        """Get all active scans for tenant"""
        try:
            return Scan.query.filter(
                Scan.tenant_id == tenant_id,
                Scan.status.in_([ScanStatus.PENDING, ScanStatus.QUEUED, ScanStatus.RUNNING]),
                Scan.is_deleted == False
            ).all()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching active scans: {e}")
            raise

    @classmethod
    def count_active_scans(cls, tenant_id: str) -> int:
        """Count active scans for tenant"""
        try:
            return Scan.query.filter(
                Scan.tenant_id == tenant_id,
                Scan.status.in_([ScanStatus.PENDING, ScanStatus.QUEUED, ScanStatus.RUNNING]),
                Scan.is_deleted == False
            ).count()
        except SQLAlchemyError as e:
            logger.error(f"Error counting active scans: {e}")
            raise


class DeviceRepository(BaseRepository):
    """Device data access"""
    model = Device

    @classmethod
    def get_devices_by_scan(cls, scan_id: int, skip: int = 0, limit: int = 100) -> List[Device]:
        """Get all devices discovered in a scan"""
        try:
            return Device.query.filter(
                Device.scan_id == scan_id,
                Device.is_deleted == False
            ).offset(skip).limit(limit).all()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching devices: {e}")
            raise

    @classmethod
    def get_cctv_devices(cls, scan_id: int) -> List[Device]:
        """Get all CCTV devices in a scan"""
        try:
            return Device.query.filter(
                Device.scan_id == scan_id,
                Device.is_cctv == True,
                Device.is_deleted == False
            ).all()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching CCTV devices: {e}")
            raise

    @classmethod
    def get_by_ip(cls, scan_id: int, ip_address: str) -> Optional[Device]:
        """Get device by IP address"""
        try:
            return Device.query.filter(
                Device.scan_id == scan_id,
                Device.ip_address == ip_address,
                Device.is_deleted == False
            ).first()
        except SQLAlchemyError as e:
            logger.error(f"Error finding device: {e}")
            raise


class VulnerabilityRepository(BaseRepository):
    """Vulnerability data access"""
    model = Vulnerability

    @classmethod
    def get_vulnerabilities_by_device(cls, device_id: int) -> List[Vulnerability]:
        """Get all vulnerabilities for a device"""
        try:
            return Vulnerability.query.filter(
                Vulnerability.device_id == device_id,
                Vulnerability.is_deleted == False
            ).order_by(desc(Vulnerability.cvss_score)).all()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching vulnerabilities: {e}")
            raise

    @classmethod
    def get_vulnerabilities_by_scan(cls, scan_id: int) -> List[Vulnerability]:
        """Get all vulnerabilities found in a scan"""
        try:
            return db.session.query(Vulnerability).join(
                Device
            ).filter(
                Device.scan_id == scan_id,
                Vulnerability.is_deleted == False
            ).all()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching scan vulnerabilities: {e}")
            raise

    @classmethod
    def get_critical_vulnerabilities(cls, scan_id: int) -> List[Vulnerability]:
        """Get critical vulnerabilities for a scan"""
        try:
            from backend.core.models import SeverityLevel
            return db.session.query(Vulnerability).join(
                Device
            ).filter(
                Device.scan_id == scan_id,
                Vulnerability.severity == SeverityLevel.CRITICAL,
                Vulnerability.false_positive == False,
                Vulnerability.is_deleted == False
            ).all()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching critical vulnerabilities: {e}")
            raise

    @classmethod
    def count_by_severity(cls, scan_id: int) -> Dict[str, int]:
        """Count vulnerabilities by severity for a scan"""
        try:
            from backend.core.models import SeverityLevel
            result = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0,
            }

            vulns = db.session.query(Vulnerability).join(Device).filter(
                Device.scan_id == scan_id,
                Vulnerability.is_deleted == False
            ).all()

            for vuln in vulns:
                severity = vuln.severity.value if vuln.severity else 'info'
                if severity in result:
                    result[severity] += 1

            return result
        except SQLAlchemyError as e:
            logger.error(f"Error counting vulnerabilities: {e}")
            raise


class ReportRepository(BaseRepository):
    """Report data access"""
    model = Report

    @classmethod
    def get_by_report_id(cls, report_id: str, tenant_id: str) -> Optional[Report]:
        """Get report by report_id"""
        try:
            return Report.query.filter(
                Report.report_id == report_id,
                Report.tenant_id == tenant_id,
                Report.is_deleted == False
            ).first()
        except SQLAlchemyError as e:
            logger.error(f"Error finding report: {e}")
            raise

    @classmethod
    def get_reports_by_scan(cls, scan_id: int) -> List[Report]:
        """Get all reports for a scan"""
        try:
            return Report.query.filter(
                Report.scan_id == scan_id,
                Report.is_deleted == False
            ).all()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching reports: {e}")
            raise


class AuditLogRepository(BaseRepository):
    """Audit log data access"""
    model = AuditLog

    @classmethod
    def log_action(cls, user_id: Optional[int], tenant_id: str, action: str,
                   resource_type: Optional[str] = None, resource_id: Optional[str] = None,
                   details: Optional[Dict] = None, ip_address: Optional[str] = None,
                   status: str = "success", error_message: Optional[str] = None) -> AuditLog:
        """Create audit log entry"""
        try:
            import json
            audit = AuditLog(
                user_id=user_id,
                tenant_id=tenant_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                details=json.dumps(details) if details else None,
                ip_address=ip_address,
                status=status,
                error_message=error_message
            )
            db.session.add(audit)
            db.session.commit()
            return audit
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Error creating audit log: {e}")
            raise

    @classmethod
    def get_tenant_audit_log(cls, tenant_id: str, action: Optional[str] = None,
                             skip: int = 0, limit: int = 100) -> List[AuditLog]:
        """Get audit logs for tenant"""
        try:
            query = AuditLog.query.filter(AuditLog.tenant_id == tenant_id)

            if action:
                query = query.filter(AuditLog.action == action)

            return query.order_by(desc(AuditLog.timestamp)).offset(skip).limit(limit).all()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching audit logs: {e}")
            raise
