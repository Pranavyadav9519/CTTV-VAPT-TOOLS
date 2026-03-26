"""
Service Layer - Business Logic Implementation
Handles core application logic and orchestration
"""

from typing import Dict, List, Optional, Tuple
from datetime import datetime
import logging
import uuid
import ipaddress
import json
import hashlib
from pathlib import Path

from backend.core.database import db
from backend.core.models import (
    User, Scan, Device, Vulnerability, ScanStatus, SeverityLevel, DeviceType, Report
)
from backend.core.repositories import (
    UserRepository, ScanRepository, DeviceRepository, 
    VulnerabilityRepository, AuditLogRepository, ReportRepository
)

logger = logging.getLogger(__name__)


class AuthService:
    """Authentication and user management"""

    @staticmethod
    def register_user(email: str, username: str, password: str, tenant_id: str) -> Tuple[User, bool]:
        """Register a new user"""
        try:
            # Validation
            if len(password) < 8:
                return None, False

            # Check if user exists
            existing = UserRepository.get_by_email(email)
            if existing:
                logger.warning(f"Registration attempt with existing email: {email}")
                return None, False

            # Create user
            user = User(
                email=email,
                username=username,
                tenant_id=tenant_id,
                first_name="",
                last_name=""
            )
            user.set_password(password)

            db.session.add(user)
            db.session.commit()

            logger.info(f"User registered: {username}")
            return user, True

        except Exception as e:
            logger.error(f"Registration error: {e}")
            return None, False

    @staticmethod
    def authenticate_user(username: str, password: str) -> Tuple[Optional[User], bool]:
        """Authenticate a user"""
        try:
            user = UserRepository.get_by_username(username)

            if not user:
                logger.warning(f"Login attempt with non-existent user: {username}")
                return None, False

            if not user.is_active:
                logger.warning(f"Login attempt with inactive user: {username}")
                return None, False

            if not user.check_password(password):
                # Increment failed attempts
                user.failed_login_attempts += 1
                db.session.commit()
                logger.warning(f"Failed login attempt: {username}")
                return None, False

            # Reset failed attempts on successful login
            user.failed_login_attempts = 0
            user.last_login = datetime.utcnow()
            db.session.commit()

            logger.info(f"User authenticated: {username}")
            return user, True

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None, False


class ScanService:
    """Scan management and orchestration"""

    @staticmethod
    def create_scan(user_id: int, tenant_id: str, network_range: Optional[str] = None,
                    scan_type: str = "network_discovery", description: str = "") -> Tuple[Optional[Scan], bool]:
        """Create a new scan"""
        try:
            # Validate network range if provided
            if network_range:
                try:
                    net = ipaddress.ip_network(network_range, strict=False)
                    from backend.core.config import get_config
                    config = get_config()

                    if net.num_addresses > config.MAX_SCAN_HOSTS:
                        logger.warning(f"Network range too large: {network_range}")
                        return None, False

                except ValueError:
                    logger.warning(f"Invalid network range: {network_range}")
                    return None, False

            # Check concurrent scan limit
            active_count = ScanRepository.count_active_scans(tenant_id)
            from backend.core.config import get_config
            config = get_config()

            if active_count >= config.MAX_CONCURRENT_SCANS:
                logger.warning(f"Concurrent scan limit reached for tenant: {tenant_id}")
                return None, False

            # Create scan
            scan = Scan(
                scan_id=f"SCAN-{uuid.uuid4().hex[:12].upper()}",
                user_id=user_id,
                tenant_id=tenant_id,
                status=ScanStatus.PENDING,
                network_range=network_range,
                scan_type=scan_type,
                description=description
            )

            db.session.add(scan)
            db.session.commit()

            logger.info(f"Scan created: {scan.scan_id}")

            # Audit log
            AuditLogRepository.log_action(
                user_id=user_id,
                tenant_id=tenant_id,
                action="scan_created",
                resource_type="scan",
                resource_id=scan.scan_id,
                details={
                    "network_range": network_range,
                    "scan_type": scan_type
                }
            )

            return scan, True

        except Exception as e:
            logger.error(f"Error creating scan: {e}")
            return None, False

    @staticmethod
    def get_scan(scan_id: str, tenant_id: str, user_id: int) -> Optional[Scan]:
        """Get a specific scan with authorization check"""
        try:
            scan = ScanRepository.get_by_scan_id(scan_id, tenant_id)

            if not scan:
                return None

            # Verify user has access
            user = UserRepository.get_by_id(user_id)
            if not user.can_access_scan(scan):
                logger.warning(f"Unauthorized scan access: {user_id} -> {scan_id}")
                return None

            return scan

        except Exception as e:
            logger.error(f"Error fetching scan: {e}")
            return None

    @staticmethod
    def update_scan_progress(scan_id: int, progress: int, status: ScanStatus = None):
        """Update scan progress"""
        try:
            scan = ScanRepository.get_by_id(scan_id)
            if not scan:
                return False

            scan.progress_percent = min(100, max(0, progress))

            if status:
                scan.status = status

            if status == ScanStatus.RUNNING and not scan.started_at:
                scan.started_at = datetime.utcnow()

            if status == ScanStatus.COMPLETED:
                scan.completed_at = datetime.utcnow()

            db.session.commit()
            return True

        except Exception as e:
            logger.error(f"Error updating scan progress: {e}")
            return False


class DeviceService:
    """Device discovery and management"""

    @staticmethod
    def add_discovered_device(scan_id: int, tenant_id: str, ip_address: str,
                              mac_address: Optional[str] = None,
                              hostname: Optional[str] = None,
                              manufacturer: Optional[str] = None,
                              device_type: DeviceType = DeviceType.UNKNOWN,
                              model: Optional[str] = None,
                              firmware_version: Optional[str] = None,
                              is_cctv: bool = False,
                              confidence_score: float = 0.0) -> Tuple[Optional[Device], bool]:
        """Add a discovered device to the scan"""
        try:
            # Check if device already exists
            existing = DeviceRepository.get_by_ip(scan_id, ip_address)
            if existing:
                # Update existing device
                existing.mac_address = mac_address or existing.mac_address
                existing.hostname = hostname or existing.hostname
                existing.manufacturer = manufacturer or existing.manufacturer
                existing.device_type = device_type or existing.device_type
                existing.model = model or existing.model
                existing.firmware_version = firmware_version or existing.firmware_version
                existing.is_cctv = is_cctv or existing.is_cctv
                existing.confidence_score = max(confidence_score, existing.confidence_score)
                existing.last_seen = datetime.utcnow()

                db.session.commit()
                logger.debug(f"Updated device: {ip_address}")
                return existing, True

            # Create new device
            device = Device(
                scan_id=scan_id,
                tenant_id=tenant_id,
                ip_address=ip_address,
                mac_address=mac_address,
                hostname=hostname,
                manufacturer=manufacturer,
                device_type=device_type,
                model=model,
                firmware_version=firmware_version,
                is_cctv=is_cctv,
                confidence_score=confidence_score
            )

            db.session.add(device)
            db.session.commit()

            logger.info(f"Device discovered: {ip_address}")
            return device, True

        except Exception as e:
            logger.error(f"Error adding device: {e}")
            return None, False

    @staticmethod
    def get_scan_devices(scan_id: int, skip: int = 0, limit: int = 100) -> List[Device]:
        """Get all devices in a scan"""
        try:
            return DeviceRepository.get_devices_by_scan(scan_id, skip, limit)
        except Exception as e:
            logger.error(f"Error fetching devices: {e}")
            return []


class VulnerabilityService:
    """Vulnerability detection and management"""

    @staticmethod
    def add_vulnerability(device_id: int, title: str, description: str,
                          severity: SeverityLevel, cvss_score: float = 0.0,
                          cve_id: Optional[str] = None, cwe_id: Optional[str] = None,
                          remediation: Optional[str] = None,
                          references: Optional[List[str]] = None,
                          port_id: Optional[int] = None) -> Tuple[Optional[Vulnerability], bool]:
        """Add a vulnerability finding"""
        try:
            import json

            # Generate unique vulnerability ID
            vuln_id = f"VULN-{uuid.uuid4().hex[:12].upper()}"

            vulnerability = Vulnerability(
                device_id=device_id,
                port_id=port_id,
                vuln_id=vuln_id,
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cve_id=cve_id,
                cwe_id=cwe_id,
                remediation=remediation,
                references=json.dumps(references) if references else None
            )

            db.session.add(vulnerability)
            db.session.commit()

            logger.info(f"Vulnerability recorded: {vuln_id}")
            return vulnerability, True

        except Exception as e:
            logger.error(f"Error adding vulnerability: {e}")
            return None, False

    @staticmethod
    def get_device_vulnerabilities(device_id: int) -> List[Vulnerability]:
        """Get all vulnerabilities for a device"""
        try:
            return VulnerabilityRepository.get_vulnerabilities_by_device(device_id)
        except Exception as e:
            logger.error(f"Error fetching vulnerabilities: {e}")
            return []

    @staticmethod
    def calculate_severity_distribution(scan_id: int) -> Dict[str, int]:
        """Calculate vulnerability count by severity for a scan"""
        try:
            return VulnerabilityRepository.count_by_severity(scan_id)
        except Exception as e:
            logger.error(f"Error calculating severity distribution: {e}")
            return {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }

    @staticmethod
    def update_scan_vulnerability_counts(scan_id: int):
        """Update scan's vulnerability counts"""
        try:
            severity_counts = VulnerabilityService.calculate_severity_distribution(scan_id)

            scan = ScanRepository.get_by_id(scan_id)
            if not scan:
                return False

            scan.critical_count = severity_counts.get('critical', 0)
            scan.high_count = severity_counts.get('high', 0)
            scan.medium_count = severity_counts.get('medium', 0)
            scan.low_count = severity_counts.get('low', 0)
            scan.vulnerabilities_found = sum(severity_counts.values())

            db.session.commit()
            return True

        except Exception as e:
            logger.error(f"Error updating vulnerability counts: {e}")
            return False


class ReportService:
    """Report generation and management with formatting and storage"""

    @staticmethod
    def generate_report(scan_id: int, report_format: str = "json", user_id: Optional[int] = None,
                       tenant_id: Optional[str] = None) -> Tuple[Optional[Dict], bool]:
        """Generate and persist a comprehensive report for a scan"""
        try:
            from backend.core.repositories import ReportRepository
            from backend.core.models import Report
            import json
            import hashlib
            from pathlib import Path
            import os

            # Validate scan
            scan = ScanRepository.get_by_id(scan_id)
            if not scan or scan.status != ScanStatus.COMPLETED:
                logger.warning(f"Cannot generate report for incomplete scan: {scan_id}")
                return None, False

            # Gather comprehensive scan data
            scan_data = ReportService._gather_scan_data(scan)

            # Format report based on requested format
            if report_format == "json":
                report_content = json.dumps(scan_data, indent=2, default=str)
                file_ext = ".json"
            elif report_format == "html":
                report_content = ReportService._format_html_report(scan_data)
                file_ext = ".html"
            else:
                logger.warning(f"Unsupported report format: {report_format}")
                return None, False

            # Create report file path
            report_dir = Path("backend/reports")
            report_dir.mkdir(parents=True, exist_ok=True)

            report_id = str(uuid.uuid4())[:12]
            filename = f"VAPT_Report_{report_id}{file_ext}"
            file_path = report_dir / filename

            # Write report to file
            with open(file_path, 'w') as f:
                f.write(report_content)

            # Calculate checksum
            checksum = hashlib.sha256(report_content.encode()).hexdigest()

            # Save report record to database
            report = Report(
                report_id=report_id,
                scan_id=scan_id,
                tenant_id=tenant_id or scan.tenant_id,
                title=f"Vulnerability Report: {scan.network_range}",
                format=report_format,
                file_path=str(file_path),
                file_size=len(report_content),
                generated_by=scan.operator.username if scan.operator else "system",
                checksum=checksum,
                is_immutable=True
            )

            db.session.add(report)
            db.session.commit()

            # Log action
            AuditLogRepository.log_action(
                user_id=user_id,
                action="report_generated",
                resource_type="report",
                resource_id=report_id,
                tenant_id=tenant_id or scan.tenant_id,
                status="success",
                details={"scan_id": scan_id, "format": report_format}
            )

            logger.info(f"Report generated: {report_id} ({report_format})")

            return report.to_dict(), True

        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return None, False

    @staticmethod
    def _gather_scan_data(scan: 'Scan') -> Dict:
        """Gather all scan data from database"""
        scan_data = {
            'report_id': scan.scan_id,
            'operator': scan.operator.username if scan.operator else "Unknown",
            'network_range': scan.network_range,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'duration_seconds': ReportService._calculate_duration(scan),
            'devices': [],
            'summary': {
                'total_hosts': scan.total_hosts_found,
                'cctv_devices': scan.cctv_devices_found,
                'vulnerabilities': scan.vulnerabilities_found,
                'severity_breakdown': scan.get_severity_breakdown()
            }
        }

        # Gather devices and vulnerabilities
        devices = DeviceRepository.get_devices_by_scan(scan.id)
        for device in devices:
            device_data = device.to_dict()
            vulns = VulnerabilityRepository.get_vulnerabilities_by_device(device.id) if hasattr(
                VulnerabilityRepository, 'get_vulnerabilities_by_device') else []
            device_data['vulnerabilities'] = [v.to_dict() for v in vulns]
            device_data['vulnerability_count'] = len(vulns)
            scan_data['devices'].append(device_data)

        return scan_data

    @staticmethod
    def _calculate_duration(scan: 'Scan') -> int:
        """Calculate scan duration in seconds"""
        try:
            if scan.started_at and scan.completed_at:
                delta = scan.completed_at - scan.started_at
                return int(delta.total_seconds())
        except:
            pass
        return 0

    @staticmethod
    def _format_html_report(scan_data: Dict) -> str:
        """Format scan data as HTML report"""
        severity_breakdown = scan_data.get('summary', {}).get('severity_breakdown', {})
        critical_count = severity_breakdown.get('critical', 0)
        high_count = severity_breakdown.get('high', 0)
        medium_count = severity_breakdown.get('medium', 0)
        low_count = severity_breakdown.get('low', 0)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VAPT Report - {scan_data.get('network_range', 'N/A')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; background: white; }}
        header {{ border-bottom: 4px solid #2c3e50; padding-bottom: 20px; margin-bottom: 30px; }}
        h1 {{ color: #2c3e50; font-size: 2.5em; margin-bottom: 5px; }}
        .metadata {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-top: 20px; }}
        .meta-box {{ background: #ecf0f1; padding: 15px; border-radius: 5px; }}
        .meta-box label {{ font-weight: bold; color: #7f8c8d; font-size: 0.9em; }}
        .meta-box value {{ font-size: 1.1em; color: #2c3e50; display: block; margin-top: 5px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 30px 0; }}
        .summary-box {{ padding: 20px; border-radius: 5px; text-align: center; }}
        .summary-box h3 {{ font-size: 1.3em; margin-bottom: 10px; }}
        .summary-box .value {{ font-size: 2em; font-weight: bold; }}
        .critical {{ background: #e74c3c; color: white; }}
        .high {{ background: #e67e22; color: white; }}
        .medium {{ background: #f39c12; color: white; }}
        .low {{ background: #3498db; color: white; }}
        .devices-section {{ margin-top: 40px; }}
        .device {{ background: #f8f9fa; padding: 20px; margin-bottom: 20px; border-left: 4px solid #3498db; border-radius: 3px; }}
        .device.cctv {{ border-left-color: #e74c3c; }}
        .device-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
        .device-header h3 {{ color: #2c3e50; }}
        .device-badge {{ background: #e74c3c; color: white; padding: 5px 15px; border-radius: 20px; font-size: 0.9em; }}
        .device-details {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 15px; }}
        .detail-item {{ font-size: 0.95em; }}
        .detail-item strong {{ display: block; color: #7f8c8d; font-size: 0.85em; margin-bottom: 3px; }}
        .vulnerabilities {{ margin-top: 20px; margin-left: 20px; }}
        .vuln-item {{ background: white; padding: 15px; border-radius: 3px; margin-bottom: 10px; border-left: 3px solid #3498db; }}
        .vuln-item.critical {{ border-left-color: #e74c3c; }}
        .vuln-item.high {{ border-left-color: #e67e22; }}
        .vuln-item.medium {{ border-left-color: #f39c12; }}
        .vuln-item.low {{ border-left-color: #3498db; }}
        .vuln-title {{ font-weight: bold; color: #2c3e50; margin-bottom: 5px; }}
        .vuln-meta {{ display: flex; gap: 15px; font-size: 0.9em; margin-bottom: 8px; }}
        .badge {{ background: #ecf0f1; padding: 2px 8px; border-radius: 3px; }}
        footer {{ margin-top: 50px; padding-top: 20px; border-top: 1px solid #ecf0f1; color: #7f8c8d; font-size: 0.9em; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>CCTV Vulnerability Assessment Report</h1>
            <div class="metadata">
                <div class="meta-box">
                    <label>Network Range</label>
                    <value>{scan_data.get('network_range', 'N/A')}</value>
                </div>
                <div class="meta-box">
                    <label>Scan Duration</label>
                    <value>{scan_data.get('duration_seconds', 0)}s</value>
                </div>
                <div class="meta-box">
                    <label>Operator</label>
                    <value>{scan_data.get('operator', 'Unknown')}</value>
                </div>
                <div class="meta-box">
                    <label>Report Generated</label>
                    <value>{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</value>
                </div>
            </div>
        </header>

        <section class="summary">
            <div class="summary-box critical">
                <h3>Critical</h3>
                <div class="value">{critical_count}</div>
            </div>
            <div class="summary-box high">
                <h3>High</h3>
                <div class="value">{high_count}</div>
            </div>
            <div class="summary-box medium">
                <h3>Medium</h3>
                <div class="value">{medium_count}</div>
            </div>
            <div class="summary-box low">
                <h3>Low</h3>
                <div class="value">{low_count}</div>
            </div>
        </section>

        <section class="summary">
            <div class="summary-box" style="background: #34495e; color: white;">
                <h3>Total Hosts</h3>
                <div class="value">{scan_data.get('summary', {}).get('total_hosts', 0)}</div>
            </div>
            <div class="summary-box" style="background: #c0392b; color: white;">
                <h3>CCTV Devices</h3>
                <div class="value">{scan_data.get('summary', {}).get('cctv_devices', 0)}</div>
            </div>
            <div class="summary-box" style="background: #16a085; color: white;">
                <h3>Vulnerabilities Found</h3>
                <div class="value">{scan_data.get('summary', {}).get('vulnerabilities', 0)}</div>
            </div>
            <div class="summary-box" style="background: #27ae60; color: white;">
                <h3>Affected Devices</h3>
                <div class="value">{len([d for d in scan_data.get('devices', []) if d.get('vulnerability_count', 0) > 0])}</div>
            </div>
        </section>
"""

        # Add devices section
        if scan_data.get('devices'):
            html += '<section class="devices-section"><h2 style="color: #2c3e50; margin-bottom: 20px;">Discovered Devices & Vulnerabilities</h2>'

            for device in scan_data.get('devices', []):
                is_cctv = device.get('is_cctv', False)
                device_class = 'cctv' if is_cctv else ''
                cctv_badge = '<span class="device-badge">⚠ CCTV Device</span>' if is_cctv else ''

                html += f"""
                <div class="device {device_class}">
                    <div class="device-header">
                        <h3>{device.get('ip_address', 'Unknown')} - {device.get('device_type', 'Unknown').upper()}</h3>
                        {cctv_badge}
                    </div>
                    <div class="device-details">
                        <div class="detail-item">
                            <strong>MAC Address</strong>
                            {device.get('mac_address', 'N/A')}
                        </div>
                        <div class="detail-item">
                            <strong>Manufacturer</strong>
                            {device.get('manufacturer', 'Unknown')}
                        </div>
                        <div class="detail-item">
                            <strong>Confidence</strong>
                            {device.get('confidence_score', 0)}%
                        </div>
                    </div>
"""

                # Add vulnerabilities for device
                vulns = device.get('vulnerabilities', [])
                if vulns:
                    html += '<div class="vulnerabilities">'
                    for vuln in vulns:
                        severity = vuln.get('severity', 'low').lower()
                        html += f"""
                        <div class="vuln-item {severity}">
                            <div class="vuln-title">{vuln.get('title', 'Unknown Vulnerability')}</div>
                            <div class="vuln-meta">
                                <span class="badge">CVE: {vuln.get('cve_id', 'N/A')}</span>
                                <span class="badge">CVSS: {vuln.get('cvss_score', 'N/A')}</span>
                                <span class="badge">{severity.upper()}</span>
                            </div>
                            <div style="font-size: 0.9em; color: #555; margin-top: 8px;">
                                <strong>Remediation:</strong> {vuln.get('remediation', 'N/A')}
                            </div>
                        </div>
"""
                    html += '</div>'

                html += '</div>'

            html += '</section>'

        html += f"""
        <footer>
            <p>Report ID: {scan_data.get('report_id', 'N/A')} | Generated: {datetime.utcnow().isoformat()}</p>
            <p>This report contains sensitive security information and should be handled according to your organization's security policies.</p>
        </footer>
    </div>
</body>
</html>"""

        return html

    @staticmethod
    def get_report(report_id: str, tenant_id: str) -> Tuple[Optional[Dict], bool]:
        """Retrieve report metadata and optionally file content"""
        try:
            from backend.core.repositories import ReportRepository

            report = ReportRepository.get_by_report_id(report_id) if hasattr(
                ReportRepository, 'get_by_report_id') else None

            if not report or report.tenant_id != tenant_id:
                logger.warning(f"Report not found or unauthorized: {report_id}")
                return None, False

            return report.to_dict(), True

        except Exception as e:
            logger.error(f"Error retrieving report: {e}")
            return None, False

    @staticmethod
    def list_reports(tenant_id: str, scan_id: Optional[int] = None,
                    limit: int = 50, offset: int = 0) -> Tuple[List[Dict], int, bool]:
        """List reports with pagination"""
        try:
            from backend.core.repositories import ReportRepository

            if scan_id:
                reports = ReportRepository.get_reports_by_scan(scan_id) if hasattr(
                    ReportRepository, 'get_reports_by_scan') else []
            else:
                # Get all reports for tenant
                reports = db.session.query(Report).filter(
                    Report.tenant_id == tenant_id,
                    Report.is_deleted == False
                ).order_by(Report.generated_at.desc()).all()

            total = len(reports)
            paginated = reports[offset:offset + limit]

            return [r.to_dict() for r in paginated], total, True

        except Exception as e:
            logger.error(f"Error listing reports: {e}")
            return [], 0, False

    @staticmethod
    def delete_report(report_id: str, tenant_id: str) -> Tuple[bool, bool]:
        """Soft-delete a report"""
        try:
            from backend.core.repositories import ReportRepository

            report = ReportRepository.get_by_report_id(report_id) if hasattr(
                ReportRepository, 'get_by_report_id') else None

            if not report or report.tenant_id != tenant_id:
                logger.warning(f"Report not found or unauthorized: {report_id}")
                return False, False

            if report.is_immutable:
                logger.warning(f"Cannot delete immutable report: {report_id}")
                return False, False

            report.soft_delete()
            logger.info(f"Report deleted: {report_id}")
            return True, True

        except Exception as e:
            logger.error(f"Error deleting report: {e}")
            return False, False
