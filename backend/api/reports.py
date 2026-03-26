"""
Report API Endpoints
Handles report generation, retrieval, and management with database integration
"""

from flask import Blueprint, request, jsonify, send_file
from functools import wraps
import logging
from typing import Tuple
from pathlib import Path

from backend.core.errors import (
    APIException, ValidationError, AuthenticationError, AuthorizationError,
    NotFoundError, error_response, success_response
)
from backend.core.services import ReportService
from backend.core.repositories import ReportRepository, ScanRepository
from backend.core.utils import (
    require_auth, require_role, require_tenant_header, validate_json,
    log_action, Pagination, get_request_id
)

logger = logging.getLogger(__name__)

# Create blueprint
reports_bp = Blueprint('reports', __name__, url_prefix='/api/reports')


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_request_context() -> Tuple[str, str, int]:
    """Extract request context (tenant_id, user_ip, user_id)"""
    tenant_id = request.headers.get('X-Tenant-ID', 'default')
    user_ip = request.remote_addr
    user_id = getattr(request, 'user_id', None)
    return tenant_id, user_ip, user_id


# ============================================================================
# REPORT GENERATION ENDPOINT
# ============================================================================

@reports_bp.route('', methods=['POST'])
@require_auth
@require_tenant_header
@validate_json('scan_id', 'report_format')
@log_action('report_generated')
def generate_report():
    """
    Generate a new report for a scan
    
    Request JSON:
    {
        "scan_id": 1,
        "report_format": "json|html"  # Default: "json"
    }
    
    Response: 201 Created
    {
        "success": true,
        "data": {
            "report_id": "abc123def456",
            "scan_id": 1,
            "format": "json",
            "file_path": "/path/to/report.json",
            "file_size": 5242,
            "generated_at": "2026-03-26T10:30:00"
        }
    }
    """
    try:
        tenant_id, user_ip, user_id = get_request_context()
        data = request.get_json()

        scan_id = data.get('scan_id')
        report_format = data.get('report_format', 'json').lower()

        # Validate report format
        if report_format not in ['json', 'html', 'pdf']:
            return error_response(
                f"Invalid report format: {report_format}. Must be 'json', 'html', or 'pdf'",
                400,
                "validation_error"
            )

        # Verify scan exists and belongs to tenant
        scan = ScanRepository.get_by_id(scan_id)
        if not scan:
            return error_response("Scan not found", 404, "not_found")

        if scan.tenant_id != tenant_id:
            return error_response("Unauthorized: Scan belongs to different tenant", 403, "forbidden")

        # Check scan is completed
        from backend.core.models import ScanStatus
        if scan.status != ScanStatus.COMPLETED:
            return error_response("Cannot generate report for incomplete scan", 400, "invalid_state")

        # Generate report
        report_data, success = ReportService.generate_report(
            scan_id=scan_id,
            report_format=report_format,
            user_id=user_id,
            tenant_id=tenant_id
        )

        if not success:
            return error_response("Failed to generate report", 500, "generation_error")

        logger.info(f"Report generated for scan {scan_id}: {report_data.get('report_id')}")
        return success_response(report_data, 201, "Report generated successfully")

    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return error_response(str(e), 500, "internal_error")


# ============================================================================
# LIST REPORTS ENDPOINT
# ============================================================================

@reports_bp.route('', methods=['GET'])
@require_auth
@require_tenant_header
def list_reports():
    """
    List reports for the tenant with filtering and pagination
    
    Query Parameters:
    - scan_id: Filter by scan ID (optional)
    - limit: Number of results (default: 20, max: 100)
    - offset: Pagination offset (default: 0)
    
    Response: 200 OK
    {
        "success": true,
        "data": {
            "reports": [...],
            "total": 42,
            "limit": 20,
            "offset": 0
        }
    }
    """
    try:
        tenant_id, _, _ = get_request_context()

        # Get pagination params
        pagination = Pagination.get_params()
        scan_id = request.args.get('scan_id', type=int)

        # Fetch reports
        reports, total, success = ReportService.list_reports(
            tenant_id=tenant_id,
            scan_id=scan_id,
            limit=pagination['limit'],
            offset=pagination['offset']
        )

        if not success:
            return error_response("Failed to retrieve reports", 500, "retrieval_error")

        response_data = {
            'reports': reports,
            'total': total,
            'limit': pagination['limit'],
            'offset': pagination['offset']
        }

        return success_response(response_data)

    except Exception as e:
        logger.error(f"Error listing reports: {e}")
        return error_response(str(e), 500, "internal_error")


# ============================================================================
# GET REPORT DETAILS ENDPOINT
# ============================================================================

@reports_bp.route('/<report_id>', methods=['GET'])
@require_auth
@require_tenant_header
def get_report_details(report_id: str):
    """
    Get detailed information about a specific report
    
    Response: 200 OK
    {
        "success": true,
        "data": {
            "report_id": "abc123",
            "scan_id": 1,
            "format": "json",
            "file_path": "/path/to/report.json",
            "file_size": 5242,
            "checksum": "sha256hash...",
            "generated_by": "operator1",
            "is_immutable": true,
            "generated_at": "2026-03-26T10:30:00"
        }
    }
    """
    try:
        tenant_id, _, _ = get_request_context()

        # Get report
        report_data, success = ReportService.get_report(
            report_id=report_id,
            tenant_id=tenant_id
        )

        if not success or not report_data:
            return error_response("Report not found", 404, "not_found")

        return success_response(report_data)

    except Exception as e:
        logger.error(f"Error retrieving report: {e}")
        return error_response(str(e), 500, "internal_error")


# ============================================================================
# DOWNLOAD REPORT FILE ENDPOINT
# ============================================================================

@reports_bp.route('/<report_id>/download', methods=['GET'])
@require_auth
@require_tenant_header
def download_report(report_id: str):
    """
    Download the actual report file (JSON, HTML, or PDF)
    
    Response: 200 OK with file content
    """
    try:
        tenant_id, _, user_id = get_request_context()

        # Get report metadata
        report_data, success = ReportService.get_report(
            report_id=report_id,
            tenant_id=tenant_id
        )

        if not success or not report_data:
            return error_response("Report not found", 404, "not_found")

        file_path = report_data.get('file_path')
        if not file_path:
            return error_response("Report file not available", 400, "file_error")

        # Verify file exists
        path = Path(file_path)
        if not path.exists():
            logger.error(f"Report file missing: {file_path}")
            return error_response("Report file not found on disk", 500, "file_error")

        # Log download action
        from backend.core.repositories import AuditLogRepository
        AuditLogRepository.log_action(
            user_id=user_id,
            action="report_downloaded",
            resource_type="report",
            resource_id=report_id,
            tenant_id=tenant_id,
            details={"format": report_data.get('format')},
            ip_address=request.remote_addr,
            status="success"
        )

        logger.info(f"Report downloaded: {report_id}")

        # Send file
        return send_file(
            str(path),
            as_attachment=True,
            download_name=path.name,
            mimetype=_get_mimetype(report_data.get('format', 'json'))
        )

    except Exception as e:
        logger.error(f"Error downloading report: {e}")
        return error_response(str(e), 500, "internal_error")


# ============================================================================
# DELETE REPORT ENDPOINT
# ============================================================================

@reports_bp.route('/<report_id>', methods=['DELETE'])
@require_auth
@require_tenant_header
@require_role('admin', 'operator')
@log_action('report_deleted')
def delete_report(report_id: str):
    """
    Soft-delete a report (only admin/operator can delete, and not immutable reports)
    
    Response: 200 OK
    {
        "success": true,
        "data": {
            "report_id": "abc123",
            "status": "deleted"
        }
    }
    """
    try:
        tenant_id, _, user_id = get_request_context()

        # Delete report
        success, deleted = ReportService.delete_report(
            report_id=report_id,
            tenant_id=tenant_id
        )

        if not success:
            if not deleted:
                return error_response("Cannot delete immutable report", 403, "immutable_error")
            return error_response("Report not found", 404, "not_found")

        response_data = {
            'report_id': report_id,
            'status': 'deleted'
        }

        return success_response(response_data, message="Report deleted successfully")

    except Exception as e:
        logger.error(f"Error deleting report: {e}")
        return error_response(str(e), 500, "internal_error")


# ============================================================================
# REPORT COMPARISON ENDPOINT
# ============================================================================

@reports_bp.route('/compare', methods=['POST'])
@require_auth
@require_tenant_header
@validate_json('report_id_1', 'report_id_2')
def compare_reports():
    """
    Compare two reports to see what changed between scans
    
    Request JSON:
    {
        "report_id_1": "abc123",
        "report_id_2": "def456"
    }
    
    Response: 200 OK
    {
        "success": true,
        "data": {
            "new_vulnerabilities": [...],
            "resolved_vulnerabilities": [...],
            "changed_severity": [...],
            "summary": {...}
        }
    }
    """
    try:
        tenant_id, _, _ = get_request_context()
        data = request.get_json()

        report_id_1 = data.get('report_id_1')
        report_id_2 = data.get('report_id_2')

        # Get both reports
        report1, success1 = ReportService.get_report(report_id_1, tenant_id)
        report2, success2 = ReportService.get_report(report_id_2, tenant_id)

        if not (success1 and success2):
            return error_response("One or both reports not found", 404, "not_found")

        # Compare reports
        comparison = _compare_scan_reports(report1, report2)

        return success_response(comparison)

    except Exception as e:
        logger.error(f"Error comparing reports: {e}")
        return error_response(str(e), 500, "internal_error")


# ============================================================================
# REPORT STATISTICS ENDPOINT
# ============================================================================

@reports_bp.route('/stats', methods=['GET'])
@require_auth
@require_tenant_header
def get_report_stats():
    """
    Get statistics about reports in this tenant
    
    Response: 200 OK
    {
        "success": true,
        "data": {
            "total_reports": 42,
            "by_format": {"json": 20, "html": 15, "pdf": 7},
            "by_status": {"completed": 38, "failed": 4},
            "recent_reports": [...]
        }
    }
    """
    try:
        tenant_id, _, _ = get_request_context()

        from backend.core.models import Report
        from sqlalchemy import func

        # Total reports
        total = Report.query.filter(
            Report.tenant_id == tenant_id,
            Report.is_deleted == False
        ).count()

        # By format
        by_format = {}
        for format_type in ['json', 'html', 'pdf']:
            count = Report.query.filter(
                Report.tenant_id == tenant_id,
                Report.format == format_type,
                Report.is_deleted == False
            ).count()
            if count > 0:
                by_format[format_type] = count

        # Recent reports
        recent = Report.query.filter(
            Report.tenant_id == tenant_id,
            Report.is_deleted == False
        ).order_by(Report.generated_at.desc()).limit(5).all()

        stats = {
            'total_reports': total,
            'by_format': by_format,
            'recent_reports': [r.to_dict() for r in recent]
        }

        return success_response(stats)

    except Exception as e:
        logger.error(f"Error getting report stats: {e}")
        return error_response(str(e), 500, "internal_error")


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _get_mimetype(report_format: str) -> str:
    """Get MIME type for report format"""
    mime_types = {
        'json': 'application/json',
        'html': 'text/html',
        'pdf': 'application/pdf'
    }
    return mime_types.get(report_format, 'application/octet-stream')


def _compare_scan_reports(report1: dict, report2: dict) -> dict:
    """Compare two scan reports"""
    # Extract vulnerability lists
    devices1 = report1.get('devices', []) if isinstance(report1, dict) else []
    devices2 = report2.get('devices', []) if isinstance(report2, dict) else []

    vulns1 = set()
    vulns2 = set()

    for device in devices1:
        for vuln in device.get('vulnerabilities', []):
            vuln_key = (device.get('ip_address'), vuln.get('title'), vuln.get('cve_id'))
            vulns1.add(vuln_key)

    for device in devices2:
        for vuln in device.get('vulnerabilities', []):
            vuln_key = (device.get('ip_address'), vuln.get('title'), vuln.get('cve_id'))
            vulns2.add(vuln_key)

    new_vulns = vulns2 - vulns1
    resolved_vulns = vulns1 - vulns2

    return {
        'new_vulnerabilities_count': len(new_vulns),
        'resolved_vulnerabilities_count': len(resolved_vulns),
        'new_vulnerabilities': [list(v) for v in sorted(new_vulns)],
        'resolved_vulnerabilities': [list(v) for v in sorted(resolved_vulns)],
        'summary': {
            'comparison_created': datetime.utcnow().isoformat()
        }
    }


def register_reports_blueprint(app):
    """Register reports blueprint with Flask app"""
    app.register_blueprint(reports_bp)
    logger.info("Reports API blueprint registered")
