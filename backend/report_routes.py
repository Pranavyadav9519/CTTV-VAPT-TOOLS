"""
REPORT GENERATION API ENDPOINTS
Connects reporting engine to Flask and integrates with frontend
"""

from flask import Blueprint, jsonify, request, send_file
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Blueprint for report endpoints
report_bp = Blueprint('reports', __name__, url_prefix='/api')


# ============================================================================
# REPORT GENERATION ENDPOINTS
# ============================================================================

@report_bp.route('/scan/<int:scan_id>/report', methods=['POST'])
def generate_report(scan_id):
    """
    Generate comprehensive report for a completed scan
    POST /api/scan/<scan_id>/report
    """
    try:
        from backend.database.db import db
        from backend.database.models import Scan, Report
        from backend.reporting_engine import ReportOrchestrator, OutputDistributor
        
        # Get scan from database
        scan = db.session.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan.status != 'completed':
            return jsonify({'error': 'Scan not completed yet'}), 400
        
        # Prepare scan data for reporting
        scan_data = {
            'scan_id': scan.id,
            'operator_name': scan.operator_name or 'Unknown',
            'network_range': scan.network_range,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'status': scan.status,
            'total_hosts_found': scan.total_hosts_found or 0,
            'cctv_devices_found': scan.cctv_devices_found or 0,
            'vulnerabilities_found': scan.vulnerabilities_found or 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'devices': _serialize_scan_devices(scan)
        }
        
        # Count severity distribution
        all_vulns = []
        for device in scan_data['devices']:
            all_vulns.extend(device.get('vulnerabilities', []))
        
        for vuln in all_vulns:
            severity = vuln.get('severity', '').lower()
            if severity == 'critical':
                scan_data['critical_count'] += 1
            elif severity == 'high':
                scan_data['high_count'] += 1
            elif severity == 'medium':
                scan_data['medium_count'] += 1
            elif severity == 'low':
                scan_data['low_count'] += 1
        
        # Execute 6-layer reporting pipeline
        orchestrator = ReportOrchestrator()
        report_result, success = orchestrator.generate_complete_report(scan_data)
        
        if not success:
            return jsonify({'error': 'Report generation failed'}), 500
        
        # Export to all formats
        distributor = OutputDistributor(output_dir='backend/reports')
        exports = distributor.export_all_formats(report_result, f"VAPT_Report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        # Save report to database
        report = Report(
            scan_id=scan.id,
            report_type='comprehensive',
            content=report_result,
            json_export=exports['json'].get('file'),
            html_export=exports['html'].get('file'),
            generated_at=datetime.utcnow()
        )
        db.session.add(report)
        db.session.commit()
        
        # Return report with export links
        return jsonify({
            'success': True,
            'message': 'Report generated successfully',
            'report_id': report.id,
            'scan_id': scan_id,
            'generated_at': report.generated_at.isoformat(),
            'formats': {
                'json': exports['json'].get('file'),
                'html': exports['html'].get('file')
            },
            'preview': {
                'executive': report_result.get('reports', {}).get('executive_summary', {}).get('sections', [])[:2],
                'risk_level': report_result.get('enriched_data', {}).get('risk_assessment', {}),
                'statistics': report_result.get('enriched_data', {}).get('statistics', {}),
                'recommendations': report_result.get('enriched_data', {}).get('recommendations', [])[:3]
            }
        }), 201
        
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        return jsonify({'error': str(e)}), 500


@report_bp.route('/scan/<int:scan_id>/report', methods=['GET'])
def get_report(scan_id):
    """
    Retrieve generated report for a scan
    GET /api/scan/<scan_id>/report
    """
    try:
        from backend.database.db import db
        from backend.database.models import Report
        
        report = db.session.query(Report).filter_by(scan_id=scan_id).first()
        if not report:
            return jsonify({'error': 'Report not found'}), 404
        
        return jsonify({
            'id': report.id,
            'scan_id': report.scan_id,
            'report_type': report.report_type,
            'generated_at': report.generated_at.isoformat(),
            'content': report.content,
            'exports': {
                'json': report.json_export,
                'html': report.html_export
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Report retrieval error: {e}")
        return jsonify({'error': str(e)}), 500


@report_bp.route('/scan/<int:scan_id>/report/export/<format>', methods=['GET'])
def export_report(scan_id, format):
    """
    Download report in specific format
    GET /api/scan/<scan_id>/report/export/{json|html}
    """
    try:
        from backend.database.db import db
        from backend.database.models import Report
        
        report = db.session.query(Report).filter_by(scan_id=scan_id).first()
        if not report:
            return jsonify({'error': 'Report not found'}), 404
        
        if format == 'json':
            file_path = report.json_export
            mimetype = 'application/json'
        elif format == 'html':
            file_path = report.html_export
            mimetype = 'text/html'
        else:
            return jsonify({'error': 'Invalid format'}), 400
        
        if not file_path:
            return jsonify({'error': f'{format.upper()} export not available'}), 404
        
        return send_file(file_path, mimetype=mimetype, as_attachment=True)
        
    except Exception as e:
        logger.error(f"Export error: {e}")
        return jsonify({'error': str(e)}), 500


@report_bp.route('/reports', methods=['GET'])
def list_reports():
    """
    List all generated reports
    GET /api/reports
    """
    try:
        from backend.database.db import db
        from backend.database.models import Report
        
        reports = db.session.query(Report).order_by(Report.generated_at.desc()).all()
        
        return jsonify({
            'total': len(reports),
            'reports': [
                {
                    'id': r.id,
                    'scan_id': r.scan_id,
                    'type': r.report_type,
                    'generated_at': r.generated_at.isoformat()
                }
                for r in reports
            ]
        }), 200
        
    except Exception as e:
        logger.error(f"Report listing error: {e}")
        return jsonify({'error': str(e)}), 500


@report_bp.route('/report/<int:report_id>', methods=['GET'])
def get_report_by_id(report_id):
    """
    Get report by ID
    GET /api/report/<report_id>
    """
    try:
        from backend.database.db import db
        from backend.database.models import Report
        
        report = db.session.query(Report).filter_by(id=report_id).first()
        if not report:
            return jsonify({'error': 'Report not found'}), 404
        
        return jsonify({
            'id': report.id,
            'scan_id': report.scan_id,
            'type': report.report_type,
            'generated_at': report.generated_at.isoformat(),
            'content': report.content
        }), 200
        
    except Exception as e:
        logger.error(f"Report retrieval error: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _serialize_scan_devices(scan):
    """Convert scan devices to serializable format for reporting"""
    devices = []
    
    for device in scan.devices:
        device_data = {
            'id': device.id,
            'ip_address': device.ip_address,
            'mac_address': device.mac_address,
            'manufacturer': device.manufacturer,
            'device_type': device.device_type,
            'is_cctv': device.is_cctv,
            'confidence_score': device.confidence_score,
            'ports': []
        }
        
        # Add ports
        for port in device.ports:
            device_data['ports'].append({
                'port_number': port.port_number,
                'protocol': port.protocol,
                'service_name': port.service_name,
                'banner': port.banner
            })
        
        # Add vulnerabilities
        device_data['vulnerabilities'] = []
        for vuln in device.vulnerabilities:
            device_data['vulnerabilities'].append({
                'id': vuln.id,
                'vuln_id': vuln.vuln_id,
                'cve_id': vuln.cve_id,
                'title': vuln.title,
                'severity': vuln.severity,
                'cvss_score': vuln.cvss_score,
                'remediation': vuln.remediation
            })
        
        devices.append(device_data)
    
    return devices
