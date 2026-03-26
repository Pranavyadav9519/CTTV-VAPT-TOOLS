from flask import Blueprint, request, jsonify, send_file, current_app
from flask_jwt_extended import jwt_required
from app.repositories.report_repo import ReportRepository
from app.services.storage import LocalStorage
from app.security.rbac import roles_required
import os
import uuid

reports_bp = Blueprint('reports', __name__)


@reports_bp.route('/<report_id>/download', methods=['GET'])
@jwt_required()
@roles_required('viewer', 'operator', 'admin')
def download(report_id: str):
    tenant_id = request.headers.get('X-Tenant-ID')
    request_id = request.headers.get('X-Request-ID') or str(uuid.uuid4())
    if not tenant_id:
        return jsonify({'success': False, 'data': None, 'error': {'code': 'tenant.missing', 'message': 'X-Tenant-ID header required'}, 'request_id': request_id}), 400

    report = ReportRepository.get_by_report_id(report_id, tenant_id)
    if not report:
        return jsonify({'success': False, 'data': None, 'error': {'code': 'report.not_found', 'message': 'Not found'}, 'request_id': request_id}), 404

    key = os.getenv('STORAGE_KEY')
    if not key:
        current_app.logger.error('STORAGE_KEY not configured')
        return jsonify({'success': False, 'data': None, 'error': {'code': 'storage.not_configured', 'message': 'Storage key not configured'}, 'request_id': request_id}), 500

    storage = LocalStorage(os.getenv('REPORTS_DIR', 'reports'), key.encode())
    data = storage.read_decrypted(report.file_path)
    tmp_path = f"{report.file_path}.tmp"
    with open(tmp_path, 'wb') as f:
        f.write(data)

    return send_file(tmp_path, as_attachment=True, download_name=os.path.basename(report.file_path))
