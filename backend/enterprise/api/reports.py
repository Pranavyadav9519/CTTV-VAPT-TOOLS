import io
import os
import uuid

from flask import Blueprint, request, jsonify, send_file, current_app
from flask_jwt_extended import jwt_required

from backend.enterprise.repositories.report_repo import ReportRepository
from backend.enterprise.storage.local_storage import LocalStorage
from backend.enterprise.security.rbac import roles_required

reports_bp = Blueprint('reports', __name__)


@reports_bp.route('/<report_id>/download', methods=['GET'])
@jwt_required()
@roles_required('viewer', 'operator', 'admin')
def download(report_id: str):
    request_id = request.headers.get('X-Request-ID') or str(uuid.uuid4())

    report = ReportRepository.get_by_report_id(report_id)
    if not report:
        return jsonify({'success': False, 'data': None, 'error': {'code': 'report.not_found', 'message': 'Not found'}, 'request_id': request_id}), 404

    key = current_app.config.get('ENCRYPTION_KEY') or os.getenv('STORAGE_KEY')
    if not key:
        current_app.logger.error('ENCRYPTION_KEY not configured')
        return jsonify({'success': False, 'data': None, 'error': {'code': 'storage.not_configured', 'message': 'Storage key not configured'}, 'request_id': request_id}), 500

    reports_dir = str(current_app.config.get('REPORTS_DIR', 'reports'))
    try:
        storage = LocalStorage(reports_dir, key.encode() if isinstance(key, str) else key)
        data = storage.read_decrypted(report.file_path)
    except Exception as e:
        current_app.logger.error(f"Failed to decrypt report: {e}")
        return jsonify({'success': False, 'data': None, 'error': {'code': 'report.decrypt_failed', 'message': 'Failed to read report'}, 'request_id': request_id}), 500

    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=os.path.basename(report.file_path).removesuffix('.enc'),
        mimetype='application/octet-stream',
    )
