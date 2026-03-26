from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required
from pydantic import BaseModel, ValidationError, constr
from app.models.scan import Scan
from app.repositories.scan_repo import ScanRepository
from app.security.idempotency import idempotency_required
from app.security.rbac import roles_required
from app import celery_app as celery
import uuid
import os
import ipaddress

scans_bp = Blueprint('scans', __name__)


class StartScanModel(BaseModel):
    operator_name: constr(min_length=1, max_length=100)
    network_range: constr(min_length=1) | None = None


@scans_bp.route('/start', methods=['POST'])
@jwt_required()
@roles_required('operator', 'admin')
@idempotency_required
def start_scan():
    tenant_id = request.headers.get('X-Tenant-ID')
    if not tenant_id:
        return jsonify({'success': False, 'data': None, 'error': {'code': 'tenant.missing', 'message': 'X-Tenant-ID header required'}, 'request_id': request.headers.get('X-Request-ID')}), 400

    try:
        payload = StartScanModel(**(request.get_json() or {}))
    except ValidationError as e:
        return jsonify({'success': False, 'data': None, 'error': {'code': 'validation.failed', 'message': e.errors()}, 'request_id': request.headers.get('X-Request-ID')}), 400

    if payload.network_range:
        try:
            net = ipaddress.ip_network(payload.network_range, strict=False)
            if net.num_addresses > int(os.getenv('MAX_SCAN_HOSTS', '1024')):
                return jsonify({'success': False, 'data': None, 'error': {'code': 'scan.size_exceeded', 'message': 'Requested scan exceeds max host count'}, 'request_id': request.headers.get('X-Request-ID')}), 400
        except Exception:
            return jsonify({'success': False, 'data': None, 'error': {'code': 'network.invalid', 'message': 'Invalid network_range'}, 'request_id': request.headers.get('X-Request-ID')}), 400

    active = ScanRepository.count_active_scans(tenant_id)
    max_concurrent = int(os.getenv('MAX_CONCURRENT_SCANS', '3'))
    if active >= max_concurrent:
        return jsonify({'success': False, 'data': None, 'error': {'code': 'tenant.limit_exceeded', 'message': 'Tenant has too many active scans'}, 'request_id': request.headers.get('X-Request-ID')}), 429

    scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
    scan = Scan(
        tenant_id=tenant_id,
        scan_id=scan_id,
        operator_name=payload.operator_name,
        network_range=payload.network_range,
        status='queued',
    )
    try:
        scan = ScanRepository.add(scan)
        task = celery.send_task('app.tasks.scan_worker.run_scan', args=[scan.id, scan.scan_id, tenant_id], kwargs={}, queue=os.getenv('CELERY_QUEUE', 'default'))
        return jsonify({'success': True, 'data': {'scan_id': scan.scan_id, 'task_id': task.id}, 'error': None, 'request_id': request.headers.get('X-Request-ID')}), 202
    except Exception as e:
        current_app.logger.error(f"Failed to enqueue scan: {e}")
        return jsonify({'success': False, 'data': None, 'error': {'code': 'scan.enqueue_failed', 'message': str(e)}, 'request_id': request.headers.get('X-Request-ID')}), 500
