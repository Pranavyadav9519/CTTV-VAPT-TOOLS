from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt
from pydantic import BaseModel, ValidationError, field_validator
from typing import Optional
from backend.enterprise.models.scan import Scan
from backend.enterprise.repositories.scan_repo import ScanRepository
from backend.enterprise.security.idempotency import idempotency_required
from backend.enterprise.security.rbac import roles_required
from backend.enterprise.extensions import celery_app as celery
import uuid
import os
import ipaddress

scans_bp = Blueprint('scans', __name__)

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _is_private(net: ipaddress.IPv4Network) -> bool:
    return any(net.subnet_of(priv) for priv in _PRIVATE_NETWORKS)


class StartScanModel(BaseModel):
    operator_name: str
    network_range: Optional[str] = None
    authorization_confirmed: bool = False

    @field_validator('operator_name')
    @classmethod
    def operator_name_nonempty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError('operator_name must not be empty')
        if len(v) > 100:
            raise ValueError('operator_name must be 100 characters or less')
        return v


@scans_bp.route('/start', methods=['POST'])
@jwt_required()
@roles_required('operator', 'admin')
@idempotency_required
def start_scan():
    request_id = request.headers.get('X-Request-ID') or str(uuid.uuid4())

    try:
        payload = StartScanModel(**(request.get_json() or {}))
    except ValidationError as e:
        return jsonify({'success': False, 'data': None, 'error': {'code': 'validation.failed', 'message': e.errors()}, 'request_id': request_id}), 400

    if not payload.authorization_confirmed:
        return jsonify({'success': False, 'data': None, 'error': {'code': 'scan.authorization_required', 'message': 'You must confirm authorization to scan (authorization_confirmed: true)'}, 'request_id': request_id}), 400

    if payload.network_range:
        try:
            net = ipaddress.ip_network(payload.network_range, strict=False)
        except Exception:
            return jsonify({'success': False, 'data': None, 'error': {'code': 'network.invalid', 'message': 'Invalid network_range'}, 'request_id': request_id}), 400

        allow_public = os.getenv('ALLOW_PUBLIC_SCANS', 'false').lower() == 'true'
        claims = get_jwt()
        roles = set(claims.get('roles', []) or [])
        if not _is_private(net) and not (allow_public and 'admin' in roles):
            return jsonify({'success': False, 'data': None, 'error': {'code': 'scan.public_range_denied', 'message': 'Public IP ranges are not allowed. Set ALLOW_PUBLIC_SCANS=true and use an admin account to override.'}, 'request_id': request_id}), 403

        max_hosts = int(os.getenv('MAX_SCAN_HOSTS', '1024'))
        if net.num_addresses > max_hosts:
            return jsonify({'success': False, 'data': None, 'error': {'code': 'scan.size_exceeded', 'message': f'Requested scan exceeds max host count ({max_hosts})'}, 'request_id': request_id}), 400

    active = ScanRepository.count_active_scans()
    max_concurrent = int(os.getenv('MAX_CONCURRENT_SCANS', '3'))
    if active >= max_concurrent:
        return jsonify({'success': False, 'data': None, 'error': {'code': 'scan.limit_exceeded', 'message': 'Too many active scans'}, 'request_id': request_id}), 429

    scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
    scan = Scan(
        scan_id=scan_id,
        operator_name=payload.operator_name,
        network_range=payload.network_range,
        status='queued',
    )
    try:
        scan = ScanRepository.add(scan)
        task = celery.send_task(
            'backend.enterprise.tasks.scan_worker.run_scan',
            args=[scan.id, scan.scan_id],
            kwargs={},
            queue=os.getenv('CELERY_QUEUE', 'default'),
        )
        return jsonify({'success': True, 'data': {'scan_id': scan.scan_id, 'task_id': task.id}, 'error': None, 'request_id': request_id}), 202
    except Exception as e:
        current_app.logger.error(f"Failed to enqueue scan: {e}")
        return jsonify({'success': False, 'data': None, 'error': {'code': 'scan.enqueue_failed', 'message': str(e)}, 'request_id': request_id}), 500
