import hashlib
import json
import logging
import os
import uuid
from datetime import datetime

from celery import Task, shared_task

from backend.core.scan_engine import run_scan as engine_run_scan
from backend.enterprise.extensions import db
from backend.enterprise.models.device import Device
from backend.enterprise.models.port import Port
from backend.enterprise.models.report import Report
from backend.enterprise.models.scan import Scan, ScanStatus
from backend.enterprise.models.vulnerability import Vulnerability
from backend.enterprise.repositories.report_repo import ReportRepository
from backend.enterprise.storage.local_storage import LocalStorage
from backend.reporting.report_builder import CRRReportBuilder

logger = logging.getLogger(__name__)


class ScanTask(Task):
    autoretry_for = ()
    max_retries = 0


@shared_task(name='backend.enterprise.tasks.scan_worker.run_scan', bind=True, base=ScanTask)
def run_scan(self, scan_db_id: int, scan_id: str, timeout: int = 1800):
    """
    Enterprise Celery scan task.
    Delegates to the shared scan engine, persists results into enterprise
    DB models, encrypts and stores the report, and triggers post-scan analytics.
    """
    # ---- Mark scan as running -------------------------------------------
    with db.session.begin():
        scan = (
            db.session.query(Scan)
            .with_for_update()
            .filter(Scan.id == scan_db_id, Scan.is_deleted.is_(False))
            .first()
        )
        if not scan:
            return {'success': False, 'error': 'scan not found'}
        if scan.status not in (ScanStatus.QUEUED, ScanStatus.PENDING):
            return {'success': False, 'error': f'unexpected scan status: {scan.status}'}
        scan.status = ScanStatus.RUNNING
        db.session.add(scan)

    operator = scan.operator_name if scan else 'system'
    network_range = scan.network_range if scan else None
    tenant_id = scan.tenant_id if scan else 'default'

    try:
        # ---- Run the shared scan engine ---------------------------------
        def _progress(phase: str, progress: float, message: str) -> None:
            logger.info(f"[{scan_id}] [{phase}] {progress:.0f}% – {message}")

        result = engine_run_scan(
            scan_id=scan_id,
            network_range=network_range,
            progress_cb=_progress,
        )

        # ---- Persist devices + ports + vulnerabilities ------------------
        with db.session.begin():
            for crr_dev in result.devices:
                ip = crr_dev.ip_address
                device_row = Device(
                    tenant_id=tenant_id,
                    scan_id=scan_db_id,
                    ip_address=ip,
                    mac_address=crr_dev.mac_address,
                    hostname=crr_dev.hostname,
                    manufacturer=crr_dev.manufacturer,
                    model=crr_dev.model,
                    firmware_version=crr_dev.firmware_version,
                    device_type=crr_dev.device_type,
                    is_cctv=crr_dev.is_cctv,
                    confidence_score=crr_dev.confidence_score,
                )
                db.session.add(device_row)
                db.session.flush()

                for port_info in result.ports_data.get(ip, []):
                    port_row = Port(
                        device_id=device_row.id,
                        port_number=port_info.get('port_number'),
                        protocol=port_info.get('protocol', 'tcp'),
                        state=port_info.get('state', 'open'),
                        service_name=port_info.get('service_name'),
                        banner=port_info.get('banner'),
                    )
                    db.session.add(port_row)

                for vuln in result.vulnerabilities.get(ip, []):
                    vuln_row = Vulnerability(
                        device_id=device_row.id,
                        vuln_id=vuln.vuln_id,
                        title=vuln.title,
                        description=vuln.description,
                        severity=vuln.severity,
                        cvss_score=vuln.cvss_score,
                        cve_id=vuln.cve_id,
                        cwe_id=vuln.cwe_id,
                        affected_component=vuln.affected_component,
                        remediation=vuln.remediation,
                        proof_of_concept=vuln.proof_of_concept,
                        references=json.dumps(vuln.references),
                    )
                    db.session.add(vuln_row)

        # ---- Build canonical JSON report --------------------------------
        builder = CRRReportBuilder()
        report_content = builder.build_json(result, operator=operator)

        # ---- Encrypt and save report ------------------------------------
        key = os.getenv('ENCRYPTION_KEY') or os.getenv('STORAGE_KEY')
        if not key:
            raise RuntimeError('ENCRYPTION_KEY not configured')

        reports_dir = os.getenv('REPORTS_DIR', 'reports')
        key_bytes = key.encode() if isinstance(key, str) else key
        storage = LocalStorage(reports_dir, key_bytes)
        filename = f"report_{scan_id}_{uuid.uuid4().hex}.json.enc"
        path, size = storage.save_encrypted(filename, report_content)
        checksum = hashlib.sha256(report_content).hexdigest()

        report = Report(
            report_id=str(uuid.uuid4()),
            scan_id=scan_db_id,
            title=f"CRR Report – {scan_id}",
            format='json',
            file_path=path,
            file_size=size,
            generated_by=operator,
            checksum=checksum,
        )
        ReportRepository.add(report)

        # ---- Update scan statistics + mark completed --------------------
        with db.session.begin():
            s = db.session.query(Scan).filter(Scan.id == scan_db_id).first()
            s.status = ScanStatus.COMPLETED
            s.completed_at = datetime.utcnow()
            s.total_hosts_found = result.total_hosts_found
            s.cctv_devices_found = result.cctv_devices_found
            s.vulnerabilities_found = result.vulnerabilities_found
            s.critical_count = result.critical_count
            s.high_count = result.high_count
            s.medium_count = result.medium_count
            s.low_count = result.low_count
            db.session.add(s)

        # ---- Trigger post-scan analytics (best-effort) ------------------
        try:
            from backend.tasks.analytics_tasks import post_scan_analytics_task
            post_scan_analytics_task.apply_async(
                args=[tenant_id, scan_id],
                queue='analytics',
            )
        except Exception as analytics_exc:
            logger.warning(f"[{scan_id}] Analytics task failed to enqueue: {analytics_exc}")

        logger.info(f"[{scan_id}] Enterprise scan completed, report={report.report_id}")
        return {'success': True, 'report_id': report.report_id}

    except Exception as exc:
        logger.error(f"[{scan_id}] Enterprise scan failed: {exc}", exc_info=True)
        with db.session.begin():
            s = db.session.query(Scan).filter(Scan.id == scan_db_id).first()
            if s:
                s.status = ScanStatus.FAILED
                s.error_message = str(exc)
                s.completed_at = datetime.utcnow()
                db.session.add(s)
        raise
