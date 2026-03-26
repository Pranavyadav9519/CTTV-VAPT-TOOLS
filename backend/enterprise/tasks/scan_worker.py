from celery import shared_task, Task
from app.extensions import db
from app.models.scan import Scan
from app.models.report import Report
from app.repositories.report_repo import ReportRepository
from app.services.storage import LocalStorage
import os
import hashlib
import uuid
import time
from datetime import datetime


class ScanTask(Task):
    autoretry_for = ()
    max_retries = 0


@shared_task(name='app.tasks.scan_worker.run_scan', bind=True, base=ScanTask)
def run_scan(self, scan_db_id: int, scan_id: str, tenant_id: str, timeout: int = 1800):
    start = time.time()
    with db.session.begin():
        scan = (
            db.session.query(Scan)
            .with_for_update()
            .filter(Scan.id == scan_db_id, Scan.tenant_id == tenant_id, Scan.is_deleted.is_(False))
            .first()
        )
        if not scan:
            return {'success': False, 'error': 'scan not found'}
        if scan.status not in ('queued', 'pending'):
            return {'success': False, 'error': f'unexpected scan status: {scan.status}'}
        scan.status = 'running'
        db.session.add(scan)

    try:
        # Enforce timeout
        # Simulate work in slices to allow timeout enforcement
        simulated_steps = 3
        content_bytes = b''
        for step in range(simulated_steps):
            if time.time() - start > timeout:
                raise TimeoutError('Scan execution timed out')
            # simulate scanning by sleeping small intervals
            time.sleep(0.5)
            content_bytes += f"step-{step+1} for {scan.scan_id}\n".encode('utf-8')

        # finalize report content
        report_content = (f"Report for {scan.scan_id}\n").encode('utf-8') + content_bytes

        # Ensure encryption key exists
        key = os.getenv('ENCRYPTION_KEY') or os.getenv('STORAGE_KEY')
        if not key:
            raise RuntimeError('ENCRYPTION_KEY not configured')

        storage = LocalStorage(os.getenv('REPORTS_DIR', 'reports'), key.encode())
        filename = f"report_{scan.scan_id}_{uuid.uuid4().hex}.json.enc"
        path, size = storage.save_encrypted(filename, report_content)
        checksum = hashlib.sha256(report_content).hexdigest()

        report = Report(
            tenant_id=tenant_id,
            report_id=str(uuid.uuid4()),
            scan_id=scan.id,
            title=f"Report {scan.scan_id}",
            format='json',
            file_path=path,
            file_size=size,
            generated_by='system',
            checksum=checksum,
        )
        ReportRepository.add(report)

        with db.session.begin():
            s = db.session.query(Scan).filter(Scan.id == scan_db_id, Scan.tenant_id == tenant_id).first()
            s.status = 'completed'
            s.finished_at = datetime.utcnow()
            db.session.add(s)

        return {'success': True, 'report_id': report.report_id}
    except Exception as exc:
        with db.session.begin():
            s = db.session.query(Scan).filter(Scan.id == scan_db_id, Scan.tenant_id == tenant_id).first()
            if s:
                s.status = 'failed'
                s.error_message = str(exc)
                s.finished_at = datetime.utcnow()
                db.session.add(s)
        raise
