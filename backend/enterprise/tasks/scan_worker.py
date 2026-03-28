from celery import shared_task, Task
from backend.enterprise.extensions import db
from backend.enterprise.models.scan import Scan
from backend.enterprise.models.report import Report
from backend.enterprise.repositories.report_repo import ReportRepository
from backend.enterprise.storage.local_storage import LocalStorage
import os
import hashlib
import uuid
import time
from datetime import datetime


class ScanTask(Task):
    autoretry_for = ()
    max_retries = 0


@shared_task(name='backend.enterprise.tasks.scan_worker.run_scan', bind=True, base=ScanTask)
def run_scan(self, scan_db_id: int, scan_id: str, timeout: int = 1800):
    start = time.time()
    with db.session.begin():
        scan = (
            db.session.query(Scan)
            .with_for_update()
            .filter(Scan.id == scan_db_id, Scan.is_deleted.is_(False))
            .first()
        )
        if not scan:
            return {'success': False, 'error': 'scan not found'}
        if scan.status not in ('queued', 'pending'):
            return {'success': False, 'error': f'unexpected scan status: {scan.status}'}
        scan.status = 'running'
        db.session.add(scan)

    try:
        simulated_steps = 3
        content_bytes = b''
        for step in range(simulated_steps):
            if time.time() - start > timeout:
                raise TimeoutError('Scan execution timed out')
            time.sleep(0.5)
            content_bytes += f"step-{step+1} for {scan_id}\n".encode('utf-8')

        report_content = f"Report for {scan_id}\n".encode('utf-8') + content_bytes

        key = os.getenv('ENCRYPTION_KEY') or os.getenv('STORAGE_KEY')
        if not key:
            raise RuntimeError('ENCRYPTION_KEY not configured')

        storage = LocalStorage(os.getenv('REPORTS_DIR', 'reports'), key.encode() if isinstance(key, str) else key)
        filename = f"report_{scan_id}_{uuid.uuid4().hex}.json.enc"
        path, size = storage.save_encrypted(filename, report_content)
        checksum = hashlib.sha256(report_content).hexdigest()

        report = Report(
            report_id=str(uuid.uuid4()),
            scan_id=scan_db_id,
            title=f"Report {scan_id}",
            format='json',
            file_path=path,
            file_size=size,
            generated_by='system',
            checksum=checksum,
        )
        ReportRepository.add(report)

        with db.session.begin():
            s = db.session.query(Scan).filter(Scan.id == scan_db_id).first()
            s.status = 'completed'
            s.completed_at = datetime.utcnow()
            db.session.add(s)

        return {'success': True, 'report_id': report.report_id}
    except Exception as exc:
        with db.session.begin():
            s = db.session.query(Scan).filter(Scan.id == scan_db_id).first()
            if s:
                s.status = 'failed'
                s.error_message = str(exc)
                s.completed_at = datetime.utcnow()
                db.session.add(s)
        raise
