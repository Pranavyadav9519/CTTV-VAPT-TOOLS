"""
Celery Tasks for Report Generation
For background processing of report generation and related tasks
"""

import logging
from datetime import datetime, timedelta
from pathlib import Path

from backend.enterprise.celery_app import celery_app
from backend.core.services import ReportService
from backend.core.repositories import ScanRepository, ReportRepository, AuditLogRepository
from backend.core.database import db

logger = logging.getLogger(__name__)


# ============================================================================
# REPORT GENERATION TASKS
# ============================================================================

@celery_app.task(
    name='tasks.generate_report_async',
    bind=True,
    max_retries=3,
    default_retry_delay=60
)
def generate_report_async(self, scan_id: int, report_format: str = 'json',
                         user_id: int = None, tenant_id: str = None):
    """
    Generate report asynchronously with retry logic
    
    Args:
        scan_id: ID of the scan to generate report for
        report_format: Format of the report (json, html, pdf)
        user_id: ID of user requesting the report
        tenant_id: Tenant ID
    
    Returns:
        Dictionary with report details or error info
    """
    try:
        logger.info(f"[TASK] Generating {report_format} report for scan {scan_id}")

        # Generate the report
        report_data, success = ReportService.generate_report(
            scan_id=scan_id,
            report_format=report_format,
            user_id=user_id,
            tenant_id=tenant_id
        )

        if not success:
            logger.error(f"Report generation failed for scan {scan_id}")
            # Retry logic
            try:
                raise self.retry(exc=Exception("Report generation failed"), countdown=60)
            except self.MaxRetriesExceededError:
                # Log final failure
                AuditLogRepository.log_action(
                    user_id=user_id,
                    action="report_generation_failed",
                    resource_type="report",
                    resource_id=str(scan_id),
                    tenant_id=tenant_id,
                    status="failure",
                    error_message="Max retries exceeded"
                )
                return {
                    'status': 'failed',
                    'scan_id': scan_id,
                    'error': 'Max retries exceeded'
                }

        logger.info(f"Report generated successfully: {report_data.get('report_id')}")
        return {
            'status': 'success',
            'scan_id': scan_id,
            'report_id': report_data.get('report_id'),
            'format': report_format
        }

    except Exception as e:
        logger.error(f"Error in report generation task: {e}")
        try:
            raise self.retry(exc=e, countdown=60)
        except self.MaxRetriesExceededError:
            return {
                'status': 'failed',
                'scan_id': scan_id,
                'error': str(e)
            }


@celery_app.task(
    name='tasks.generate_multiple_format_reports',
    bind=True,
    max_retries=3
)
def generate_multiple_format_reports(self, scan_id: int, formats: list = None,
                                     user_id: int = None, tenant_id: str = None):
    """
    Generate reports in multiple formats for a single scan
    
    Args:
        scan_id: ID of the scan
        formats: List of formats to generate (default: ['json', 'html'])
        user_id: User ID
        tenant_id: Tenant ID
    
    Returns:
        Dictionary with results for each format
    """
    try:
        formats = formats or ['json', 'html']
        logger.info(f"[TASK] Generating reports in {len(formats)} formats for scan {scan_id}")

        results = {}
        for fmt in formats:
            task_result = generate_report_async.delay(
                scan_id=scan_id,
                report_format=fmt,
                user_id=user_id,
                tenant_id=tenant_id
            )
            results[fmt] = {
                'task_id': task_result.id,
                'status': 'pending'
            }

        logger.info(f"Queued {len(formats)} report generation tasks for scan {scan_id}")
        return {
            'scan_id': scan_id,
            'formats': results
        }

    except Exception as e:
        logger.error(f"Error queuing multiple format reports: {e}")
        try:
            raise self.retry(exc=e, countdown=60)
        except self.MaxRetriesExceededError:
            return {
                'status': 'failed',
                'scan_id': scan_id,
                'error': str(e)
            }


# ============================================================================
# REPORT CLEANUP TASKS
# ============================================================================

@celery_app.task(
    name='tasks.cleanup_old_reports',
    bind=True
)
def cleanup_old_reports(self, days_old: int = 90):
    """
    Clean up old reports (soft-delete reports older than specified days)
    
    Args:
        days_old: Number of days to keep reports (default: 90)
    
    Returns:
        Dictionary with cleanup statistics
    """
    try:
        logger.info(f"[TASK] Cleaning up reports older than {days_old} days")

        from backend.core.models import Report
        cutoff_date = datetime.utcnow() - timedelta(days=days_old)

        # Find old reports
        old_reports = Report.query.filter(
            Report.generated_at < cutoff_date,
            Report.is_deleted == False,
            Report.is_immutable == False  # Don't delete immutable reports
        ).all()

        deleted_count = 0
        total_size_freed = 0

        for report in old_reports:
            try:
                total_size_freed += report.file_size or 0
                report.soft_delete()
                deleted_count += 1

                # Try to delete file
                if report.file_path:
                    try:
                        path = Path(report.file_path)
                        if path.exists():
                            path.unlink()
                    except Exception as e:
                        logger.warning(f"Failed to delete report file: {report.file_path}: {e}")

            except Exception as e:
                logger.error(f"Error deleting report {report.id}: {e}")

        db.session.commit()

        logger.info(f"Cleaned up {deleted_count} reports, freed {total_size_freed} bytes")
        return {
            'status': 'success',
            'reports_deleted': deleted_count,
            'bytes_freed': total_size_freed
        }

    except Exception as e:
        logger.error(f"Error in cleanup task: {e}")
        return {
            'status': 'failed',
            'error': str(e)
        }


@celery_app.task(
    name='tasks.cleanup_orphaned_report_files'
)
def cleanup_orphaned_report_files():
    """
    Clean up report files that don't have corresponding database records
    
    Returns:
        Dictionary with cleanup statistics
    """
    try:
        logger.info("[TASK] Cleaning up orphaned report files")

        report_dir = Path("backend/reports")
        if not report_dir.exists():
            return {'status': 'success', 'files_deleted': 0}

        from backend.core.models import Report
        db_file_paths = set()
        for report in Report.query.filter(Report.is_deleted == False).all():
            if report.file_path:
                db_file_paths.add(report.file_path)

        deleted_count = 0
        for file_path in report_dir.glob("VAPT_Report_*"):
            if str(file_path) not in db_file_paths:
                try:
                    file_path.unlink()
                    deleted_count += 1
                    logger.info(f"Deleted orphaned report file: {file_path}")
                except Exception as e:
                    logger.warning(f"Failed to delete orphaned file: {file_path}: {e}")

        logger.info(f"Deleted {deleted_count} orphaned report files")
        return {
            'status': 'success',
            'files_deleted': deleted_count
        }

    except Exception as e:
        logger.error(f"Error cleaning orphaned files: {e}")
        return {
            'status': 'failed',
            'error': str(e)
        }


# ============================================================================
# REPORT ARCHIVAL TASKS
# ============================================================================

@celery_app.task(
    name='tasks.archive_reports',
    bind=True
)
def archive_reports(self, days_old: int = 30, archive_path: str = None):
    """
    Archive old reports to a separate location for long-term storage
    
    Args:
        days_old: Age threshold for archival (default: 30 days)
        archive_path: Path to archive directory
    
    Returns:
        Dictionary with archive statistics
    """
    try:
        logger.info(f"[TASK] Archiving reports older than {days_old} days")

        from backend.core.models import Report
        import shutil

        cutoff_date = datetime.utcnow() - timedelta(days=days_old)
        archive_dir = Path(archive_path or "backend/reports_archive")
        archive_dir.mkdir(parents=True, exist_ok=True)

        old_reports = Report.query.filter(
            Report.generated_at < cutoff_date,
            Report.is_deleted == False
        ).all()

        archived_count = 0
        total_size_archived = 0

        for report in old_reports:
            try:
                if report.file_path and Path(report.file_path).exists():
                    source = Path(report.file_path)
                    dest = archive_dir / source.name

                    shutil.copy2(source, dest)
                    total_size_archived += report.file_size or 0
                    archived_count += 1

                    # Mark as archived in metadata
                    report.archived_at = datetime.utcnow()
                    db.session.commit()

            except Exception as e:
                logger.error(f"Error archiving report {report.id}: {e}")

        logger.info(f"Archived {archived_count} reports ({total_size_archived} bytes)")
        return {
            'status': 'success',
            'reports_archived': archived_count,
            'bytes_archived': total_size_archived
        }

    except Exception as e:
        logger.error(f"Error in archive task: {e}")
        return {
            'status': 'failed',
            'error': str(e)
        }


# ============================================================================
# REPORT VALIDATION TASKS
# ============================================================================

@celery_app.task(
    name='tasks.validate_report_checksums'
)
def validate_report_checksums():
    """
    Validate checksums of all report files to detect corruption
    
    Returns:
        Dictionary with validation statistics
    """
    try:
        logger.info("[TASK] Validating report file checksums")

        from backend.core.models import Report
        import hashlib

        reports = Report.query.filter(Report.is_deleted == False).all()
        validated = 0
        corrupted = []

        for report in reports:
            try:
                if not report.file_path or not Path(report.file_path).exists():
                    corrupted.append({
                        'report_id': report.report_id,
                        'issue': 'file_not_found'
                    })
                    continue

                # Calculate checksum
                with open(report.file_path, 'rb') as f:
                    actual_checksum = hashlib.sha256(f.read()).hexdigest()

                if actual_checksum != report.checksum:
                    corrupted.append({
                        'report_id': report.report_id,
                        'issue': 'checksum_mismatch',
                        'expected': report.checksum,
                        'actual': actual_checksum
                    })
                else:
                    validated += 1

            except Exception as e:
                logger.warning(f"Error validating report {report.report_id}: {e}")
                corrupted.append({
                    'report_id': report.report_id,
                    'issue': 'validation_error',
                    'error': str(e)
                })

        logger.info(f"Validated {validated} reports, found {len(corrupted)} issues")
        return {
            'status': 'success',
            'validated': validated,
            'corrupted_count': len(corrupted),
            'corrupted': corrupted[:10]  # Return first 10 for review
        }

    except Exception as e:
        logger.error(f"Error in checksum validation task: {e}")
        return {
            'status': 'failed',
            'error': str(e)
        }


# ============================================================================
# SCHEDULED TASKS (Use with Beat Scheduler)
# ============================================================================

@celery_app.task(
    name='tasks.scheduled_report_cleanup'
)
def scheduled_report_cleanup():
    """
    Scheduled task to automatically clean up old reports (runs daily)
    Configure in celery beat schedule
    """
    return cleanup_old_reports.delay(days_old=90)


@celery_app.task(
    name='tasks.scheduled_checksum_validation'
)
def scheduled_checksum_validation():
    """
    Scheduled task to validate report checksums (runs weekly)
    """
    return validate_report_checksums.delay()
