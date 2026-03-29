"""
Analytics Celery Tasks
Background jobs for generating rollups and updating analytics
"""

from celery import shared_task
from datetime import datetime, timedelta
from backend.celery_app import celery_app
from backend.core.analytics_service import (
    RiskScoringEngine, AnalyticsEngine
)
from backend.core.database import db
from backend.core.models import Scan, ScanStatus
import logging

logger = logging.getLogger(__name__)


@shared_task(name='analytics.generate_daily_rollup')
def generate_daily_rollup_task(tenant_id: str, target_date: str = None):
    """
    Generate daily analytics rollup for a specific date
    
    Args:
        tenant_id: Tenant identifier
        target_date: ISO format date (optional, defaults to today)
    """
    try:
        if target_date:
            target_date = datetime.fromisoformat(target_date)
        else:
            target_date = datetime.utcnow()
        
        rollup = AnalyticsEngine.generate_daily_rollup(tenant_id, target_date)
        
        logger.info(f"✓ Daily rollup generated for {tenant_id} on {target_date.date()}")
        return {
            'status': 'success',
            'rollup_date': target_date.date().isoformat(),
            'tenant_id': tenant_id,
        }
        
    except Exception as e:
        logger.error(f"✗ Error generating daily rollup: {str(e)}")
        raise


@shared_task(name='analytics.generate_vulnerability_trend')
def generate_vulnerability_trend_task(tenant_id: str, target_date: str = None):
    """
    Generate vulnerability trends for a specific date
    
    Args:
        tenant_id: Tenant identifier
        target_date: ISO format date (optional, defaults to today)
    """
    try:
        if target_date:
            target_date = datetime.fromisoformat(target_date)
        else:
            target_date = datetime.utcnow()
        
        trend = AnalyticsEngine.generate_vulnerability_trend(tenant_id, target_date)
        
        logger.info(f"✓ Vulnerability trend generated for {tenant_id} on {target_date.date()}")
        return {
            'status': 'success',
            'trend_date': target_date.date().isoformat(),
            'tenant_id': tenant_id,
        }
        
    except Exception as e:
        logger.error(f"✗ Error generating vulnerability trend: {str(e)}")
        raise


@shared_task(name='analytics.update_device_risks')
def update_device_risks_task(tenant_id: str, device_id: int = None):
    """
    Update device risk scores (single or all devices)
    
    Args:
        tenant_id: Tenant identifier
        device_id: Specific device ID (optional, defaults to all)
    """
    try:
        if device_id:
            RiskScoringEngine.calculate_device_risk(device_id, tenant_id)
            logger.info(f"✓ Risk score updated for device {device_id}")
            action = f"device {device_id}"
        else:
            count = RiskScoringEngine.recalculate_all_device_risks(tenant_id)
            logger.info(f"✓ Risk scores updated for {count} devices")
            action = f"{count} devices"
        
        return {
            'status': 'success',
            'action': action,
            'tenant_id': tenant_id,
        }
        
    except Exception as e:
        logger.error(f"✗ Error updating device risks: {str(e)}")
        raise


@shared_task(name='analytics.update_top_devices')
def update_top_devices_task(tenant_id: str, limit: int = 20):
    """
    Update cached top devices list
    
    Args:
        tenant_id: Tenant identifier
        limit: Number of top devices to cache
    """
    try:
        count = AnalyticsEngine.update_top_devices(tenant_id, limit)
        
        logger.info(f"✓ Top {count} devices updated for {tenant_id}")
        return {
            'status': 'success',
            'devices_updated': count,
            'tenant_id': tenant_id,
        }
        
    except Exception as e:
        logger.error(f"✗ Error updating top devices: {str(e)}")
        raise


@shared_task(name='analytics.post_scan_analytics')
def post_scan_analytics_task(tenant_id: str, scan_id: str):
    """
    Run analytics generation after scan completion
    This is called automatically when a scan finishes
    
    Args:
        tenant_id: Tenant identifier
        scan_id: Scan identifier
    """
    try:
        logger.info(f"Running post-scan analytics for scan {scan_id}")
        
        # Update risk scores
        update_device_risks_task.apply_async(
            args=[tenant_id],
            queue='analytics'
        )
        
        # Generate daily rollup
        generate_daily_rollup_task.apply_async(
            args=[tenant_id, None],
            queue='analytics'
        )
        
        # Generate vulnerability trend
        generate_vulnerability_trend_task.apply_async(
            args=[tenant_id, None],
            queue='analytics'
        )
        
        # Update top devices
        update_top_devices_task.apply_async(
            args=[tenant_id, 20],
            queue='analytics'
        )
        
        logger.info(f"✓ Analytics tasks queued for scan {scan_id}")
        return {
            'status': 'queued',
            'scan_id': scan_id,
            'tenant_id': tenant_id,
        }
        
    except Exception as e:
        logger.error(f"✗ Error queuing analytics tasks: {str(e)}")
        raise


@shared_task(name='analytics.daily_maintenance')
def daily_maintenance_task():
    """
    Daily maintenance task - run all rollups, trends, and top devices updates
    Should be scheduled to run once daily via beat schedule
    """
    try:
        from backend.core.models import User
        
        logger.info("Starting daily analytics maintenance")
        
        # Get all unique tenants
        tenants = db.session.query(User.tenant_id).distinct().all()
        
        for tenant_row in tenants:
            tenant_id = tenant_row[0]
            
            try:
                # Generate today's rollup
                generate_daily_rollup_task.apply_async(
                    args=[tenant_id, None],
                    queue='analytics'
                )
                
                # Generate today's trends
                generate_vulnerability_trend_task.apply_async(
                    args=[tenant_id, None],
                    queue='analytics'
                )
                
                # Recalculate all risks
                update_device_risks_task.apply_async(
                    args=[tenant_id, None],
                    queue='analytics'
                )
                
                # Update top devices
                update_top_devices_task.apply_async(
                    args=[tenant_id, 20],
                    queue='analytics'
                )
                
                logger.info(f"✓ Daily analytics queued for tenant {tenant_id}")
                
            except Exception as e:
                logger.error(f"✗ Error processing tenant {tenant_id}: {str(e)}")
                continue
        
        logger.info("✓ Daily maintenance completed")
        return {
            'status': 'success',
            'action': 'daily_maintenance',
            'tenants_processed': len(tenants),
        }
        
    except Exception as e:
        logger.error(f"✗ Error in daily maintenance: {str(e)}")
        raise


# Beat schedule configuration (add to celery_app config)
CELERY_BEAT_SCHEDULE = {
    'daily-analytics-maintenance': {
        'task': 'analytics.daily_maintenance',
        'schedule': timedelta(hours=24),
        'options': {'queue': 'analytics'}
    },
}
