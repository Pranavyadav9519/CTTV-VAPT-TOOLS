"""
Analytics Service
Handles risk score calculation, daily rollups, and KPI aggregation
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from sqlalchemy import func, and_, or_
from backend.core.database import db
from backend.core.models import Scan, Device, Vulnerability, Port, SeverityLevel, ScanStatus
from backend.core.analytics_models import (
    DeviceRiskScore, DailyAnalyticsRollup, TopDevicesAnalytics, VulnerabilityTrend
)
import logging

logger = logging.getLogger(__name__)


class RiskScoringEngine:
    """Calculates device risk scores based on vulnerabilities and exposure"""
    
    @staticmethod
    def calculate_device_risk(device_id: int, tenant_id: str) -> DeviceRiskScore:
        """Calculate or update risk score for a device"""
        try:
            # Get or create risk score record
            risk = db.session.query(DeviceRiskScore).filter(
                DeviceRiskScore.device_id == device_id
            ).first()
            
            if not risk:
                risk = DeviceRiskScore(device_id=device_id, tenant_id=tenant_id)
                db.session.add(risk)
            
            # Calculate overall score
            risk.calculate_overall_score()
            risk.last_updated_at = datetime.utcnow()
            
            db.session.commit()
            logger.info(f"Risk score calculated for device {device_id}: {risk.overall_risk_score}")
            return risk
            
        except Exception as e:
            logger.error(f"Error calculating risk for device {device_id}: {str(e)}")
            db.session.rollback()
            raise

    @staticmethod
    def recalculate_all_device_risks(tenant_id: str) -> int:
        """Recalculate risk scores for all devices"""
        try:
            devices = db.session.query(Device).filter(
                Device.tenant_id == tenant_id,
                Device.is_deleted == False
            ).all()
            
            count = 0
            for device in devices:
                RiskScoringEngine.calculate_device_risk(device.id, tenant_id)
                count += 1
            
            logger.info(f"Recalculated risks for {count} devices in tenant {tenant_id}")
            return count
            
        except Exception as e:
            logger.error(f"Error recalculating device risks: {str(e)}")
            raise

    @staticmethod
    def get_risk_statistics(tenant_id: str) -> Dict:
        """Get overall risk statistics for tenant"""
        try:
            stats = db.session.query(
                func.count(DeviceRiskScore.id).label('total_devices'),
                func.count(
                    func.case(
                        (DeviceRiskScore.risk_tier == 'CRITICAL', 1)
                    )
                ).label('critical_devices'),
                func.count(
                    func.case(
                        (DeviceRiskScore.risk_tier == 'HIGH', 1)
                    )
                ).label('high_devices'),
                func.avg(DeviceRiskScore.overall_risk_score).label('avg_risk_score'),
            ).filter(
                DeviceRiskScore.tenant_id == tenant_id
            ).first()
            
            return {
                'total_devices': stats[0] or 0,
                'critical_count': stats[1] or 0,
                'high_count': stats[2] or 0,
                'average_risk_score': float(stats[3] or 0.0),
            }
            
        except Exception as e:
            logger.error(f"Error getting risk statistics: {str(e)}")
            return {
                'total_devices': 0,
                'critical_count': 0,
                'high_count': 0,
                'average_risk_score': 0.0,
            }


class AnalyticsEngine:
    """Computes daily rollups and trend analytics"""
    
    @staticmethod
    def generate_daily_rollup(tenant_id: str, for_date: Optional[datetime] = None) -> DailyAnalyticsRollup:
        """Generate daily analytics rollup for a specific date"""
        try:
            if for_date is None:
                for_date = datetime.utcnow()
            
            date_start = for_date.replace(hour=0, minute=0, second=0, microsecond=0)
            date_end = date_start + timedelta(days=1)
            
            # Check if rollup exists
            rollup = db.session.query(DailyAnalyticsRollup).filter(
                DailyAnalyticsRollup.tenant_id == tenant_id,
                DailyAnalyticsRollup.rollup_date == date_start.date()
            ).first()
            
            if not rollup:
                rollup = DailyAnalyticsRollup(
                    tenant_id=tenant_id,
                    rollup_date=date_start.date()
                )
                db.session.add(rollup)
            
            # Calculate scan metrics
            scans = db.session.query(Scan).filter(
                Scan.tenant_id == tenant_id,
                Scan.created_at >= date_start,
                Scan.created_at < date_end,
                Scan.is_deleted == False
            ).all()
            
            rollup.total_scans = len(scans)
            rollup.completed_scans = sum(1 for s in scans if s.status == ScanStatus.COMPLETED)
            rollup.failed_scans = sum(1 for s in scans if s.status == ScanStatus.FAILED)
            
            # Average scan duration
            durations = []
            for scan in scans:
                if scan.started_at and scan.completed_at:
                    duration = (scan.completed_at - scan.started_at).total_seconds()
                    durations.append(int(duration))
            
            if durations:
                rollup.avg_scan_duration_seconds = int(sum(durations) / len(durations))
            
            # Device metrics
            devices_today = db.session.query(Device).filter(
                Device.tenant_id == tenant_id,
                Device.created_at >= date_start,
                Device.created_at < date_end,
                Device.is_deleted == False
            ).all()
            
            all_devices = db.session.query(Device).filter(
                Device.tenant_id == tenant_id,
                Device.is_deleted == False
            ).all()
            
            rollup.new_devices = len(devices_today)
            rollup.unique_devices_found = len(all_devices)
            rollup.cctv_devices_found = sum(1 for d in all_devices if d.is_cctv)
            
            # Vulnerability metrics
            all_vulns = db.session.query(Vulnerability).filter(
                Vulnerability.tenant_id == tenant_id,
                Vulnerability.is_deleted == False
            ).all()
            
            new_vulns = db.session.query(Vulnerability).filter(
                Vulnerability.tenant_id == tenant_id,
                Vulnerability.created_at >= date_start,
                Vulnerability.created_at < date_end,
                Vulnerability.is_deleted == False
            ).all()
            
            rollup.total_vulnerabilities = len(all_vulns)
            rollup.new_vulnerabilities = len(new_vulns)
            rollup.false_positives = sum(1 for v in all_vulns if v.false_positive)
            
            # Severity breakdown
            severity_counts = {}
            for vuln in all_vulns:
                if not vuln.false_positive:
                    sev = vuln.severity.value.lower() if vuln.severity else 'info'
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            rollup.critical_count = severity_counts.get('critical', 0)
            rollup.high_count = severity_counts.get('high', 0)
            rollup.medium_count = severity_counts.get('medium', 0)
            rollup.low_count = severity_counts.get('low', 0)
            rollup.info_count = severity_counts.get('info', 0)
            
            # Risk metrics
            risk_scores = db.session.query(DeviceRiskScore).filter(
                DeviceRiskScore.tenant_id == tenant_id
            ).all()
            
            if risk_scores:
                avg_risk = sum(r.overall_risk_score for r in risk_scores) / len(risk_scores)
                rollup.avg_device_risk_score = avg_risk
                rollup.high_risk_devices = sum(1 for r in risk_scores if r.risk_tier in ['HIGH', 'CRITICAL'])
                rollup.critical_risk_devices = sum(1 for r in risk_scores if r.risk_tier == 'CRITICAL')
            
            rollup.updated_at = datetime.utcnow()
            db.session.commit()
            
            logger.info(f"Daily rollup generated for {tenant_id} on {date_start.date()}")
            return rollup
            
        except Exception as e:
            logger.error(f"Error generating daily rollup: {str(e)}")
            db.session.rollback()
            raise

    @staticmethod
    def generate_vulnerability_trend(tenant_id: str, for_date: Optional[datetime] = None) -> VulnerabilityTrend:
        """Generate vulnerability trend for a specific date"""
        try:
            if for_date is None:
                for_date = datetime.utcnow()
            
            date_start = for_date.replace(hour=0, minute=0, second=0, microsecond=0)
            date_end = date_start + timedelta(days=1)
            
            # Check if trend exists
            trend = db.session.query(VulnerabilityTrend).filter(
                VulnerabilityTrend.tenant_id == tenant_id,
                VulnerabilityTrend.trend_date == date_start.date()
            ).first()
            
            if not trend:
                trend = VulnerabilityTrend(
                    tenant_id=tenant_id,
                    trend_date=date_start.date()
                )
                db.session.add(trend)
            
            # New findings today
            new_findings = db.session.query(Vulnerability).filter(
                Vulnerability.tenant_id == tenant_id,
                Vulnerability.created_at >= date_start,
                Vulnerability.created_at < date_end,
                Vulnerability.is_deleted == False,
                Vulnerability.false_positive == False
            ).all()
            
            trend.new_findings = len(new_findings)
            
            # By severity (new)
            for vuln in new_findings:
                sev = vuln.severity.value.lower() if vuln.severity else 'info'
                if sev == 'critical':
                    trend.critical_new += 1
                elif sev == 'high':
                    trend.high_new += 1
                elif sev == 'medium':
                    trend.medium_new += 1
                elif sev == 'low':
                    trend.low_new += 1
            
            # Still open findings
            open_findings = db.session.query(Vulnerability).filter(
                Vulnerability.tenant_id == tenant_id,
                Vulnerability.is_deleted == False,
                Vulnerability.false_positive == False
            ).all()
            
            trend.still_open = len(open_findings)
            
            db.session.commit()
            logger.info(f"Vulnerability trend generated for {tenant_id} on {date_start.date()}")
            return trend
            
        except Exception as e:
            logger.error(f"Error generating vulnerability trend: {str(e)}")
            db.session.rollback()
            raise

    @staticmethod
    def update_top_devices(tenant_id: str, limit: int = 20) -> int:
        """Update top devices cache for quick queries"""
        try:
            # Get top devices by risk score
            top_devices = db.session.query(Device).join(
                DeviceRiskScore, Device.id == DeviceRiskScore.device_id
            ).filter(
                Device.tenant_id == tenant_id,
                Device.is_deleted == False
            ).order_by(
                DeviceRiskScore.overall_risk_score.desc()
            ).limit(limit).all()
            
            count = 0
            for device in top_devices:
                # Get or create analytics record
                analytics = db.session.query(TopDevicesAnalytics).filter(
                    TopDevicesAnalytics.device_id == device.id
                ).first()
                
                if not analytics:
                    analytics = TopDevicesAnalytics(
                        tenant_id=tenant_id,
                        device_id=device.id
                    )
                    db.session.add(analytics)
                
                # Update cached fields
                analytics.ip_address = device.ip_address
                analytics.hostname = device.hostname or ''
                analytics.manufacturer = device.manufacturer or ''
                
                # Vulnerability counts
                vulns = db.session.query(Vulnerability).filter(
                    Vulnerability.device_id == device.id,
                    Vulnerability.is_deleted == False,
                    Vulnerability.false_positive == False
                ).all()
                
                analytics.total_vulnerabilities = len(vulns)
                analytics.critical_vulns = sum(1 for v in vulns if v.severity.value.lower() == 'critical')
                analytics.high_vulns = sum(1 for v in vulns if v.severity.value.lower() == 'high')
                
                # Risk metrics
                risk = device.risk_score if device.risk_score else DeviceRiskScore.query.filter_by(device_id=device.id).first()
                if risk:
                    analytics.risk_score = risk.overall_risk_score
                    analytics.risk_tier = risk.risk_tier
                
                # Last scan
                last_scan = db.session.query(Scan).filter(
                    Scan.id == device.scan_id
                ).first()
                if last_scan:
                    analytics.last_scan_date = last_scan.completed_at or last_scan.started_at
                
                analytics.updated_at = datetime.utcnow()
                count += 1
            
            db.session.commit()
            logger.info(f"Updated top {count} devices for tenant {tenant_id}")
            return count
            
        except Exception as e:
            logger.error(f"Error updating top devices: {str(e)}")
            db.session.rollback()
            raise


class AnalyticsQuery:
    """Query interface for analytics data"""
    
    @staticmethod
    def get_kpi_summary(tenant_id: str, days: int = 7) -> Dict:
        """Get KPI summary for last N days"""
        try:
            start_date = (datetime.utcnow() - timedelta(days=days)).date()
            
            rollups = db.session.query(DailyAnalyticsRollup).filter(
                DailyAnalyticsRollup.tenant_id == tenant_id,
                DailyAnalyticsRollup.rollup_date >= start_date
            ).all()
            
            total_scans = sum(r.total_scans for r in rollups)
            total_vulns = sum(r.total_vulnerabilities for r in rollups)
            critical_count = sum(r.critical_count for r in rollups)
            high_count = sum(r.high_count for r in rollups)
            
            risk_stats = RiskScoringEngine.get_risk_statistics(tenant_id)
            
            return {
                'time_period': {
                    'days': days,
                    'start_date': start_date.isoformat(),
                    'end_date': datetime.utcnow().date().isoformat(),
                },
                'kpi': {
                    'total_scans': total_scans,
                    'vulnerabilities_found': total_vulns,
                    'critical_vulnerabilities': critical_count,
                    'high_vulnerabilities': high_count,
                    'devices_scanned': risk_stats['total_devices'],
                    'critical_devices': risk_stats['critical_count'],
                    'high_risk_devices': risk_stats['high_count'],
                    'average_risk_score': round(risk_stats['average_risk_score'], 2),
                },
            }
            
        except Exception as e:
            logger.error(f"Error getting KPI summary: {str(e)}")
            return {}

    @staticmethod
    def get_top_devices(tenant_id: str, limit: int = 10) -> List[Dict]:
        """Get top devices by risk"""
        try:
            devices = db.session.query(TopDevicesAnalytics).filter(
                TopDevicesAnalytics.tenant_id == tenant_id
            ).order_by(
                TopDevicesAnalytics.risk_score.desc()
            ).limit(limit).all()
            
            return [d.to_dict() for d in devices]
            
        except Exception as e:
            logger.error(f"Error getting top devices: {str(e)}")
            return []

    @staticmethod
    def get_vulnerability_trends(tenant_id: str, days: int = 30) -> List[Dict]:
        """Get vulnerability trends for last N days"""
        try:
            start_date = (datetime.utcnow() - timedelta(days=days)).date()
            
            trends = db.session.query(VulnerabilityTrend).filter(
                VulnerabilityTrend.tenant_id == tenant_id,
                VulnerabilityTrend.trend_date >= start_date
            ).order_by(
                VulnerabilityTrend.trend_date.asc()
            ).all()
            
            return [t.to_dict() for t in trends]
            
        except Exception as e:
            logger.error(f"Error getting vulnerability trends: {str(e)}")
            return []
