"""
Analytics Models and Rollups for VAPT
Tracks trends, device risk scores, and KPI aggregations
"""

from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, List, Dict
from backend.core.database import db
import json


class TrendType(Enum):
    """Analytics trend types"""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


# ============================================================================
# DEVICE RISK SCORE MODEL
# ============================================================================

class DeviceRiskScore(db.Model):
    """Calculated risk score for each device"""
    __tablename__ = "device_risk_scores"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=False, index=True)
    tenant_id = db.Column(db.String(36), nullable=False, index=True)
    
    # Risk components (0-100 scale)
    vulnerability_score = db.Column(db.Float, default=0.0)  # Based on severity counts
    exploitability_score = db.Column(db.Float, default=0.0)  # Based on attack complexity
    exposure_score = db.Column(db.Float, default=0.0)  # Internet facing, open ports
    
    # Final composite score (0-100, can exceed 100 before normalization)
    overall_risk_score = db.Column(db.Float, default=0.0)
    
    # Risk tier
    risk_tier = db.Column(db.String(10))  # CRITICAL, HIGH, MEDIUM, LOW
    
    # Metadata
    calculated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    device = db.relationship("Device", backref="risk_score")

    def calculate_vulnerability_score(self) -> float:
        """Calculate score from vulnerability counts"""
        # Get vulnerability counts from device
        vulns = db.session.query(
            db.func.count(db.func.IF(db.func.lower(Vulnerability.severity) == 'critical', 1, None)).label('critical'),
            db.func.count(db.func.IF(db.func.lower(Vulnerability.severity) == 'high', 1, None)).label('high'),
            db.func.count(db.func.IF(db.func.lower(Vulnerability.severity) == 'medium', 1, None)).label('medium'),
            db.func.count(db.func.IF(db.func.lower(Vulnerability.severity) == 'low', 1, None)).label('low'),
        ).filter(
            Vulnerability.device_id == self.device_id,
            Vulnerability.false_positive == False
        ).first()
        
        if not vulns:
            return 0.0
        
        critical = vulns[0] or 0
        high = vulns[1] or 0
        medium = vulns[2] or 0
        low = vulns[3] or 0
        
        # Weighted scoring: Critical (40%), High (25%), Medium (15%), Low (10%), Info (5%)
        score = (critical * 40) + (high * 25) + (medium * 15) + (low * 10)
        
        # Cap at 100 (can be exceeded by multiple critical vulns)
        return min(score, 100.0)

    def calculate_exploitability_score(self) -> float:
        """Calculate score based on exploitability factors"""
        score = 0.0
        
        from backend.core.models import Vulnerability
        
        # Check for known CVEs (exploitability indicator)
        with_cves = db.session.query(Vulnerability).filter(
            Vulnerability.device_id == self.device_id,
            Vulnerability.cve_id != None,
            Vulnerability.false_positive == False
        ).count()
        
        if with_cves > 0:
            score += 30  # Known exploits available
        
        # Check for default credentials
        default_cred_vulns = db.session.query(Vulnerability).filter(
            Vulnerability.device_id == self.device_id,
            Vulnerability.title.contains("default", case=False),
            Vulnerability.false_positive == False
        ).count()
        
        if default_cred_vulns > 0:
            score += 40  # Default credentials easily exploitable
        
        # Check for weak authentication
        weak_auth_vulns = db.session.query(Vulnerability).filter(
            Vulnerability.device_id == self.device_id,
            Vulnerability.title.contains(("weak auth", "no auth", "anonymous"), case=False),
            Vulnerability.false_positive == False
        ).count()
        
        if weak_auth_vulns > 0:
            score += 25
        
        return min(score, 100.0)

    def calculate_exposure_score(self) -> float:
        """Calculate score based on exposure (internet-facing, open ports, etc.)"""
        from backend.core.models import Port
        
        score = 0.0
        device = db.session.query("Device").get(self.device_id)
        
        if not device:
            return 0.0
        
        # Count open ports (more ports = higher exposure)
        open_ports = db.session.query(Port).filter(
            Port.device_id == self.device_id,
            Port.state == "open"
        ).count()
        
        if open_ports >= 10:
            score += 40
        elif open_ports >= 5:
            score += 25
        elif open_ports >= 1:
            score += 15
        
        # Check for known risky services
        dangerous_services = ["telnet", "ftp", "http", "rtsp", "onvif"]
        risky_ports = db.session.query(Port).filter(
            Port.device_id == self.device_id,
            Port.service_name.in_(dangerous_services)
        ).count()
        
        if risky_ports > 0:
            score += 30
        
        # CCTV devices with vulnerabilities = higher exposure (mass target)
        if device.is_cctv:
            score += 20
        
        return min(score, 100.0)

    def calculate_overall_score(self) -> float:
        """Calculate composite risk score"""
        # Recalculate components
        self.vulnerability_score = self.calculate_vulnerability_score()
        self.exploitability_score = self.calculate_exploitability_score()
        self.exposure_score = self.calculate_exposure_score()
        
        # Weighted composite (Vulnerability 40%, Exploitability 35%, Exposure 25%)
        composite = (
            (self.vulnerability_score * 0.40) +
            (self.exploitability_score * 0.35) +
            (self.exposure_score * 0.25)
        )
        
        self.overall_risk_score = min(composite, 100.0)
        
        # Set risk tier
        if self.overall_risk_score >= 80:
            self.risk_tier = "CRITICAL"
        elif self.overall_risk_score >= 60:
            self.risk_tier = "HIGH"
        elif self.overall_risk_score >= 40:
            self.risk_tier = "MEDIUM"
        else:
            self.risk_tier = "LOW"
        
        return self.overall_risk_score

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'device_id': self.device_id,
            'vulnerability_score': round(self.vulnerability_score, 2),
            'exploitability_score': round(self.exploitability_score, 2),
            'exposure_score': round(self.exposure_score, 2),
            'overall_risk_score': round(self.overall_risk_score, 2),
            'risk_tier': self.risk_tier,
            'calculated_at': self.calculated_at.isoformat(),
        }


# ============================================================================
# DAILY ANALYTICS ROLLUP MODEL
# ============================================================================

class DailyAnalyticsRollup(db.Model):
    """Daily aggregated analytics for KPI dashboard"""
    __tablename__ = "daily_analytics_rollups"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(36), nullable=False, index=True)
    rollup_date = db.Column(db.Date, nullable=False, index=True)
    
    # Scan metrics
    total_scans = db.Column(db.Integer, default=0)
    completed_scans = db.Column(db.Integer, default=0)
    failed_scans = db.Column(db.Integer, default=0)
    avg_scan_duration_seconds = db.Column(db.Integer, default=0)
    
    # Device metrics
    unique_devices_found = db.Column(db.Integer, default=0)
    new_devices = db.Column(db.Integer, default=0)
    cctv_devices_found = db.Column(db.Integer, default=0)
    
    # Vulnerability metrics
    total_vulnerabilities = db.Column(db.Integer, default=0)
    new_vulnerabilities = db.Column(db.Integer, default=0)
    resolved_vulnerabilities = db.Column(db.Integer, default=0)
    false_positives = db.Column(db.Integer, default=0)
    
    # Severity breakdown
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    info_count = db.Column(db.Integer, default=0)
    
    # Risk metrics
    avg_device_risk_score = db.Column(db.Float, default=0.0)
    high_risk_devices = db.Column(db.Integer, default=0)
    critical_risk_devices = db.Column(db.Integer, default=0)
    
    # Status
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'rollup_date': self.rollup_date.isoformat(),
            'scans': {
                'total': self.total_scans,
                'completed': self.completed_scans,
                'failed': self.failed_scans,
                'avg_duration_seconds': self.avg_scan_duration_seconds,
            },
            'devices': {
                'unique_found': self.unique_devices_found,
                'new': self.new_devices,
                'cctv': self.cctv_devices_found,
            },
            'vulnerabilities': {
                'total': self.total_vulnerabilities,
                'new': self.new_vulnerabilities,
                'resolved': self.resolved_vulnerabilities,
                'false_positives': self.false_positives,
                'severity': {
                    'critical': self.critical_count,
                    'high': self.high_count,
                    'medium': self.medium_count,
                    'low': self.low_count,
                    'info': self.info_count,
                }
            },
            'risk': {
                'avg_device_score': round(self.avg_device_risk_score, 2),
                'high_risk_devices': self.high_risk_devices,
                'critical_risk_devices': self.critical_risk_devices,
            },
        }


# ============================================================================
# TOP DEVICES ANALYTICS
# ============================================================================

class TopDevicesAnalytics(db.Model):
    """Top devices by risk/vulnerability count for quick queries"""
    __tablename__ = "top_devices_analytics"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(36), nullable=False, index=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=False, index=True)
    
    # Cached metrics (denormalized for speed)
    ip_address = db.Column(db.String(45), nullable=False)
    hostname = db.Column(db.String(255))
    manufacturer = db.Column(db.String(100))
    
    # Vulnerability counts
    total_vulnerabilities = db.Column(db.Integer, default=0)
    critical_vulns = db.Column(db.Integer, default=0)
    high_vulns = db.Column(db.Integer, default=0)
    
    # Risk metrics
    risk_score = db.Column(db.Float, default=0.0)
    risk_tier = db.Column(db.String(10))
    
    # Last activity
    last_scan_date = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    device = db.relationship("Device", backref="analytics_top")

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'device_id': self.device_id,
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'manufacturer': self.manufacturer,
            'vulnerabilities': {
                'total': self.total_vulnerabilities,
                'critical': self.critical_vulns,
                'high': self.high_vulns,
            },
            'risk': {
                'score': round(self.risk_score, 2),
                'tier': self.risk_tier,
            },
            'last_scanned': self.last_scan_date.isoformat() if self.last_scan_date else None,
        }


# ============================================================================
# VULNERABILITY TREND MODEL
# ============================================================================

class VulnerabilityTrend(db.Model):
    """Tracks vulnerability trends over time"""
    __tablename__ = "vulnerability_trends"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(36), nullable=False, index=True)
    trend_date = db.Column(db.Date, nullable=False, index=True)
    
    # Trends
    new_findings = db.Column(db.Integer, default=0)
    resolved_findings = db.Column(db.Integer, default=0)
    still_open = db.Column(db.Integer, default=0)  # Cumulative open
    
    # By severity
    critical_new = db.Column(db.Integer, default=0)
    high_new = db.Column(db.Integer, default=0)
    medium_new = db.Column(db.Integer, default=0)
    low_new = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'date': self.trend_date.isoformat(),
            'findings': {
                'new': self.new_findings,
                'resolved': self.resolved_findings,
                'still_open': self.still_open,
            },
            'by_severity': {
                'critical': self.critical_new,
                'high': self.high_new,
                'medium': self.medium_new,
                'low': self.low_new,
            },
        }


# ============================================================================
# IMPORTS (at end to avoid circular dependencies)
# ============================================================================
from backend.core.models import Vulnerability, Device
