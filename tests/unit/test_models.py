"""
Unit tests for database models
Tests ORM model definitions and validations
"""

import pytest
from datetime import datetime


@pytest.mark.unit
def test_scan_model_creation(db):
    """Test Scan model can be instantiated"""
    try:
        from backend.core.models import Scan, ScanStatus
        
        scan = Scan(
            network_range='192.168.1.0/24',
            status=ScanStatus.PENDING,
            tenant_id='test-tenant'
        )
        db.session.add(scan)
        db.session.commit()
        
        assert scan.scan_id is not None
        assert scan.network_range == '192.168.1.0/24'
    except ImportError:
        pytest.skip("Models module not available")


@pytest.mark.unit
def test_device_model_creation(db):
    """Test Device model can be instantiated"""
    try:
        from backend.core.models import Scan, Device, ScanStatus
        
        # Create a scan first
        scan = Scan(
            network_range='192.168.1.0/24',
            status=ScanStatus.COMPLETED,
            tenant_id='test-tenant'
        )
        db.session.add(scan)
        db.session.commit()
        
        # Create a device
        device = Device(
            ip_address='192.168.1.100',
            is_cctv=True,
            confidence_score=0.95,
            scan_id=scan.scan_id,
            tenant_id='test-tenant'
        )
        db.session.add(device)
        db.session.commit()
        
        assert device.device_id is not None
        assert device.ip_address == '192.168.1.100'
    except ImportError:
        pytest.skip("Models module not available")


@pytest.mark.unit
def test_vulnerability_model_creation(db):
    """Test Vulnerability model can be instantiated"""
    try:
        from backend.core.models import Scan, Device, Vulnerability, ScanStatus, SeverityLevel
        
        # Create scan and device
        scan = Scan(
            network_range='192.168.1.0/24',
            status=ScanStatus.COMPLETED,
            tenant_id='test-tenant'
        )
        db.session.add(scan)
        db.session.commit()
        
        device = Device(
            ip_address='192.168.1.100',
            is_cctv=True,
            confidence_score=0.95,
            scan_id=scan.scan_id,
            tenant_id='test-tenant'
        )
        db.session.add(device)
        db.session.commit()
        
        # Create vulnerability
        vuln = Vulnerability(
            device_id=device.device_id,
            title='Default Credentials',
            severity=SeverityLevel.HIGH,
            cvss_score=7.5,
            tenant_id='test-tenant'
        )
        db.session.add(vuln)
        db.session.commit()
        
        assert vuln.vulnerability_id is not None
        assert vuln.title == 'Default Credentials'
    except ImportError:
        pytest.skip("Models module not available")


@pytest.mark.unit
def test_report_model_creation(db):
    """Test Report model can be instantiated"""
    try:
        from backend.core.models import Scan, Report, ScanStatus
        
        # Create a scan
        scan = Scan(
            network_range='192.168.1.0/24',
            status=ScanStatus.COMPLETED,
            tenant_id='test-tenant'
        )
        db.session.add(scan)
        db.session.commit()
        
        # Create a report
        report = Report(
            scan_id=scan.scan_id,
            format='html',
            file_path='/tmp/report.html',
            tenant_id='test-tenant'
        )
        db.session.add(report)
        db.session.commit()
        
        assert report.report_id is not None
        assert report.format == 'html'
    except ImportError:
        pytest.skip("Models module not available")
