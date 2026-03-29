"""
Analytics API Routes
Endpoints for dashboard KPIs, device risks, trends, and reports
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timedelta
from backend.core.analytics_service import (
    RiskScoringEngine, AnalyticsEngine, AnalyticsQuery
)
from backend.core.database import db
from functools import wraps
import logging

logger = logging.getLogger(__name__)

# Create blueprint
analytics_bp = Blueprint('analytics', __name__, url_prefix='/api/v1/analytics')


# ============================================================================
# DECORATORS
# ============================================================================

def require_auth(f):
    """Require JWT authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({
                'ok': False,
                'error': {
                    'code': 'AUTH_REQUIRED',
                    'message': 'Authorization token required'
                }
            }), 401
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# MAIN KPI ENDPOINT
# ============================================================================

@analytics_bp.route('/summary', methods=['GET'])
@require_auth
def get_analytics_summary():
    """
    GET /api/v1/analytics/summary
    
    Returns comprehensive analytics KPI summary
    
    Query params:
    - from: start date (YYYY-MM-DD, optional, default: 7 days ago)
    - to: end date (YYYY-MM-DD, optional, default: today)
    - days: number of days (optional, 7 default)
    """
    try:
        # Get tenant from token (simplified for now)
        tenant_id = request.headers.get('X-Tenant-ID', 'default')
        
        # Parse parameters
        days = request.args.get('days', 7, type=int)
        days = min(days, 365)  # Max 1 year
        
        # Get KPI summary
        kpi_data = AnalyticsQuery.get_kpi_summary(tenant_id, days)
        
        # Get top devices
        top_devices = AnalyticsQuery.get_top_devices(tenant_id, limit=10)
        
        # Get trends
        trends = AnalyticsQuery.get_vulnerability_trends(tenant_id, days)
        
        return jsonify({
            'ok': True,
            'data': {
                'kpi': kpi_data.get('kpi', {}),
                'time_period': kpi_data.get('time_period', {}),
                'top_devices': top_devices,
                'trends': trends,
            },
            'meta': {
                'timestamp': datetime.utcnow().isoformat(),
                'tenant_id': tenant_id,
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error in analytics summary: {str(e)}")
        return jsonify({
            'ok': False,
            'error': {
                'code': 'ANALYTICS_QUERY_FAILED',
                'message': str(e),
            }
        }), 500


# ============================================================================
# TOP DEVICES ENDPOINT
# ============================================================================

@analytics_bp.route('/devices', methods=['GET'])
@require_auth
def get_top_devices():
    """
    GET /api/v1/analytics/devices
    
    Returns list of devices ranked by risk score
    
    Query params:
    - limit: number of devices to return (default: 20, max: 100)
    - risk_tier: filter by tier (CRITICAL, HIGH, MEDIUM, LOW)
    - sort: sort field (risk_score, vulnerability_count, etc.)
    """
    try:
        tenant_id = request.headers.get('X-Tenant-ID', 'default')
        limit = request.args.get('limit', 20, type=int)
        limit = min(limit, 100)
        
        devices = AnalyticsQuery.get_top_devices(tenant_id, limit)
        
        # Apply filter if provided
        risk_tier = request.args.get('risk_tier', '').upper()
        if risk_tier:
            devices = [d for d in devices if d['risk']['tier'] == risk_tier]
        
        return jsonify({
            'ok': True,
            'data': {
                'devices': devices,
                'count': len(devices),
            },
            'meta': {
                'timestamp': datetime.utcnow().isoformat(),
                'tenant_id': tenant_id,
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting top devices: {str(e)}")
        return jsonify({
            'ok': False,
            'error': {
                'code': 'QUERY_FAILED',
                'message': str(e),
            }
        }), 500


# ============================================================================
# DEVICE DETAIL ENDPOINT
# ============================================================================

@analytics_bp.route('/devices/<int:device_id>', methods=['GET'])
@require_auth
def get_device_analytics(device_id):
    """
    GET /api/v1/analytics/devices/<device_id>
    
    Returns detailed analytics for a specific device
    """
    try:
        tenant_id = request.headers.get('X-Tenant-ID', 'default')
        
        from backend.core.models import Device
        from backend.core.analytics_models import DeviceRiskScore, TopDevicesAnalytics
        
        device = db.session.query(Device).filter(
            Device.id == device_id,
            Device.tenant_id == tenant_id
        ).first()
        
        if not device:
            return jsonify({
                'ok': False,
                'error': {
                    'code': 'NOT_FOUND',
                    'message': 'Device not found'
                }
            }), 404
        
        # Get risk score
        risk = db.session.query(DeviceRiskScore).filter(
            DeviceRiskScore.device_id == device_id
        ).first()
        
        # Get top analytics
        analytics = db.session.query(TopDevicesAnalytics).filter(
            TopDevicesAnalytics.device_id == device_id
        ).first()
        
        result = {
            'device': {
                'id': device.id,
                'ip_address': device.ip_address,
                'hostname': device.hostname,
                'manufacturer': device.manufacturer,
                'model': device.model,
                'firmware': device.firmware_version,
                'is_cctv': device.is_cctv,
            },
            'risk': risk.to_dict() if risk else {},
            'analytics': analytics.to_dict() if analytics else {},
        }
        
        return jsonify({
            'ok': True,
            'data': result,
            'meta': {
                'timestamp': datetime.utcnow().isoformat(),
                'tenant_id': tenant_id,
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting device analytics: {str(e)}")
        return jsonify({
            'ok': False,
            'error': {
                'code': 'QUERY_FAILED',
                'message': str(e),
            }
        }), 500


# ============================================================================
# TRENDS ENDPOINT
# ============================================================================

@analytics_bp.route('/trends', methods=['GET'])
@require_auth
def get_trends():
    """
    GET /api/v1/analytics/trends
    
    Returns vulnerability trends over time
    
    Query params:
    - days: number of days to look back (default: 30, max: 365)
    """
    try:
        tenant_id = request.headers.get('X-Tenant-ID', 'default')
        days = request.args.get('days', 30, type=int)
        days = min(days, 365)
        
        trends = AnalyticsQuery.get_vulnerability_trends(tenant_id, days)
        
        return jsonify({
            'ok': True,
            'data': {
                'trends': trends,
                'count': len(trends),
                'period_days': days,
            },
            'meta': {
                'timestamp': datetime.utcnow().isoformat(),
                'tenant_id': tenant_id,
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting trends: {str(e)}")
        return jsonify({
            'ok': False,
            'error': {
                'code': 'QUERY_FAILED',
                'message': str(e),
            }
        }), 500


# ============================================================================
# RISK STATISTICS ENDPOINT
# ============================================================================

@analytics_bp.route('/risk-stats', methods=['GET'])
@require_auth
def get_risk_statistics():
    """
    GET /api/v1/analytics/risk-stats
    
    Returns overall risk statistics for organization
    """
    try:
        tenant_id = request.headers.get('X-Tenant-ID', 'default')
        
        stats = RiskScoringEngine.get_risk_statistics(tenant_id)
        
        return jsonify({
            'ok': True,
            'data': stats,
            'meta': {
                'timestamp': datetime.utcnow().isoformat(),
                'tenant_id': tenant_id,
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting risk stats: {str(e)}")
        return jsonify({
            'ok': False,
            'error': {
                'code': 'QUERY_FAILED',
                'message': str(e),
            }
        }), 500


# ============================================================================
# MAINTENANCE/ADMIN ENDPOINTS
# ============================================================================

@analytics_bp.route('/calculate-risks', methods=['POST'])
@require_auth
def recalculate_risks():
    """
    POST /api/v1/analytics/calculate-risks (Admin only)
    
    Recalculates all device risk scores
    """
    try:
        tenant_id = request.headers.get('X-Tenant-ID', 'default')
        
        count = RiskScoringEngine.recalculate_all_device_risks(tenant_id)
        
        return jsonify({
            'ok': True,
            'data': {
                'devices_updated': count,
            },
            'meta': {
                'timestamp': datetime.utcnow().isoformat(),
                'tenant_id': tenant_id,
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error recalculating risks: {str(e)}")
        return jsonify({
            'ok': False,
            'error': {
                'code': 'OPERATION_FAILED',
                'message': str(e),
            }
        }), 500


@analytics_bp.route('/generate-rollup', methods=['POST'])
@require_auth
def generate_rollup():
    """
    POST /api/v1/analytics/generate-rollup (Admin only)
    
    Manually trigger daily rollup generation
    """
    try:
        tenant_id = request.headers.get('X-Tenant-ID', 'default')
        
        # Optional: specify date
        target_date = request.json.get('date') if request.json else None
        if target_date:
            target_date = datetime.fromisoformat(target_date)
        
        rollup = AnalyticsEngine.generate_daily_rollup(tenant_id, target_date)
        
        return jsonify({
            'ok': True,
            'data': rollup.to_dict(),
            'meta': {
                'timestamp': datetime.utcnow().isoformat(),
                'tenant_id': tenant_id,
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error generating rollup: {str(e)}")
        return jsonify({
            'ok': False,
            'error': {
                'code': 'OPERATION_FAILED',
                'message': str(e),
            }
        }), 500


# ============================================================================
# UTILITY ENDPOINTS
# ============================================================================

@analytics_bp.route('/health', methods=['GET'])
def analytics_health_check():
    """Health check for analytics service"""
    return jsonify({
        'ok': True,
        'status': 'healthy',
        'service': 'analytics',
    }), 200
