"""
API Blueprint Factory and Registration
Initializes all API endpoints
"""

from flask import Blueprint
from flask_restx import Api, Namespace

def create_api_blueprint():
    """Create main API blueprint"""
    api_bp = Blueprint('api', __name__, url_prefix='/api')

    # TODO: Import and register individual blueprint modules
    # from backend.api.auth import auth_bp
    # from backend.api.scans import scans_bp
    # from backend.api.devices import devices_bp
    # from backend.api.vulnerabilities import vulns_bp
    # from backend.api.reports import reports_bp

    # api_bp.register_blueprint(auth_bp, url_prefix='/auth')
    # api_bp.register_blueprint(scans_bp, url_prefix='/scans')
    # api_bp.register_blueprint(devices_bp, url_prefix='/devices')
    # api_bp.register_blueprint(vulns_bp, url_prefix='/vulnerabilities')
    # api_bp.register_blueprint(reports_bp, url_prefix='/reports')

    return api_bp


def register_api(app):
    """Register API with Flask app"""
    api_bp = create_api_blueprint()
    app.register_blueprint(api_bp)
