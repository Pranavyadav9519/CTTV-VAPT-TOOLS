
"""VAPT Tool - Enterprise SaaS Platform
Flask Application Factory"""


import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, render_template_string
from flask_cors import CORS

from .config import Config, config_by_name
from .extensions import db, migrate, jwt, limiter, celery_app, init_celery


def create_app(config_name: str = None) -> Flask:
    """Create and configure the Flask application (single-tenant)."""
    app = Flask(__name__)

    # ── Config ────────────────────────────────────────────────────────────────
    cfg_name = config_name or os.environ.get("FLASK_ENV", "production")
    cfg_class = config_by_name.get(cfg_name, Config)
    app.config.from_object(cfg_class)

    # Validate critical settings in production
    if not app.config.get("TESTING"):
        errors = cfg_class.validate()
        if errors:
            raise ValueError("Configuration errors: " + "; ".join(errors))

    # ── Logging ───────────────────────────────────────────────────────────────
    _init_logging(app)

    # ── Extensions ────────────────────────────────────────────────────────────
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    limiter.init_app(app)

    CORS(
        app,
        # Default allows local development; set CORS_ORIGINS env var in production.
        origins=app.config.get("CORS_ORIGINS") or ["http://localhost:3000"],
        supports_credentials=True,
        methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-Idempotency-Key", "X-Request-ID"],
    )

    # ── Celery context binding ────────────────────────────────────────────────
    init_celery(app, celery_app)

    # ── Blueprints / routes ───────────────────────────────────────────────────
    _init_blueprints(app)

    # ── Error handlers ────────────────────────────────────────────────────────
    _init_error_handlers(app)

    # ── Health endpoints ──────────────────────────────────────────────────────
    _init_health_endpoints(app)

    return app


def _init_logging(app: Flask) -> None:
    """Configure structured logging."""
    log_level = app.config.get("LOG_LEVEL", "INFO")
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    formatter = logging.Formatter(log_format)

    logs_dir = str(app.config.get("LOGS_DIR", "logs"))
    os.makedirs(logs_dir, exist_ok=True)

    file_handler = RotatingFileHandler(
        os.path.join(logs_dir, "vapt.log"),
        maxBytes=10 * 1024 * 1024,
        backupCount=10,
    )
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    app.logger.setLevel(getattr(logging, log_level, logging.INFO))
    if not app.logger.handlers:
        app.logger.addHandler(file_handler)
        app.logger.addHandler(console_handler)

    logging.getLogger("werkzeug").setLevel(logging.WARNING)


def _init_blueprints(app: Flask) -> None:
    """Register all API blueprints."""
    from .api.auth import auth_bp
    from .api.scans import scans_bp
    from .api.reports import reports_bp

    # Register at /api/ prefix (not /api/v1/) to match frontend expectations
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(scans_bp, url_prefix="/api/scans")
    app.register_blueprint(reports_bp, url_prefix="/api/reports")


def _init_error_handlers(app: Flask) -> None:
    """Register global error handlers."""

    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"success": False, "error": "Bad request", "code": 400}), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"success": False, "error": "Unauthorized", "code": 401}), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({"success": False, "error": "Forbidden", "code": 403}), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"success": False, "error": "Not found", "code": 404}), 404

    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return jsonify({"success": False, "error": "Rate limit exceeded", "code": 429}), 429

    @app.errorhandler(Exception)
    def handle_exception(e):
        app.logger.exception("Unhandled error: %s", e)
        return jsonify({"success": False, "error": "Internal server error", "code": 500}), 500


def _init_health_endpoints(app: Flask) -> None:
    """Register /health, /ready, frontend assets, and root endpoints."""
    import os
    from flask import send_from_directory

    @app.route("/", methods=["GET"])
    def home():
        """Landing page - VAPT Dashboard for CCTV Scanning."""
        html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>VAPT - CCTV Vulnerability & Penetration Testing</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .container {
                    background: white;
                    border-radius: 15px;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
                    max-width: 1000px;
                    width: 100%;
                    padding: 50px;
                }
                .header {
                    display: flex;
                    align-items: center;
                    margin-bottom: 30px;
                    border-bottom: 3px solid #1e3c72;
                    padding-bottom: 20px;
                }
                .header-icon {
                    font-size: 3em;
                    margin-right: 20px;
                }
                .header-text h1 {
                    color: #1e3c72;
                    margin-bottom: 5px;
                }
                .header-text p {
                    color: #666;
                    font-size: 1.1em;
                }
                .status-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 15px;
                    margin-bottom: 40px;
                }
                .status-card {
                    background: linear-gradient(135deg, #f0f4ff 0%, #e8ecff 100%);
                    padding: 20px;
                    border-radius: 10px;
                    border-left: 5px solid #2a5298;
                }
                .status-card h3 {
                    color: #1e3c72;
                    margin-bottom: 10px;
                    font-size: 0.9em;
                    text-transform: uppercase;
                }
                .status-value {
                    color: #2a5298;
                    font-size: 1.5em;
                    font-weight: bold;
                }
                .status-check {
                    color: #22c55e;
                    font-weight: bold;
                }
                .section {
                    margin-bottom: 40px;
                }
                .section h2 {
                    color: #1e3c72;
                    font-size: 1.4em;
                    margin-bottom: 20px;
                    padding-bottom: 10px;
                    border-bottom: 2px solid #2a5298;
                }
                .features-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }
                .feature-card {
                    background: #f8f9fa;
                    padding: 25px;
                    border-radius: 10px;
                    border-left: 4px solid #2a5298;
                    transition: all 0.3s ease;
                }
                .feature-card:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
                    border-left-color: #ff6b6b;
                }
                .feature-icon {
                    font-size: 2.5em;
                    margin-bottom: 10px;
                }
                .feature-card h3 {
                    color: #1e3c72;
                    margin-bottom: 10px;
                    font-size: 1.1em;
                }
                .feature-card p {
                    color: #666;
                    font-size: 0.95em;
                }
                .action-buttons {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 15px;
                    margin-top: 30px;
                }
                .btn {
                    padding: 15px 25px;
                    border: none;
                    border-radius: 8px;
                    font-size: 1em;
                    cursor: pointer;
                    text-decoration: none;
                    display: inline-block;
                    text-align: center;
                    transition: all 0.3s ease;
                    font-weight: 600;
                }
                .btn-primary {
                    background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                    color: white;
                }
                .btn-primary:hover {
                    transform: translateY(-3px);
                    box-shadow: 0 15px 30px rgba(30, 60, 114, 0.4);
                }
                .btn-secondary {
                    background: #ff6b6b;
                    color: white;
                }
                .btn-secondary:hover {
                    background: #e63946;
                    transform: translateY(-3px);
                    box-shadow: 0 15px 30px rgba(230, 57, 70, 0.4);
                }
                .btn-success {
                    background: #22c55e;
                    color: white;
                }
                .btn-success:hover {
                    background: #16a34a;
                    transform: translateY(-3px);
                    box-shadow: 0 15px 30px rgba(34, 197, 94, 0.4);
                }
                .endpoints-list {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 15px;
                }
                .endpoint-item {
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 8px;
                    border-left: 3px solid #2a5298;
                }
                .endpoint-path {
                    font-family: 'Courier New', monospace;
                    color: #2a5298;
                    font-weight: bold;
                    font-size: 0.9em;
                    background: #f0f4ff;
                    padding: 8px;
                    border-radius: 4px;
                    margin-bottom: 5px;
                    display: inline-block;
                }
                .endpoint-method {
                    display: inline-block;
                    padding: 3px 8px;
                    border-radius: 3px;
                    font-size: 0.75em;
                    font-weight: bold;
                    margin-right: 8px;
                    color: white;
                }
                .method-get { background: #3b82f6; }
                .method-post { background: #10b981; }
                .method-delete { background: #ef4444; }
                .footer {
                    margin-top: 40px;
                    padding-top: 30px;
                    border-top: 2px solid #eee;
                    color: #999;
                    text-align: center;
                    font-size: 0.9em;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="header-icon">🛡️</div>
                    <div class="header-text">
                        <h1>VAPT Platform</h1>
                        <p>CCTV Vulnerability Assessment & Penetration Testing</p>
                    </div>
                </div>

                <!-- Status Cards -->
                <div class="status-grid">
                    <div class="status-card">
                        <h3>System Status</h3>
                        <div class="status-value"><span class="status-check">✓</span> Operational</div>
                    </div>
                    <div class="status-card">
                        <h3>Database</h3>
                        <div class="status-value"><span class="status-check">✓</span> Connected</div>
                    </div>
                    <div class="status-card">
                        <h3>API</h3>
                        <div class="status-value"><span class="status-check">✓</span> Active</div>
                    </div>
                    <div class="status-card">
                        <h3>Version</h3>
                        <div class="status-value">2.0.0</div>
                    </div>
                </div>

                <!-- Features Section -->
                <div class="section">
                    <h2>🔍 Core Features</h2>
                    <div class="features-grid">
                        <div class="feature-card">
                            <div class="feature-icon">📡</div>
                            <h3>Network Discovery</h3>
                            <p>Auto-discover CCTV devices on your network using SSDP, ONVIF, and RTSP scanning</p>
                        </div>
                        <div class="feature-card">
                            <div class="feature-icon">🔐</div>
                            <h3>Vulnerability Assessment</h3>
                            <p>Identify security weaknesses, default credentials, and protocol vulnerabilities</p>
                        </div>
                        <div class="feature-card">
                            <div class="feature-icon">🎯</div>
                            <h3>Port Scanning</h3>
                            <p>Deep service enumeration and attack path analysis for penetration testing</p>
                        </div>
                        <div class="feature-card">
                            <div class="feature-icon">📊</div>
                            <h3>Report Generation</h3>
                            <p>Comprehensive HTML, JSON, and PDF reports with remediation recommendations</p>
                        </div>
                        <div class="feature-card">
                            <div class="feature-icon">🏗️</div>
                            <h3>Attack Paths</h3>
                            <p>Automatic attack path analysis and risk prioritization for critical threats</p>
                        </div>
                        <div class="feature-card">
                            <div class="feature-icon">📈</div>
                            <h3>Analytics</h3>
                            <p>Real-time analytics dashboard with vulnerability trends and risk metrics</p>
                        </div>
                    </div>
                </div>

                <!-- Quick Actions -->
                <div class="section">
                    <h2>⚡ Quick Actions</h2>
                    <div class="action-buttons">
                        <a href="/api/v1/scans" class="btn btn-primary">📋 View All Scans</a>
                        <a href="/api/v1/reports" class="btn btn-success">📊 View Reports</a>
                        <a href="/api/v1/auth/login" class="btn btn-secondary">🔐 Login</a>
                    </div>
                </div>

                <div class="footer">
                    <p><strong>VAPT Tool v2.0.0</strong> | Enterprise CCTV Vulnerability Assessment & Penetration Testing Platform</p>
                    <p>Scan, Assess, Report, and Remediate CCTV/DVR Security Risks</p>
                </div>
            </div>
        </body>
        </html>
        """
        return render_template_string(html)

    @app.route("/css/<path:filename>", methods=["GET"])
    def serve_css(filename):
        """Serve CSS static files from frontend/css directory."""
        try:
            css_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend", "css")
            return send_from_directory(css_dir, filename)
        except Exception as e:
            app.logger.warning(f"CSS file not found: {filename} - {e}")
            return jsonify({"error": "File not found"}), 404

    @app.route("/js/<path:filename>", methods=["GET"])
    def serve_js(filename):
        """Serve JavaScript static files from frontend/js directory."""
        try:
            js_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend", "js")
            return send_from_directory(js_dir, filename)
        except Exception as e:
            app.logger.warning(f"JS file not found: {filename} - {e}")
            return jsonify({"error": "File not found"}), 404

    @app.route("/health", methods=["GET"])
    def health_check():
        return jsonify({
            "status": "healthy",
            "version": app.config.get("APP_VERSION", "1.0.0"),
        })

    @app.route("/ready", methods=["GET"])
    def readiness_check():
        try:
            db.session.execute(db.text("SELECT 1"))
            return jsonify({"status": "ready"})
        except Exception as e:
            return jsonify({"status": "not ready", "error": str(e)}), 503
