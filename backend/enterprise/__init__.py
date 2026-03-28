
"""VAPT Tool - Enterprise SaaS Platform
Flask Application Factory"""


import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify
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

    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(scans_bp, url_prefix="/api/v1/scans")
    app.register_blueprint(reports_bp, url_prefix="/api/v1/reports")


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
    """Register /health and /ready endpoints."""

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
