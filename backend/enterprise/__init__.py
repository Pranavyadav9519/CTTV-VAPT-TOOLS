

"""VAPT Tool - Enterprise SaaS Platform
Flask Application Factory"""


import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, jsonify, request, g
from flask_cors import CORS
from redis import Redis
from celery import Celery
from .config import Config
from .extensions import db, migrate, redis_client, jwt, limiter, cors, s3_client, kms_client, celery_app, logger
from ..utils.logger import configure_logging


def create_app(config_name: str = None) -> Flask:
    """Create and configure the Flask application"""
    app = Flask(__name__)
    # Deterministic, runtime-only config load/validation
    config = Config.load_from_env()
    config.validate()
    configure_logging(config)
    app.config.from_mapping(config.as_flask_dict())
    # Secure, explicit extension initialization
    db.init_app(app)
    migrate.init_app(app, db)
    redis_client.init_app(app, config)
    jwt.init_app(app)
    limiter.init_app(app)
    cors.init_app(app)
    s3_client.init_app(app, config)
    kms_client.init_app(app, config)
    celery_app.conf.update(app.config)
    # Tenant isolation: enforce tenant context on every request
    
    @app.before_request
    def set_tenant_context():
        tenant_id = request.headers.get('X-Tenant-ID')
        if not tenant_id:
            return jsonify({"error": "Missing X-Tenant-ID header"}), 400
        g.tenant_id = tenant_id
    # Centralized error handling
    
    @app.errorhandler(Exception)
    def handle_exception(e):
        logger.exception("Unhandled error")
        return jsonify({"error": "Internal server error"}), 500
    # Register blueprints, error handlers, etc.
    # ...existing code...
    return app


def _validate_config(app: Flask) -> None:
    """Validate critical configuration at startup"""
    if not app.config.get("SECRET_KEY"):
        raise ValueError("SECRET_KEY environment variable is required")
    if len(app.config.get("SECRET_KEY", "")) < 32:
        raise ValueError("SECRET_KEY must be at least 32 characters long")
    if not app.config.get("JWT_SECRET_KEY"):
        app.config["JWT_SECRET_KEY"] = app.config["SECRET_KEY"]


def _init_extensions(app: Flask) -> None:
    """Initialize Flask extensions"""
    db.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)
    CORS(
        app,
        origins=app.config.get("CORS_ORIGINS") or [],
        supports_credentials=True,
        methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=[
            "Content-Type",
            "Authorization",
            "X-Idempotency-Key",
            "X-Tenant-ID",
        ],
    )


def _init_redis(app: Flask) -> None:
    """Initialize Redis connection"""
    global redis_client
    redis_url = app.config.get("REDIS_URL", "redis://localhost:6379/0")
    try:
        redis_client = Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
        redis_client.ping()
        app.redis = redis_client
    except Exception as e:
        app.logger.warning(
            f"Redis connection failed: {e}. Rate limiting will use memory."
        )
        redis_client = None


def _init_logging(app: Flask) -> None:
    """Configure structured JSON logging"""
    log_level = app.config.get("LOG_LEVEL", "INFO")
    log_format = (
        '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
        '"logger": "%(name)s", "message": "%(message)s"}'
    )
    formatter = logging.Formatter(log_format)
    logs_dir = app.config.get("LOGS_DIR", "logs")
    os.makedirs(logs_dir, exist_ok=True)
    file_handler = RotatingFileHandler(
        os.path.join(logs_dir, "vapt.log"),
        maxBytes=10 * 1024 * 1024,
        backupCount=10,
    )
    file_handler.setFormatter(formatter)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    app.logger.setLevel(getattr(logging, log_level))
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


def _init_blueprints(app: Flask) -> None:
    """Register application blueprints"""
    from .api.auth import auth_bp
    from .api.scans import scans_bp
    from .api.reports import reports_bp
    try:
        from .api.devices import devices_bp  # type: ignore
    except Exception:
        devices_bp = None
    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(scans_bp, url_prefix="/api/v1/scans")
    app.register_blueprint(reports_bp, url_prefix="/api/v1/reports")
    if devices_bp:
        app.register_blueprint(devices_bp, url_prefix="/api/v1/devices")


def _init_error_handlers(app: Flask) -> None:
    """Register global error handlers"""
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
    
    @app.errorhandler(500)
    def internal_error(e):
        app.logger.error(f"Internal server error: {e}")
        return (
            jsonify({"success": False, "error": "Internal server error", "code": 500}),
            500,
        )


def _init_health_endpoints(app: Flask) -> None:
    """Register health check endpoints"""
    @app.route("/health", methods=["GET"])
    def health_check():
        redis_status = "healthy"
        if redis_client:
            try:
                redis_client.ping()
            except Exception:
                redis_status = "unhealthy"
        return jsonify({
            "status": "healthy",
            "version": app.config.get("APP_VERSION", "1.0.0"),
            "redis": redis_status,
        })
    
    @app.route("/ready", methods=["GET"])
    def readiness_check():
        try:
            db.session.execute(db.text("SELECT 1"))
            return jsonify({"status": "ready"})
        except Exception as e:
            return jsonify({"status": "not ready", "error": str(e)}), 503


def init_celery(app: Flask, celery: Celery) -> None:
    """Initialize Celery with Flask app context"""
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
