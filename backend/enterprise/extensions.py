from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis
from cryptography.fernet import Fernet
from celery import Celery

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address)

def get_redis(app) -> Redis:
    redis_url = app.config.get("REDIS_URL")
    if not redis_url:
        raise RuntimeError("REDIS_URL is required in app config")
    client = Redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=5)
    try:
        client.ping()
    except Exception:
        raise RuntimeError("Redis connection failed")
    return client

def get_fernet(app) -> Fernet:
    key = app.config.get("ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("ENCRYPTION_KEY is required in app config")
    if not (isinstance(key, (str, bytes)) and len(Fernet.generate_key()) == len(key.encode() if isinstance(key, str) else key)):
        raise RuntimeError("ENCRYPTION_KEY must be 32 url-safe base64-encoded bytes")
    return Fernet(key.encode() if isinstance(key, str) else key)

def make_celery(app) -> Celery:
    celery = Celery(app.import_name)
    celery.conf.update(app.config)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis as RedisClientLib
from cryptography.fernet import Fernet
from prometheus_client import Counter, Histogram, Gauge

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address)

request_count = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"]
)
request_duration = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration",
    ["method", "endpoint"]
)
active_scans = Gauge(
    "vapt_active_scans",
    "Number of active scans"
)
scan_results = Counter(
    "vapt_scan_results_total",
    "Total scan results",
    ["status", "severity"]
)

def init_redis(app) -> RedisClientLib:
    redis_url = app.config.get("REDIS_URL")
    if not redis_url:
        raise RuntimeError("REDIS_URL is required in app config")
    client = RedisClientLib.from_url(redis_url, decode_responses=True, socket_connect_timeout=5)
    client.ping()
    return client

def init_fernet(app) -> Fernet:
    key = app.config.get("ENCRYPTION_KEY")
    if result_backend:


            def _purge_expired(self) -> None:
                import time
                now = time.time()
                    self._store.pop(k, None)

                    self._expiry.pop(key, None)

    from flask_sqlalchemy import SQLAlchemy
    from flask_migrate import Migrate
    from flask_jwt_extended import JWTManager
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    from redis import Redis
    from cryptography.fernet import Fernet
    from celery import Celery

    db = SQLAlchemy()
    migrate = Migrate()
    jwt = JWTManager()
    limiter = Limiter(key_func=get_remote_address)

    def get_redis(app) -> Redis:
        redis_url = app.config.get("REDIS_URL")
        if not redis_url:
            raise RuntimeError("REDIS_URL is required in app config")
        client = Redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=5)
        try:
            client.ping()
        except Exception:
            raise RuntimeError("Redis connection failed")
        return client

    def get_fernet(app) -> Fernet:
        key = app.config.get("ENCRYPTION_KEY")
        if not key:
            raise RuntimeError("ENCRYPTION_KEY is required in app config")
        if not (isinstance(key, (str, bytes)) and len(Fernet.generate_key()) == len(key.encode() if isinstance(key, str) else key)):
            raise RuntimeError("ENCRYPTION_KEY must be 32 url-safe base64-encoded bytes")
        return Fernet(key.encode() if isinstance(key, str) else key)

    def make_celery(app) -> Celery:
        celery = Celery(app.import_name)
        celery.conf.update(app.config)
        return celery
    ##TRUNCATE##
                self._store.pop(key, None)
                self._expiry.pop(key, None)
                return existed
    fernet = Fernet(key)
    return fernet


def init_celery(app, celery: Celery) -> Celery:
    celery.conf.update(app.config)
    broker = app.config.get("CELERY_BROKER_URL")
    result_backend = app.config.get("CELERY_RESULT_BACKEND")
    if broker:
        celery.conf.broker_url = broker
    if result_backend:
        celery.conf.result_backend = result_backend

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery
