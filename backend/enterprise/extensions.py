from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from celery import Celery

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address)
cors = CORS()
celery_app = Celery()


def init_celery(app, celery: Celery) -> Celery:
    """Bind Celery to Flask app context so tasks can access db/config."""
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
