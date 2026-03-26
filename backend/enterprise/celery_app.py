from typing import Any
from celery import Celery

def create_celery(app: Any) -> Celery:
    celery = Celery(app.import_name)
    celery.conf.update(app.config)
    return celery
