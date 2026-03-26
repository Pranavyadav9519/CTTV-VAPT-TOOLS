import os
from celery import Celery
from app.config import Config
def make_celery(app=None):
	config = Config.load_from_env()
	config.validate()
	celery = Celery(
		app.import_name if app else __name__,
		broker=config.CELERY_BROKER_URL,
		backend=config.CELERY_RESULT_BACKEND,
		include=[
			'app.modules.credential_tester',
			'app.modules.data_ingestion',
			'app.modules.data_normalizer',
			'app.modules.device_identifier',
			'app.modules.network_scanner',
			'app.modules.port_scanner',
			'app.modules.report_generator',
			'app.modules.vulnerability_scanner',
		]
	)
	celery.conf.update(app.config if app else config.as_flask_dict())
	# Enforce strict serialization, S3/Redis integration, deterministic bootstrap
	celery.conf.update(
		task_serializer='json',
		accept_content=['json'],
		result_serializer='json',
		broker_transport_options={
			'visibility_timeout': 3600,
			'queue_order_strategy': 'priority',
		},
		worker_prefetch_multiplier=1,
		task_acks_late=True,
		task_reject_on_worker_lost=True,
		broker_connection_retry_on_startup=True,
	)
	TaskBase = celery.Task
	class ContextTask(TaskBase):
		abstract = True
		def __call__(self, *args, **kwargs):
			if app:
				with app.app_context():
					return TaskBase.__call__(self, *args, **kwargs)
			return TaskBase.__call__(self, *args, **kwargs)
	celery.Task = ContextTask
	return celery
from celery import Celery
from app.config import Config
import os

broker = os.getenv('CELERY_BROKER_URL', Config.from_env().CELERY_BROKER_URL)
backend = os.getenv('CELERY_RESULT_BACKEND', Config.from_env().CELERY_RESULT_BACKEND)
celery = Celery('vapt', broker=broker, backend=backend)
celery.conf.task_serializer = 'json'
celery.conf.result_serializer = 'json'
celery.conf.accept_content = ['json']
celery.conf.task_time_limit = int(os.getenv('CELERY_TASK_TIME_LIMIT', '3600'))
