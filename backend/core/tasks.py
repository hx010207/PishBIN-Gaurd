import os
from celery import Celery

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/1") # Use DB 1 for celery

celery_app = Celery(
    "phishbin_worker",
    broker=REDIS_URL,
    backend=REDIS_URL
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],  
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300, # Max 5 minutes per job
)

# Placeholder for auto-discovering tasks once they are written
celery_app.autodiscover_tasks(['services.file_tasks', 'services.url_tasks'])
