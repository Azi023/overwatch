"""
Celery application configuration.
"""
import os
from celery import Celery
from celery.schedules import crontab

# Get Redis URL from environment
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Create Celery app
celery_app = Celery(
    "overwatch",
    broker=os.getenv("CELERY_BROKER_URL", REDIS_URL),
    backend=os.getenv("CELERY_RESULT_BACKEND", REDIS_URL),
    include=["src.overwatch_core.orchestrator.tasks"]
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max per task
    task_soft_time_limit=3000,  # 50 minutes soft limit
    worker_prefetch_multiplier=1,  # Take one task at a time
    worker_max_tasks_per_child=50,  # Restart worker after 50 tasks
)

# Periodic task schedule (optional)
celery_app.conf.beat_schedule = {
    # Example: Run maintenance every day at midnight
    'cleanup-old-scans': {
        'task': 'src.overwatch_core.orchestrator.tasks.cleanup_old_scans',
        'schedule': crontab(hour=0, minute=0),
    },
}
