from celery import Celery
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def make_celery(app_name=__name__):
    redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    
    celery = Celery(
        app_name,
        backend=redis_url,
        broker=redis_url
    )
    
    celery.conf.update(
        worker_concurrency=int(os.environ.get('CELERY_CONCURRENCY', '4')),
        task_acks_late=True,
        task_time_limit=int(os.environ.get('CELERY_TASK_TIMEOUT', '3600')),  # 1 hour timeout
        task_soft_time_limit=int(os.environ.get('CELERY_SOFT_TIMEOUT', '3300')),  # 55 min soft timeout
        worker_prefetch_multiplier=1,
        task_default_queue='port_scanner'
    )
    
    # Include all task modules here
    celery.conf.imports = ['app.tasks.scan_tasks']
    
    return celery

celery = make_celery() 