from app.tasks import celery
from app.tasks.scan_tasks import scheduled_scan
from celery.schedules import crontab

@celery.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    # Check for scheduled scans every minute
    sender.add_periodic_task(60.0, scheduled_scan.s(), name='check-scheduled-scans-every-minute')
    
    # Add other periodic tasks as needed
    # For example, daily tasks can be added with crontab:
    # sender.add_periodic_task(
    #     crontab(hour=0, minute=0),  # midnight
    #     task_name.s(),
    #     name='task-description'
    # ) 