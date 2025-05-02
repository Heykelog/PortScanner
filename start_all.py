#!/usr/bin/env python
"""
Script to start all components of the Port Scanner application:
- Flask web application
- Celery worker for background tasks
- Celery beat for scheduled tasks
"""

import os
import sys
import subprocess
import threading
import signal
import time
import atexit

# Store all processes to terminate them gracefully on exit
processes = []

def cleanup():
    """Clean up all processes on exit"""
    print("\nShutting down all components...")
    for process in processes:
        if process.poll() is None:  # If the process is still running
            print(f"Terminating {process.args}")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print(f"Force killing {process.args}")
                process.kill()
    print("All components shut down.")

def start_flask():
    """Start the Flask web application"""
    flask_cmd = [
        sys.executable,
        "run.py"
    ]
    
    print("Starting Flask application...")
    flask_process = subprocess.Popen(
        flask_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    processes.append(flask_process)
    
    # Start output reader thread
    threading.Thread(
        target=output_reader,
        args=(flask_process, "FLASK"),
        daemon=True
    ).start()
    
    return flask_process

def start_celery_worker():
    """Start the Celery worker for background tasks"""
    celery_cmd = [
        sys.executable,  # Use Python executable
        "-m", "celery",  # Run celery as a module
        "-A", "app.tasks.celery",
        "worker",
        "--loglevel=info"
    ]
    
    print("Starting Celery worker...")
    celery_process = subprocess.Popen(
        celery_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    processes.append(celery_process)
    
    # Start output reader thread
    threading.Thread(
        target=output_reader,
        args=(celery_process, "WORKER"),
        daemon=True
    ).start()
    
    return celery_process

def start_celery_beat():
    """Start the Celery beat for scheduled tasks"""
    beat_cmd = [
        sys.executable,  # Use Python executable
        "-m", "celery",  # Run celery as a module
        "-A", "app.tasks.celery",
        "beat",
        "--loglevel=info"
    ]
    
    print("Starting Celery beat...")
    beat_process = subprocess.Popen(
        beat_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    processes.append(beat_process)
    
    # Start output reader thread
    threading.Thread(
        target=output_reader,
        args=(beat_process, "BEAT"),
        daemon=True
    ).start()
    
    return beat_process

def output_reader(process, prefix):
    """Read and print the output from a process with a prefix"""
    for line in iter(process.stdout.readline, ""):
        if line:
            print(f"[{prefix}] {line.rstrip()}")
    
    if process.poll() is not None:
        print(f"[{prefix}] Process exited with code {process.returncode}")

def main():
    # Register cleanup function
    atexit.register(cleanup)
    
    # Handle SIGINT (Ctrl+C) gracefully
    signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))
    
    # Check if Redis is running
    try:
        import redis
        redis_client = redis.Redis.from_url(
            os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
        )
        redis_client.ping()
        print("Redis server is running.")
    except Exception as e:
        print(f"Warning: Redis server might not be running: {e}")
        print("Please start Redis before continuing.")
        choice = input("Continue anyway? (y/n): ").strip().lower()
        if choice != 'y':
            sys.exit(1)
    
    # Start all components
    flask_process = start_flask()
    time.sleep(2)  # Wait for Flask to start
    
    celery_worker = start_celery_worker()
    time.sleep(2)  # Wait for Celery worker to start
    
    celery_beat = start_celery_beat()
    
    print("\nAll components started. Press Ctrl+C to stop all processes.")
    
    # Wait for all processes to complete (they shouldn't unless there's an error)
    try:
        while all(p.poll() is None for p in processes):
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nReceived keyboard interrupt. Shutting down...")
        sys.exit(0)
    
    # If we get here, at least one process has terminated unexpectedly
    for process in processes:
        if process.poll() is not None:
            print(f"Process {process.args} exited with code {process.returncode}")
    
    # Exit with error
    sys.exit(1)

if __name__ == "__main__":
    main() 