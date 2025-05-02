#!/bin/sh

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL..."
while ! nc -z db 5432; do
  sleep 0.1
done
echo "PostgreSQL is up and running"

# Wait for Redis to be ready
echo "Waiting for Redis..."
while ! nc -z redis 6379; do
  sleep 0.1
done
echo "Redis is up and running"

# Wait for Celery worker to be ready
echo "Waiting for Celery worker..."
sleep 10
echo "Starting Celery beat..."

# Start the Celery beat
exec "$@" 