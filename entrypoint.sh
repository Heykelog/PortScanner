#!/bin/sh

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL..."
while ! nc -z db 5432; do
  sleep 0.1
done
echo "PostgreSQL is up and running"

# Initialize migrations if not exist
if [ ! -d "migrations" ]; then
  echo "Initializing migrations directory..."
  flask db init
fi

# Check for database tables
echo "Checking database status..."
python -c "from app import db; db.create_all()" || true

# Create admin user if it doesn't exist
echo "Setting up admin user..."
flask init-db

# Start the application
echo "Starting the application..."
exec "$@" 