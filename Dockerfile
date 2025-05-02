FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    nmap \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Make the entrypoint scripts executable
RUN chmod +x /app/entrypoint.sh
RUN chmod +x /app/celery-worker-entrypoint.sh
RUN chmod +x /app/celery-beat-entrypoint.sh

# Set environment variables
ENV FLASK_APP=run.py
ENV PYTHONUNBUFFERED=1

# Expose port
EXPOSE 5000

# Use the entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]

# Command to run when container starts
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "run:app"] 