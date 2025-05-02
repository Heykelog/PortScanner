# Port Scanner Web Application

A comprehensive internal network port scanning and vulnerability detection application built with Flask.

## Features

- User authentication and role-based access control
- Environment and subnet management
- Automated port scanning and change detection
- Vulnerability scanning using nmap scripts
- Scheduled scans and background processing
- Comprehensive reporting and visualization
- Search functionality for specific IPs and ports

## Requirements

- Python 3.8+
- Redis server
- PostgreSQL (recommended) or SQLite
- Nmap (for port scanning)

## Installation

1. Clone the repository:
```
git clone <repository-url>
cd PortScanner
```

2. Create and activate a virtual environment:
```
python -m venv venv
# On Windows
venv\Scripts\activate
# On Linux/Mac
source venv/bin/activate
```

3. Install dependencies:
```
pip install -r requirements.txt
```

4. Create a `.env` file in the project root with the following contents:
```
SECRET_KEY=your-secret-key
DATABASE_URL=postgresql://username:password@localhost/port_scanner
# Or for SQLite
# DATABASE_URL=sqlite:///port_scanner.db
REDIS_URL=redis://localhost:6379/0
CELERY_CONCURRENCY=4
```

5. Initialize the database:
```
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

## Running the Application

Starting with Docker:
```
docker-compose up
```

You can run all components with the start_all.py script:
```
python start_all.py
```

Or run components individually:

1. Run the Flask application:
```
flask run
```

2. Run Celery worker:
```
celery -A app.tasks.celery worker --loglevel=info
```

3. Run Celery beat (for scheduled tasks):
```
celery -A app.tasks.celery beat --loglevel=info
```

## First-time Setup

When you first run the application, an admin user will be created automatically with:
- Username: admin
- Password: admin

**Important:** Change the admin password immediately after first login.

## Usage

1. Access the application at http://localhost:5000
2. Log in with the admin account
3. Create environments and subnets
4. Configure scan schedules or run manual scans
5. View results in the reporting section

## Security Considerations

This application is designed for internal network scanning. It should be deployed securely:

- Change the default admin password immediately
- Use HTTPS for production deployments
- Restrict access to authorized personnel only
- Ensure proper system permissions for nmap scanning

## License

This project is licensed under the MIT License - see the LICENSE file for details. #
