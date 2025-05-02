from app import create_app, db
from app.models import User
from flask_migrate import Migrate
from flask.cli import with_appcontext
import click
import os

app = create_app()
migrate = Migrate(app, db)

# Replace before_first_request with a Click command
@click.command('init-db')
@with_appcontext
def create_tables_and_admin():
    """Create database tables and admin user if they don't exist"""
    # Create tables
    db.create_all()
    
    # Check if admin user exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        # Create admin user
        admin = User(
            username='admin',
            email='admin@example.com',
            is_admin=True
        )
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()
        print("Admin user created with username 'admin' and password 'admin'")

# Register the command with the Flask app
app.cli.add_command(create_tables_and_admin)

# Call this function on startup when running directly
if __name__ == '__main__':
    with app.app_context():
        # Create tables and admin user on startup
        db.create_all()
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True
            )
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()
            print("Admin user created with username 'admin' and password 'admin'")
    
    app.run(debug=True) 