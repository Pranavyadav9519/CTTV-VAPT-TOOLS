"""
Core database initialization with proper setup
Provides SQLAlchemy instance and initialization functions
"""

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.pool import QueuePool
import logging

logger = logging.getLogger(__name__)

# Create SQLAlchemy instance
db = SQLAlchemy()


def init_db(app):
    """Initialize database with Flask app"""
    db.init_app(app)

    with app.app_context():
        # Create all tables
        db.create_all()
        logger.info("Database tables created successfully")

    return db


def migrate_db(app):
    """Run database migrations"""
    from flask_migrate import Migrate
    migrate = Migrate(app, db)
    logger.info("Database migrations initialized")
    return migrate


def drop_db(app):
    """Drop all tables (WARNING: Use only in development)"""
    with app.app_context():
        if app.config.get("ENV") != "production":
            db.drop_all()
            logger.warning("All database tables dropped")
        else:
            logger.error("Cannot drop tables in production environment")


def seed_db(app):
    """Seed database with default data"""
    from backend.core.models import User, UserRole

    with app.app_context():
        # Check if admin already exists
        admin_exists = User.query.filter_by(username="admin").first()

        if not admin_exists:
            admin = User(
                username="admin",
                email="admin@localhost",
                tenant_id="default",
                role=UserRole.ADMIN,
                is_active=True,
                is_verified=True
            )
            admin.set_password("admin123")  # Change this after first login!

            db.session.add(admin)
            db.session.commit()

            logger.info("Default admin user created: admin/admin123")
