import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "audit-management-fallback-key-2025")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# File upload configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# initialize the app with the extension
db.init_app(app)

# Initialize database and create tables
def init_database():
    with app.app_context():
        # Import models to ensure tables are created
        import models  # noqa: F401
        db.create_all()
        
        # Create default admin user if none exists
        from models import User
        from werkzeug.security import generate_password_hash
        
        try:
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin_user = User()
                admin_user.username = 'admin'
                admin_user.email = 'admin@audit.system'
                admin_user.password_hash = generate_password_hash('admin123')
                admin_user.role = 'admin'
                admin_user.first_name = 'System'
                admin_user.last_name = 'Administrator'
                admin_user.is_active = True
                admin_user.password_reset_required = False
                
                db.session.add(admin_user)
                db.session.commit()
                logging.info("Default admin user created: admin/admin123")
        except Exception as e:
            logging.error(f"Error creating admin user: {str(e)}")
            db.session.rollback()

# Initialize database when app starts
init_database()
