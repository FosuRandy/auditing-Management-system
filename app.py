import os
import logging
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from firebase_config import firebase_config

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "audit-management-fallback-key-2025")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Firebase configuration
app.config['FIREBASE_CONFIG'] = firebase_config

# File upload configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize Firebase and create default data
def init_firebase():
    """Initialize Firebase with default data"""
    try:
        from firebase_models import UserModel, DepartmentModel
        
        # Initialize models
        user_model = UserModel()
        dept_model = DepartmentModel()
        
        # Create default admin user
        admin_email = 'admin@audit.system'
        existing_admin = user_model.get_user_by_email(admin_email)
        
        if not existing_admin:
            admin_data = {
                'email': admin_email,
                'role': 'director',
                'first_name': 'System',
                'last_name': 'Administrator',
                'username': 'admin',
                'phone': '+1-555-0001',
                'is_active': True,
                'password_reset_required': False
            }
            user_model.create_user(admin_data)
            logging.info("Default admin user created in Firebase")
        
        # Create default departments
        default_departments = [
            {'name': 'Internal Audit', 'description': 'Internal audit department'},
            {'name': 'Finance', 'description': 'Finance and accounting department'},
            {'name': 'Operations', 'description': 'Operations department'},
            {'name': 'IT', 'description': 'Information technology department'},
            {'name': 'Human Resources', 'description': 'Human resources department'}
        ]
        
        existing_depts = dept_model.get_all()
        if not existing_depts:
            for dept_data in default_departments:
                dept_model.create_department(dept_data)
            logging.info("Default departments created in Firebase")
            
    except Exception as e:
        logging.error(f"Error initializing Firebase data: {str(e)}")

# Initialize Firebase data when app starts
# Sample data will be initialized by data_store.py automatically
