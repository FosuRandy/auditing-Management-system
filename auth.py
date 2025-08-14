from flask import session, request, redirect, url_for, flash
from functools import wraps
from models import User, AuditLog
from app import db
import logging

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('landing'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('landing'))
            
            user = User.query.get(session['user_id'])
            
            # Map old role names to new ones for compatibility
            role_mapping = {
                'admin': 'director',
                'supervisor': 'head_of_business_control'
            }
            
            # Map allowed roles to actual roles
            mapped_roles = []
            for role in roles:
                mapped_roles.append(role_mapping.get(role, role))
            
            if not user or user.role not in mapped_roles:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_current_user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.is_active:
            return user
    return None

def log_audit_action(action, entity_type, entity_id=None, details=None):
    """Log user actions for audit trail"""
    try:
        user = get_current_user()
        if user:
            audit_log = AuditLog()
            audit_log.user_id = user.id
            audit_log.action = action
            audit_log.entity_type = entity_type
            audit_log.entity_id = entity_id
            audit_log.details = details
            audit_log.ip_address = request.remote_addr
            db.session.add(audit_log)
            db.session.commit()
            logging.info(f"Audit log created: {action} by {user.username}")
    except Exception as e:
        logging.error(f"Failed to create audit log: {str(e)}")

def check_password_reset_required():
    """Check if current user needs to reset password"""
    user = get_current_user()
    if user and user.password_reset_required:
        return True
    return False
