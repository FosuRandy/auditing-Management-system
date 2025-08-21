from flask import session, request, redirect, url_for, flash
from functools import wraps
from data_store import DATA_STORE, find_user_by_email, add_audit_log
import logging

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('landing'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('landing'))
            
            user = get_current_user()
            
            # Map old role names to new ones for compatibility
            role_mapping = {
                'admin': 'director',
                'supervisor': 'head_of_business_control'
            }
            
            # Get the mapped roles
            mapped_roles = []
            for role in required_roles:
                mapped_roles.append(role_mapping.get(role, role))
            
            if not user or user.get('role') not in mapped_roles or not user.get('is_active', False):
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('landing'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_current_user():
    """Get current user from session"""
    if 'user_id' in session:
        try:
            # Get user from data store
            user_id = session['user_id']
            if user_id in DATA_STORE['users']:
                user = DATA_STORE['users'][user_id]
                if user and user.get('is_active', False):
                    return user
        except Exception as e:
            logging.error(f"Error getting current user: {e}")
    return None

def log_audit_action(action, entity_type, entity_id=None, details=None):
    """Log user actions for audit trail"""
    try:
        user = get_current_user()
        if user:
            log_id = add_audit_log(
                user_id=user['id'],
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details=details,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            logging.info(f"Audit log created: {action} by {user.get('username', 'unknown')}")
    except Exception as e:
        logging.error(f"Failed to create audit log: {str(e)}")

def check_password_reset_required():
    """Check if current user needs to reset password"""
    user = get_current_user()
    if user and user.get('password_reset_required', False):
        return True
    return False