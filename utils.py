import os
import uuid
from werkzeug.utils import secure_filename
from flask import current_app
import string
import secrets
from app import db

def generate_password(length=12):
    """Generate a secure random password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        # Ensure password has at least one lowercase, uppercase, digit and special char
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in "!@#$%^&*" for c in password)):
            return password

def allowed_file(filename):
    """Check if file extension is allowed"""
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_uploaded_file(file, upload_folder='uploads'):
    """Save uploaded file and return filename"""
    if file and allowed_file(file.filename):
        # Create upload directory if it doesn't exist
        os.makedirs(upload_folder, exist_ok=True)
        
        # Generate unique filename
        filename = str(uuid.uuid4()) + '_' + secure_filename(file.filename)
        file_path = os.path.join(upload_folder, filename)
        
        # Save file
        file.save(file_path)
        
        return {
            'filename': filename,
            'original_filename': file.filename,
            'file_path': file_path,
            'file_size': os.path.getsize(file_path),
            'file_type': file.content_type or 'application/octet-stream'
        }
    return None

def get_audit_statistics():
    """Get audit statistics for dashboard"""
    from models import Audit, Finding, CorrectiveAction
    from sqlalchemy import func, extract
    from datetime import datetime, timedelta
    
    current_year = datetime.utcnow().year
    current_quarter = (datetime.utcnow().month - 1) // 3 + 1
    
    # Total audits this year
    total_audits_year = Audit.query.filter(
        extract('year', Audit.created_at) == current_year
    ).count()
    
    # Audits by status
    audits_by_status = db.session.query(
        Audit.status, func.count(Audit.id)
    ).group_by(Audit.status).all()
    
    # Top 5 recurring findings
    top_findings = db.session.query(
        Finding.category, func.count(Finding.id).label('count')
    ).group_by(Finding.category).order_by(func.count(Finding.id).desc()).limit(5).all()
    
    # Overdue actions
    overdue_actions = CorrectiveAction.query.filter(
        CorrectiveAction.planned_completion_date < datetime.utcnow().date(),
        CorrectiveAction.status != 'completed'
    ).count()
    
    total_actions = CorrectiveAction.query.count()
    sla_adherence = ((total_actions - overdue_actions) / total_actions * 100) if total_actions > 0 else 100
    
    return {
        'total_audits_year': total_audits_year,
        'audits_by_status': dict(audits_by_status),
        'top_findings': top_findings,
        'sla_adherence': round(sla_adherence, 1),
        'overdue_actions': overdue_actions
    }

def get_user_notifications(user_id, limit=10):
    """Get notifications for a user"""
    from models import Notification
    return Notification.query.filter_by(
        user_id=user_id, is_read=False
    ).order_by(Notification.created_at.desc()).limit(limit).all()

def create_notification(user_id, title, message, notification_type, related_entity_type=None, related_entity_id=None):
    """Create a new notification"""
    from models import Notification
    notification = Notification(
        user_id=user_id,
        title=title,
        message=message,
        notification_type=notification_type,
        related_entity_type=related_entity_type,
        related_entity_id=related_entity_id
    )
    db.session.add(notification)
    db.session.commit()
    return notification
