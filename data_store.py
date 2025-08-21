"""
Global data store for the audit management system
This provides a centralized in-memory storage that can work with or without Firebase
"""
from datetime import datetime
import uuid

# Global in-memory data store
DATA_STORE = {
    'users': {},
    'departments': {},
    'audits': {},
    'risk_assessments': {},
    'findings': {},
    'corrective_actions': {},
    'messages': {},
    'evidence_files': {},
    'audit_reports': {},
    'audit_logs': {}
}

def initialize_sample_data():
    """Initialize the system with sample data"""
    
    # Create default admin user
    admin_id = str(uuid.uuid4())
    admin_data = {
        'id': admin_id,
        'email': 'admin@audit.system',
        'role': 'director',
        'first_name': 'System',
        'last_name': 'Administrator',
        'username': 'admin',
        'phone': '+1-555-0001',
        'is_active': True,
        'password_reset_required': False,
        'created_at': datetime.utcnow(),
        'last_login': None
    }
    DATA_STORE['users'][admin_id] = admin_data
    
    # Create sample departments
    dept_ids = []
    departments_data = [
        {'name': 'Internal Audit', 'description': 'Internal audit department'},
        {'name': 'Finance', 'description': 'Finance and accounting department'},
        {'name': 'Operations', 'description': 'Operations department'},
        {'name': 'IT', 'description': 'Information technology department'},
    ]
    
    for dept_data in departments_data:
        dept_id = str(uuid.uuid4())
        dept_data.update({
            'id': dept_id,
            'is_active': True,
            'created_at': datetime.utcnow()
        })
        DATA_STORE['departments'][dept_id] = dept_data
        dept_ids.append(dept_id)
    
    # Create sample users for each role
    sample_users = [
        {
            'email': 'head@audit.system',
            'role': 'head_of_business_control',
            'first_name': 'Business',
            'last_name': 'Control',
            'username': 'head_control',
            'department_id': dept_ids[0] if dept_ids else None
        },
        {
            'email': 'auditor@audit.system',
            'role': 'auditor',
            'first_name': 'John',
            'last_name': 'Auditor',
            'username': 'auditor1',
            'department_id': dept_ids[0] if dept_ids else None
        },
        {
            'email': 'auditee@audit.system',
            'role': 'auditee',
            'first_name': 'Jane',
            'last_name': 'Manager',
            'username': 'auditee1',
            'department_id': dept_ids[1] if dept_ids else None
        }
    ]
    
    for user_data in sample_users:
        user_id = str(uuid.uuid4())
        user_data.update({
            'id': user_id,
            'phone': '+1-555-0000',
            'is_active': True,
            'password_reset_required': True,
            'created_at': datetime.utcnow(),
            'last_login': None
        })
        DATA_STORE['users'][user_id] = user_data
    
    # Create sample audit
    audit_id = str(uuid.uuid4())
    audit_data = {
        'id': audit_id,
        'title': 'Financial Controls Audit',
        'description': 'Review of financial control processes',
        'audit_type': 'financial',
        'department_id': dept_ids[1] if dept_ids else None,
        'status': 'draft',
        'priority': 'medium',
        'reference_number': f'AUD-2025-{str(uuid.uuid4())[:8].upper()}',
        'created_at': datetime.utcnow()
    }
    DATA_STORE['audits'][audit_id] = audit_data
    
    # Create sample risk assessment
    risk_id = str(uuid.uuid4())
    risk_data = {
        'id': risk_id,
        'risk_description': 'Data security vulnerabilities',
        'department_id': dept_ids[2] if dept_ids else None,
        'impact_level': 'high',
        'likelihood_level': 'likely',
        'risk_score': 12,
        'risk_level': 'high',
        'mitigation_measures': 'Implement enhanced security protocols',
        'created_at': datetime.utcnow()
    }
    DATA_STORE['risk_assessments'][risk_id] = risk_data
    
    print(f"Initialized sample data: {len(DATA_STORE['users'])} users, {len(DATA_STORE['departments'])} departments")

def get_data_store():
    """Get the global data store"""
    return DATA_STORE

def find_user_by_email(email):
    """Find user by email address"""
    for user_id, user in DATA_STORE['users'].items():
        if user.get('email') == email:
            return user
    return None

def add_audit_log(user_id, action, entity_type, entity_id=None, details=None, ip_address=None, user_agent=None):
    """Add audit log entry"""
    log_id = str(uuid.uuid4())
    log_data = {
        'id': log_id,
        'user_id': user_id,
        'action': action,
        'entity_type': entity_type,
        'entity_id': entity_id,
        'details': details,
        'ip_address': ip_address,
        'user_agent': user_agent,
        'created_at': datetime.now()
    }
    DATA_STORE['audit_logs'][log_id] = log_data
    return log_id