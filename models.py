from app import db
from datetime import datetime
from sqlalchemy import text
import uuid

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(30), nullable=False)  # director, head_of_business_control, auditor, auditee
    first_name = db.Column(db.String(64), nullable=False)
    last_name = db.Column(db.String(64), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    address = db.Column(db.Text, nullable=True)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    password_reset_required = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    department = db.relationship('Department', foreign_keys=[department_id], backref='users')
    assigned_audits = db.relationship('Audit', foreign_keys='Audit.auditor_id', backref='auditor')
    auditee_audits = db.relationship('Audit', foreign_keys='Audit.auditee_id', backref='auditee')
    supervised_audits = db.relationship('Audit', foreign_keys='Audit.supervisor_id', backref='head_of_business_control')
    created_audits = db.relationship('Audit', foreign_keys='Audit.created_by_id', backref='creator')
    directed_audits = db.relationship('Audit', foreign_keys='Audit.director_id', backref='director')
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    head_name = db.Column(db.String(100), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    units = db.relationship('DepartmentUnit', backref='department', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Department {self.name}>'

class DepartmentUnit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=False)
    unit_head_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    unit_head = db.relationship('User', foreign_keys=[unit_head_id])
    
    def __repr__(self):
        return f'<DepartmentUnit {self.name}>'

class AuditTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    audit_type = db.Column(db.String(50), nullable=False)  # internal, external, compliance, etc.
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    created_by = db.relationship('User', backref='created_templates')
    checklist_items = db.relationship('ChecklistItem', backref='template', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<AuditTemplate {self.name}>'

class ChecklistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    template_id = db.Column(db.Integer, db.ForeignKey('audit_template.id'), nullable=False)
    item_text = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=True)
    is_mandatory = db.Column(db.Boolean, default=True)
    order_index = db.Column(db.Integer, default=0)
    
    def __repr__(self):
        return f'<ChecklistItem {self.item_text[:50]}>'

class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reference_number = db.Column(db.String(50), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    audit_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(30), default='assigned')  # assigned, acknowledged, plan_submitted, plan_approved, in_progress, review, closed
    priority = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    
    # Audit scope and objectives (Phase 1)
    audit_scope = db.Column(db.Text, nullable=True)
    audit_objectives = db.Column(db.Text, nullable=True)
    audit_criteria = db.Column(db.Text, nullable=True)
    resources_needed = db.Column(db.Text, nullable=True)
    
    # Auditor acknowledgment and planning (Phase 2)
    auditor_acknowledged_at = db.Column(db.DateTime, nullable=True)
    audit_plan = db.Column(db.Text, nullable=True)
    audit_methodology = db.Column(db.Text, nullable=True)
    audit_checklist = db.Column(db.Text, nullable=True)
    data_request_list = db.Column(db.Text, nullable=True)
    
    # Head of Business Control Plan Submission (Phase 3)
    plan_submitted_at = db.Column(db.DateTime, nullable=True)  # When Head of Business Control submits plan to Director
    
    # Director approval (Phase 4)  
    director_approved_at = db.Column(db.DateTime, nullable=True)
    director_feedback = db.Column(db.Text, nullable=True)
    
    # Auditor assignment (Phase 5)
    auditor_assigned_at = db.Column(db.DateTime, nullable=True)  # When Head of Business Control assigns auditor
    plan_approved_at = db.Column(db.DateTime, nullable=True)  # Final approval timestamp
    supervisor_feedback = db.Column(db.Text, nullable=True)
    
    # Auditee coordination
    auditee_notified_at = db.Column(db.DateTime, nullable=True)
    auditee_acknowledged_at = db.Column(db.DateTime, nullable=True)
    document_request_sent_at = db.Column(db.DateTime, nullable=True)
    access_arrangements_completed = db.Column(db.Boolean, default=False)
    
    # Assignment
    auditor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Assigned by Head of Business Control after Director approval
    auditee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    supervisor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Head of Business Control
    director_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Director for approval
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=True)
    
    # Dates
    planned_start_date = db.Column(db.Date, nullable=True)
    planned_end_date = db.Column(db.Date, nullable=True)
    actual_start_date = db.Column(db.Date, nullable=True)
    actual_end_date = db.Column(db.Date, nullable=True)
    
    # Meta
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships  
    created_by = db.relationship('User', foreign_keys=[created_by_id], overlaps="created_audits,creator")
    assigned_department = db.relationship('Department', backref='audits')
    findings = db.relationship('Finding', backref='audit', cascade='all, delete-orphan')
    evidence_files = db.relationship('EvidenceFile', backref='audit', cascade='all, delete-orphan')
    audit_responses = db.relationship('AuditResponse', backref='audit', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Audit {self.reference_number}>'
    
    def generate_reference_number(self):
        year = datetime.utcnow().year
        count = Audit.query.filter(text("EXTRACT(year FROM created_at) = :year")).params(year=year).count() + 1
        return f"AUD-{year}-{count:04d}"

class AuditResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    audit_id = db.Column(db.Integer, db.ForeignKey('audit.id'), nullable=False)
    checklist_item_id = db.Column(db.Integer, db.ForeignKey('checklist_item.id'), nullable=False)
    response = db.Column(db.String(20), nullable=False)  # compliant, non_compliant, not_applicable, partial
    comments = db.Column(db.Text, nullable=True)
    evidence_description = db.Column(db.Text, nullable=True)
    completed_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    checklist_item = db.relationship('ChecklistItem')
    completed_by = db.relationship('User')
    
    def __repr__(self):
        return f'<AuditResponse {self.response}>'

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    audit_id = db.Column(db.Integer, db.ForeignKey('audit.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    category = db.Column(db.String(100), nullable=True)
    risk_assessment = db.Column(db.Text, nullable=True)  # Risk analysis by auditor
    recommendation = db.Column(db.Text, nullable=True)  # Auditor's recommendation
    status = db.Column(db.String(20), default='open')  # open, in_progress, resolved, closed
    
    # Assignment
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    auditee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    identified_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Dates
    due_date = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    assigned_to = db.relationship('User', foreign_keys=[assigned_to_id])
    auditee = db.relationship('User', foreign_keys=[auditee_id])
    identified_by = db.relationship('User', foreign_keys=[identified_by_id])
    corrective_actions = db.relationship('CorrectiveAction', backref='finding', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Finding {self.title}>'

class CorrectiveAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('finding.id'), nullable=False)
    action_description = db.Column(db.Text, nullable=False)
    responsible_person_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='planned')  # planned, in_progress, completed, overdue
    priority = db.Column(db.String(20), default='medium')
    
    # Dates
    planned_completion_date = db.Column(db.Date, nullable=False)
    actual_completion_date = db.Column(db.Date, nullable=True)
    
    # Progress tracking
    progress_percentage = db.Column(db.Integer, default=0)
    implementation_notes = db.Column(db.Text, nullable=True)
    
    # Meta
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    responsible_person = db.relationship('User', foreign_keys=[responsible_person_id])
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    
    def __repr__(self):
        return f'<CorrectiveAction {self.action_description[:50]}>'

class EvidenceFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    audit_id = db.Column(db.Integer, db.ForeignKey('audit.id'), nullable=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('finding.id'), nullable=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    # Supervisor review fields
    supervisor_comment = db.Column(db.Text, nullable=True)
    supervisor_status = db.Column(db.String(50), nullable=True)  # approved, rejected, reviewed
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    
    # Meta
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    uploaded_by = db.relationship('User', foreign_keys=[uploaded_by_id])
    reviewed_by = db.relationship('User', foreign_keys=[reviewed_by_id])
    finding = db.relationship('Finding', backref='evidence_files')
    
    def __repr__(self):
        return f'<EvidenceFile {self.original_filename}>'

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    entity_type = db.Column(db.String(50), nullable=False)  # audit, finding, user, etc.
    entity_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User')
    
    def __repr__(self):
        return f'<AuditLog {self.action}>'

class AuditDocumentRequest(db.Model):
    """Document requests from auditor to auditee"""
    id = db.Column(db.Integer, primary_key=True)
    audit_id = db.Column(db.Integer, db.ForeignKey('audit.id'), nullable=False)
    requested_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    auditee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    document_type = db.Column(db.String(100), nullable=False)  # policies, procedures, logs, transaction_data
    document_description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), default='medium')
    due_date = db.Column(db.Date, nullable=True)
    
    status = db.Column(db.String(20), default='pending')  # pending, provided, not_available
    auditee_response = db.Column(db.Text, nullable=True)
    response_date = db.Column(db.Date, nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    audit = db.relationship('Audit', backref='document_requests')
    requested_by = db.relationship('User', foreign_keys=[requested_by_id])
    auditee = db.relationship('User', foreign_keys=[auditee_id])
    
    def __repr__(self):
        return f'<AuditDocumentRequest {self.document_type}>'

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), nullable=False)  # audit_assigned, plan_approval_needed, documents_requested, audit_due, action_overdue
    is_read = db.Column(db.Boolean, default=False)
    related_entity_type = db.Column(db.String(50), nullable=True)
    related_entity_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='notifications')
    
    def __repr__(self):
        return f'<Notification {self.title}>'
