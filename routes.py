from flask import render_template, request, redirect, url_for, flash, session, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import extract
from app import app, db
from models import *
# Create alias for backward compatibility
Evidence = EvidenceFile
from auth import login_required, role_required, get_current_user, log_audit_action, check_password_reset_required
from utils import generate_password, save_uploaded_file, get_audit_statistics, get_user_notifications, create_notification
from datetime import datetime, timedelta
import os

@app.route('/')
def landing():
    """Landing page with role-based login options"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/login/<role>')
def login_form(role):
    """Display login form for specific role"""
    valid_roles = ['admin', 'auditor', 'auditee', 'supervisor']
    if role not in valid_roles:
        flash('Invalid role specified.', 'error')
        return redirect(url_for('landing'))
    return render_template('login.html', role=role)

@app.route('/login', methods=['POST'])
def login():
    """Process login"""
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    
    user = User.query.filter_by(username=username, role=role, is_active=True).first()
    
    if user and check_password_hash(user.password_hash, password):
        session['user_id'] = user.id
        session['user_role'] = user.role
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        log_audit_action('login', 'user', user.id, f'User {username} logged in')
        
        # Check if password reset is required
        if user.password_reset_required:
            flash('You must change your password before continuing.', 'warning')
            return redirect(url_for('change_password'))
        
        flash(f'Welcome, {user.full_name}!', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid username, password, or role.', 'error')
        return redirect(url_for('login_form', role=role))

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    user = get_current_user()
    if user:
        log_audit_action('logout', 'user', user.id, f'User {user.username} logged out')
    
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard - redirect to role-specific dashboard"""
    user = get_current_user()
    
    # Check password reset requirement
    if check_password_reset_required():
        return redirect(url_for('change_password'))
    
    # Redirect to role-specific dashboard
    if user and user.role == 'director':
        return redirect(url_for('director_dashboard'))
    elif user and user.role == 'auditor':
        return redirect(url_for('auditor_dashboard'))
    elif user and user.role == 'auditee':
        return redirect(url_for('auditee_dashboard'))
    elif user and user.role == 'head_of_business_control':
        return redirect(url_for('head_of_business_control_dashboard'))
    else:
        flash('Invalid user or role.', 'error')
        return redirect(url_for('logout'))

@app.route('/director/dashboard')
@role_required('director')
def director_dashboard():
    """Director dashboard with plan approval capabilities"""
    user = get_current_user()
    
    # Get all audits for organization overview
    all_audits = Audit.query.all()
    
    # Get audit plans pending director approval
    plans_pending_approval = Audit.query.filter_by(
        status='plan_pending_director_approval'
    ).order_by(Audit.plan_submitted_at.desc()).all()
    
    # Get recently approved plans
    recently_approved = Audit.query.filter(
        Audit.director_approved_at.isnot(None)
    ).order_by(Audit.director_approved_at.desc()).limit(10).all()
    
    # Statistics
    total_audits_count = len(all_audits)
    plans_pending_count = len(plans_pending_approval)
    approved_plans_count = len([a for a in all_audits if a.director_approved_at])
    active_audits_count = len([a for a in all_audits if a.status in ['auditor_assigned', 'in_progress']])
    
    # Get recent activities
    recent_activities = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(10).all()
    
    return render_template('director/dashboard.html',
                         user=user,
                         all_audits=all_audits,
                         plans_pending_approval=plans_pending_approval,
                         recently_approved=recently_approved,
                         total_audits_count=total_audits_count,
                         plans_pending_count=plans_pending_count,
                         approved_plans_count=approved_plans_count,
                         active_audits_count=active_audits_count,
                         recent_activities=recent_activities)

@app.route('/auditor/dashboard')
@role_required('auditor')
def auditor_dashboard():
    """Auditor dashboard with comprehensive statistics"""
    user = get_current_user()
    today = datetime.utcnow().date()
    
    # Get auditor-specific statistics
    if not user:
        return redirect(url_for('login_form', role='auditor'))
    
    assigned_audits = Audit.query.filter_by(auditor_id=user.id).count()
    in_progress_audits = Audit.query.filter_by(auditor_id=user.id, status='in_progress').count()
    completed_audits = Audit.query.filter_by(auditor_id=user.id, status='completed').count()
    overdue_audits = Audit.query.filter(
        Audit.auditor_id == user.id,
        Audit.planned_end_date < today,
        Audit.status.in_(['draft', 'in_progress'])
    ).count()
    
    stats = {
        'assigned_audits': assigned_audits,
        'in_progress_audits': in_progress_audits,
        'completed_audits': completed_audits,
        'overdue_audits': overdue_audits
    }
    
    # Recent audit assignments
    recent_audits = Audit.query.filter_by(auditor_id=user.id).order_by(Audit.created_at.desc()).limit(5).all()
    
    # Recent findings created by auditor
    recent_findings = Finding.query.join(Audit).filter(
        Audit.auditor_id == user.id
    ).order_by(Finding.created_at.desc()).limit(10).all()
    
    # Pending actions (simplified for now)
    pending_actions = []
    
    return render_template('auditor/dashboard.html', 
                         stats=stats, recent_audits=recent_audits, 
                         recent_findings=recent_findings,
                         pending_actions=pending_actions, today=today)

@app.route('/auditee/dashboard')
@role_required('auditee')
def auditee_dashboard():
    """Auditee dashboard with comprehensive statistics"""
    user = get_current_user()
    today = datetime.utcnow().date()
    
    # Get auditee-specific statistics
    if not user:
        return redirect(url_for('login_form', role='auditee'))
    
    active_audits = Audit.query.filter_by(auditee_id=user.id, status='in_progress').count()
    pending_findings = Finding.query.filter_by(auditee_id=user.id, status='open').count()
    overdue_actions = CorrectiveAction.query.join(Finding).filter(
        Finding.auditee_id == user.id,
        CorrectiveAction.planned_completion_date < today,
        CorrectiveAction.status.in_(['planned', 'in_progress'])
    ).count()
    completed_actions = CorrectiveAction.query.join(Finding).filter(
        Finding.auditee_id == user.id,
        CorrectiveAction.status == 'completed'
    ).count()
    
    stats = {
        'active_audits': active_audits,
        'pending_findings': pending_findings,
        'overdue_actions': overdue_actions,
        'completed_actions': completed_actions
    }
    
    # Recent findings
    recent_findings = Finding.query.filter_by(auditee_id=user.id).order_by(Finding.created_at.desc()).limit(5).all()
    
    # Urgent actions
    urgent_actions = CorrectiveAction.query.join(Finding).filter(
        Finding.auditee_id == user.id,
        CorrectiveAction.planned_completion_date <= today + timedelta(days=7),
        CorrectiveAction.status.in_(['planned', 'in_progress'])
    ).limit(5).all()
    
    return render_template('auditee/dashboard.html', 
                         stats=stats, recent_findings=recent_findings, 
                         urgent_actions=urgent_actions, today=today)

@app.route('/head-of-business-control/dashboard')
@role_required('head_of_business_control')
def head_of_business_control_dashboard():
    """Head of Business Control dashboard with auditor assignment and evidence review"""
    user = get_current_user()
    
    # Get supervised audits
    supervised_audits = Audit.query.filter_by(supervisor_id=user.id).all()
    
    # Get audits awaiting auditor assignment (director approved, need auditor)
    awaiting_assignment = Audit.query.filter_by(
        supervisor_id=user.id, 
        status='pending_auditor_assignment'
    ).filter(Audit.director_approved_at.isnot(None)).order_by(Audit.director_approved_at.desc()).all()
    
    # Get evidence pending review
    pending_evidence = EvidenceFile.query.join(Finding).join(Audit).filter(
        Audit.supervisor_id == user.id,
        EvidenceFile.supervisor_status.is_(None)
    ).all()
    
    # Get recent activities 
    recent_activities = AuditLog.query.filter(
        AuditLog.entity_type == 'evidence'
    ).order_by(AuditLog.created_at.desc()).limit(10).all()
    
    context = {
        'user': user,
        'supervised_audits': supervised_audits,
        'supervised_audits_count': len(supervised_audits),
        'awaiting_assignment': awaiting_assignment,
        'awaiting_assignment_count': len(awaiting_assignment),
        'active_audits_count': len([a for a in supervised_audits if a.status in ['auditor_assigned', 'in_progress']]),
        'pending_evidence': pending_evidence,
        'pending_evidence_count': len(pending_evidence),
        'completed_reviews_count': EvidenceFile.query.join(Finding).join(Audit).filter(
            Audit.supervisor_id == user.id,
            EvidenceFile.supervisor_status.isnot(None)
        ).count(),
        'recent_activities': recent_activities
    }
    
    return render_template('head_of_business_control/dashboard.html', **context)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change password"""
    user = get_current_user()
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Validate current password
        if not check_password_hash(user.password_hash, current_password):
            flash('Current password is incorrect.', 'error')
            return render_template('profile.html', user=user, change_password=True)
        
        # Validate new password
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('profile.html', user=user, change_password=True)
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('profile.html', user=user, change_password=True)
        
        # Update password
        user.password_hash = generate_password_hash(new_password)
        user.password_reset_required = False
        db.session.commit()
        
        log_audit_action('password_change', 'user', user.id, 'User changed password')
        flash('Password changed successfully.', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('profile.html', user=user, change_password=True)

@app.route('/profile')
@login_required
def profile():
    """User profile"""
    user = get_current_user()
    notifications = get_user_notifications(user.id)
    return render_template('profile.html', user=user, notifications=notifications)

# Admin Routes
@app.route('/admin/users')
@role_required('admin')
def admin_users():
    """Manage users"""
    users = User.query.all()
    departments = Department.query.filter_by(is_active=True).all()
    return render_template('admin/users.html', users=users, departments=departments)

@app.route('/admin/users/create', methods=['POST'])
@role_required('admin')
def create_user():
    """Create new user"""
    username = request.form['username']
    email = request.form['email']
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    role = request.form['role']
    department_id = request.form.get('department_id') or None
    
    # Check if user exists
    if User.query.filter_by(username=username).first():
        flash('Username already exists.', 'error')
        return redirect(url_for('admin_users'))
    
    if User.query.filter_by(email=email).first():
        flash('Email already exists.', 'error')
        return redirect(url_for('admin_users'))
    
    # Generate auto password
    auto_password = generate_password()
    
    # Get contact details
    phone = request.form.get('phone', '')
    address = request.form.get('address', '')
    
    user = User()
    user.username = username
    user.email = email
    user.first_name = first_name
    user.last_name = last_name
    user.role = role
    user.phone = phone
    user.address = address
    user.department_id = department_id
    user.password_hash = generate_password_hash(auto_password)
    user.password_reset_required = True
    
    db.session.add(user)
    db.session.commit()
    
    log_audit_action('create_user', 'user', user.id, f'Created user {username}')
    
    # Create notification for admin about the generated password
    from utils import create_notification
    admin_user = get_current_user()
    create_notification(
        user_id=admin_user.id,
        title=f'User Created: {username}',
        message=f'New user {first_name} {last_name} created with auto-generated password: {auto_password}',
        notification_type='user_created'
    )
    
    flash(f'User created successfully.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/toggle-status', methods=['POST'])
@role_required('admin')
def toggle_user_status(user_id):
    """Toggle user active status"""
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    
    action = 'activate_user' if user.is_active else 'deactivate_user'
    log_audit_action(action, 'user', user.id, f'User {user.username} {"activated" if user.is_active else "deactivated"}')
    
    flash(f'User {"activated" if user.is_active else "deactivated"} successfully.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@role_required('admin')
def delete_user(user_id):
    """Delete user"""
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting admin user
    if user.role == 'admin':
        flash('Cannot delete admin user.', 'error')
        return redirect(url_for('admin_users'))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    log_audit_action('delete_user', 'user', user_id, f'Deleted user {username}')
    flash(f'User {username} deleted successfully.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/departments')
@role_required('admin')
def admin_departments():
    """Manage departments"""
    departments = Department.query.all()
    return render_template('admin/departments.html', departments=departments)

@app.route('/admin/departments/create', methods=['POST'])
@role_required('admin')
def create_department():
    """Create new department"""
    name = request.form['name']
    description = request.form.get('description', '')
    head_name = request.form.get('head_name', '')
    
    if Department.query.filter_by(name=name).first():
        flash('Department name already exists.', 'error')
        return redirect(url_for('admin_departments'))
    
    department = Department()
    department.name = name
    department.description = description
    department.head_name = head_name
    
    db.session.add(department)
    db.session.commit()
    
    # Add department units if provided
    unit_names = request.form.getlist('unit_names[]')
    unit_descriptions = request.form.getlist('unit_descriptions[]')
    
    for i, unit_name in enumerate(unit_names):
        if unit_name.strip():
            unit = DepartmentUnit()
            unit.name = unit_name.strip()
            unit.description = unit_descriptions[i].strip() if i < len(unit_descriptions) else ''
            unit.department_id = department.id
            db.session.add(unit)
    
    db.session.commit()
    
    log_audit_action('create_department', 'department', department.id, f'Created department {name}')
    flash('Department created successfully.', 'success')
    return redirect(url_for('admin_departments'))

@app.route('/admin/departments/<int:department_id>/delete', methods=['POST'])
@role_required('admin')
def delete_department(department_id):
    """Delete department"""
    department = Department.query.get_or_404(department_id)
    
    # Check if department has users
    if department.users:
        flash('Cannot delete department with assigned users.', 'error')
        return redirect(url_for('admin_departments'))
    
    department_name = department.name
    db.session.delete(department)
    db.session.commit()
    
    log_audit_action('delete_department', 'department', department_id, f'Deleted department {department_name}')
    flash(f'Department {department_name} deleted successfully.', 'success')
    return redirect(url_for('admin_departments'))

# Audit Routes
@app.route('/audits')
@login_required
def audit_list():
    """List audits based on user role"""
    user = get_current_user()
    
    # Filter audits based on role
    if user.role == 'admin':
        audits = Audit.query.all()
    elif user.role == 'auditor':
        audits = Audit.query.filter_by(auditor_id=user.id).all()
    elif user.role == 'auditee':
        audits = Audit.query.filter_by(auditee_id=user.id).all()
    elif user.role == 'supervisor':
        audits = Audit.query.filter_by(supervisor_id=user.id).all()
    else:
        audits = []
    
    return render_template('audits/list.html', audits=audits, user=user)

@app.route('/audits/create', methods=['GET', 'POST'])
@role_required('head_of_business_control')
def create_audit():
    """Create new audit with comprehensive workflow (Phase 1: Audit Assignment)"""
    if request.method == 'POST':
        # Basic audit information
        title = request.form['title']
        description = request.form.get('description', '')
        audit_type = request.form['audit_type']
        priority = request.form['priority']
        auditor_id = request.form['auditor_id']
        auditee_id = request.form.get('auditee_id') or None
        supervisor_id = request.form.get('supervisor_id') or None
        department_id = request.form.get('department_id') or None
        planned_start_date = datetime.strptime(request.form['planned_start_date'], '%Y-%m-%d').date()
        planned_end_date = datetime.strptime(request.form['planned_end_date'], '%Y-%m-%d').date()
        
        # Phase 1 - Audit scope and objectives
        audit_scope = request.form.get('audit_scope', '')
        audit_objectives = request.form.get('audit_objectives', '')
        audit_criteria = request.form.get('audit_criteria', '')
        resources_needed = request.form.get('resources_needed', '')
        
        # Generate reference number
        year = datetime.utcnow().year
        count = Audit.query.filter(extract('year', Audit.created_at) == year).count() + 1
        reference_number = f"AUD-{year}-{count:04d}"
        
        audit = Audit()
        audit.reference_number = reference_number
        audit.title = title
        audit.description = description
        audit.audit_type = audit_type
        audit.priority = priority
        audit.auditor_id = None  # Will be assigned after director approval
        audit.auditee_id = auditee_id
        audit.supervisor_id = get_current_user().id  # Head of Business Control creating the plan
        audit.director_id = 1  # Assuming director has ID 1, you can make this dynamic
        audit.department_id = department_id
        audit.planned_start_date = planned_start_date
        audit.planned_end_date = planned_end_date
        audit.audit_scope = audit_scope
        audit.audit_objectives = audit_objectives
        audit.audit_criteria = audit_criteria
        audit.resources_needed = resources_needed
        audit.status = 'plan_pending_director_approval'  # Head of Business Control submits plan to Director
        audit.created_by_id = get_current_user().id
        
        db.session.add(audit)
        db.session.commit()
        
        log_audit_action('create_audit', 'audit', audit.id, f'Created audit {reference_number} with scope and objectives')
        
        # Mark plan as submitted to Director
        audit.plan_submitted_at = datetime.utcnow()
        audit.audit_plan = f"""Audit Plan for {title}

SCOPE:
{audit_scope}

OBJECTIVES:
{audit_objectives}

CRITERIA:
{audit_criteria}

RESOURCES NEEDED:
{resources_needed}

This plan is submitted for Director approval."""
        
        # Create notification for Director (Phase 1 complete)
        notification_message = f"""New audit plan submitted for your approval: {title}

Plan Details:
- Reference: {reference_number}
- Submitted by: {user.full_name} (Head of Business Control)
- Type: {audit_type}
- Priority: {priority.upper()}
- Planned Start: {planned_start_date.strftime('%B %d, %Y')}
- Planned End: {planned_end_date.strftime('%B %d, %Y')}

Scope: {audit_scope[:100]}...
Objectives: {audit_objectives[:100]}...

Please review and approve this audit plan."""
        
        create_notification(
            director.id,
            'New Audit Plan - Director Approval Required',
            notification_message,
            'plan_approval_required',
            'audit',
            audit.id
        )
        
        # Notify auditee if assigned
        if auditee_id:
            auditee_message = f"""You have been designated as the primary auditee for audit: {title}

Reference: {reference_number}
Auditor: {User.query.get(auditor_id).full_name}
Planned Period: {planned_start_date.strftime('%B %d, %Y')} - {planned_end_date.strftime('%B %d, %Y')}

The auditor will contact you with document requests and coordination details."""
            
            create_notification(
                auditee_id,
                'Audit Assignment Notification',
                auditee_message,
                'audit_assigned',
                'audit',
                audit.id
            )
        
        flash(f'Audit plan {reference_number} submitted to Director for approval!', 'success')
        return redirect(url_for('head_of_business_control_dashboard'))
    
    # GET request - show comprehensive form
    auditors = User.query.filter_by(role='auditor', is_active=True).all()
    auditees = User.query.filter_by(role='auditee', is_active=True).all()
    supervisors = User.query.filter_by(role='supervisor', is_active=True).all()
    departments = Department.query.filter_by(is_active=True).all()
    
    return render_template('audits/create_comprehensive.html',
                         auditors=auditors,
                         auditees=auditees,
                         supervisors=supervisors,
                         departments=departments)


# New Workflow Routes for Director and Head of Business Control

@app.route('/director/approve-plan/<int:audit_id>', methods=['GET', 'POST'])
@role_required('director')
def director_approve_plan(audit_id):
    """Director approves or rejects audit plans"""
    audit = Audit.query.get_or_404(audit_id)
    
    # Verify this audit is pending director approval
    if audit.status != 'plan_pending_director_approval':
        flash('This audit plan is not pending director approval.', 'error')
        return redirect(url_for('director_dashboard'))
    
    if request.method == 'POST':
        decision = request.form.get('decision')
        director_feedback = request.form.get('director_feedback', '').strip()
        user = get_current_user()
        
        if decision == 'approve':
            # Approve the plan
            audit.status = 'pending_auditor_assignment'
            audit.director_approved_at = datetime.utcnow()
            audit.director_feedback = director_feedback if director_feedback else 'Plan approved by Director'
            
            db.session.commit()
            
            # Notify Head of Business Control
            notification_message = f"""Audit plan approved: {audit.title}

Your audit plan "{audit.title}" has been approved by the Director.

Plan Details:
- Reference: {audit.reference_number}
- Approved: {datetime.utcnow().strftime('%B %d, %Y at %I:%M %p')}
- Director Feedback: {director_feedback if director_feedback else 'No additional feedback provided'}

Next Step: Please assign an auditor to this approved plan."""
            
            head_of_business_control = User.query.get(audit.supervisor_id)
            if head_of_business_control:
                create_notification(
                    head_of_business_control.id,
                    'Audit Plan Approved - Assign Auditor',
                    notification_message,
                    'plan_approved',
                    'audit',
                    audit.id
                )
            
            log_audit_action('approve_plan', 'audit', audit.id, f'Director approved audit plan {audit.reference_number}')
            flash(f'Audit plan {audit.reference_number} approved successfully!', 'success')
            
        elif decision == 'reject':
            # Reject the plan
            audit.status = 'plan_changes_requested'
            audit.director_feedback = director_feedback if director_feedback else 'Changes requested by Director'
            
            db.session.commit()
            
            # Notify Head of Business Control
            notification_message = f"""Changes requested for audit plan: {audit.title}

The Director has requested changes to your audit plan "{audit.title}".

Plan Details:
- Reference: {audit.reference_number}
- Status: Changes Requested
- Director Feedback: {director_feedback if director_feedback else 'Please review and revise the plan'}

Next Step: Please revise the audit plan and resubmit for approval."""
            
            head_of_business_control = User.query.get(audit.supervisor_id)
            if head_of_business_control:
                create_notification(
                    head_of_business_control.id,
                    'Audit Plan - Changes Requested',
                    notification_message,
                    'plan_changes_requested',
                    'audit',
                    audit.id
                )
            
            log_audit_action('reject_plan', 'audit', audit.id, f'Director requested changes for audit plan {audit.reference_number}')
            flash(f'Changes requested for audit plan {audit.reference_number}.', 'warning')
        
        return redirect(url_for('director_dashboard'))
    
    # GET request - show plan review page
    return render_template('director/review_plan.html', audit=audit)


@app.route('/head-of-business-control/assign-auditor/<int:audit_id>', methods=['GET', 'POST'])
@role_required('head_of_business_control')
def head_of_business_control_assign_auditor(audit_id):
    """Head of Business Control assigns auditor to approved plans"""
    audit = Audit.query.get_or_404(audit_id)
    
    # Verify this audit is ready for auditor assignment
    if audit.status != 'pending_auditor_assignment' or not audit.director_approved_at:
        flash('This audit is not ready for auditor assignment.', 'error')
        return redirect(url_for('head_of_business_control_dashboard'))
    
    # Verify user has permission to assign auditors for this audit
    user = get_current_user()
    if audit.supervisor_id != user.id:
        flash('You do not have permission to assign auditors for this audit.', 'error')
        return redirect(url_for('head_of_business_control_dashboard'))
    
    if request.method == 'POST':
        auditor_id = request.form.get('auditor_id')
        assignment_notes = request.form.get('assignment_notes', '').strip()
        
        if not auditor_id:
            flash('Please select an auditor.', 'error')
            return redirect(request.url)
        
        auditor = User.query.get(auditor_id)
        if not auditor or auditor.role != 'auditor':
            flash('Invalid auditor selected.', 'error')
            return redirect(request.url)
        
        # Assign auditor
        audit.auditor_id = auditor_id
        audit.status = 'auditor_assigned'
        audit.auditor_assigned_at = datetime.utcnow()
        audit.assignment_notes = assignment_notes
        
        db.session.commit()
        
        # Notify auditor
        notification_message = f"""You have been assigned to audit: {audit.title}

Audit Assignment Details:
- Reference: {audit.reference_number}
- Assigned by: {user.full_name} (Head of Business Control)
- Type: {audit.audit_type.replace('_', ' ').title()}
- Priority: {audit.priority.upper()}
- Planned Start: {audit.planned_start_date.strftime('%B %d, %Y') if audit.planned_start_date else 'TBD'}
- Planned End: {audit.planned_end_date.strftime('%B %d, %Y') if audit.planned_end_date else 'TBD'}

Director Approval: {audit.director_approved_at.strftime('%B %d, %Y') if audit.director_approved_at else 'N/A'}

Assignment Notes: {assignment_notes if assignment_notes else 'No additional notes provided'}

Please review the audit plan and begin your audit activities."""
        
        create_notification(
            auditor.id,
            'New Audit Assignment - Action Required',
            notification_message,
            'audit_assigned',
            'audit',
            audit.id
        )
        
        # Notify auditee
        if audit.auditee:
            auditee_message = f"""Audit notification: {audit.title}

You have been assigned as the auditee for the audit "{audit.title}".

Audit Details:
- Reference: {audit.reference_number}
- Auditor: {auditor.full_name}
- Type: {audit.audit_type.replace('_', ' ').title()}
- Priority: {audit.priority.upper()}
- Planned Timeline: {audit.planned_start_date.strftime('%B %d, %Y') if audit.planned_start_date else 'TBD'} - {audit.planned_end_date.strftime('%B %d, %Y') if audit.planned_end_date else 'TBD'}

Please prepare for the upcoming audit and coordinate with the assigned auditor."""
            
            create_notification(
                audit.auditee.id,
                'Audit Assignment - Auditee Notification',
                auditee_message,
                'auditee_assigned',
                'audit',
                audit.id
            )
        
        log_audit_action('assign_auditor', 'audit', audit.id, f'Head of Business Control assigned auditor {auditor.full_name} to audit {audit.reference_number}')
        flash(f'Auditor {auditor.full_name} assigned to audit {audit.reference_number} successfully!', 'success')
        return redirect(url_for('head_of_business_control_dashboard'))
    
    # GET request - show auditor assignment page
    available_auditors = User.query.filter_by(role='auditor', is_active=True).all()
    return render_template('head_of_business_control/assign_auditor.html', audit=audit, available_auditors=available_auditors)

@app.route('/audits/<int:audit_id>')
@login_required
def audit_detail(audit_id):
    """View audit details"""
    audit = Audit.query.get_or_404(audit_id)
    user = get_current_user()
    
    # Check access permissions
    if user.role not in ['admin'] and user.id not in [audit.auditor_id, audit.auditee_id, audit.supervisor_id]:
        flash('You do not have permission to view this audit.', 'error')
        return redirect(url_for('audit_list'))
    
    return render_template('audits/execute.html', audit=audit, user=user)

@app.route('/audits/<int:audit_id>/findings')
@login_required
def audit_findings(audit_id):
    """View audit findings"""
    audit = Audit.query.get_or_404(audit_id)
    user = get_current_user()
    
    # Check access permissions
    if user.role not in ['admin'] and user.id not in [audit.auditor_id, audit.auditee_id, audit.supervisor_id]:
        flash('You do not have permission to view this audit.', 'error')
        return redirect(url_for('audit_list'))
    
    findings = Finding.query.filter_by(audit_id=audit_id).all()
    return render_template('audits/findings.html', audit=audit, findings=findings, user=user)

@app.route('/findings/<int:finding_id>/actions')
@login_required
def finding_actions(finding_id):
    """View corrective actions for a finding"""
    finding = Finding.query.get_or_404(finding_id)
    user = get_current_user()
    
    # Check access permissions
    audit = finding.audit
    if user.role not in ['admin'] and user.id not in [audit.auditor_id, audit.auditee_id, audit.supervisor_id, finding.assigned_to_id]:
        flash('You do not have permission to view this finding.', 'error')
        return redirect(url_for('audit_list'))
    
    actions = CorrectiveAction.query.filter_by(finding_id=finding_id).all()
    users = User.query.filter_by(is_active=True).all()
    
    return render_template('audits/actions.html', finding=finding, actions=actions, users=users, user=user)

@app.route('/api/notifications/<int:notification_id>/mark-read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark notification as read"""
    notification = Notification.query.get_or_404(notification_id)
    user = get_current_user()
    
    if notification.user_id != user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    notification.is_read = True
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/notifications/count')
@login_required
def get_notification_count():
    """Get unread notification count for current user"""
    user = get_current_user()
    count = Notification.query.filter_by(user_id=user.id, is_read=False).count()
    return jsonify({'count': count})

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('base.html', error_message='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('base.html', error_message='Internal server error'), 500

# Auditor workflow routes
@app.route('/auditor/audits')
@role_required('auditor')
def auditor_audits():
    """Auditor's audit list view"""
    user = get_current_user()
    audits = Audit.query.filter_by(auditor_id=user.id).order_by(Audit.created_at.desc()).all()
    
    return render_template('auditor/audits.html', audits=audits)

@app.route('/auditor/audit/<int:audit_id>')
@role_required('auditor')
def auditor_audit_detail(audit_id):
    """Auditor's detailed audit view"""
    user = get_current_user()
    audit = Audit.query.filter_by(id=audit_id, auditor_id=user.id).first_or_404()
    
    findings = Finding.query.filter_by(audit_id=audit_id).all()
    # Get checklist items through template relationship
    checklist_items = []
    if hasattr(audit, 'template') and audit.template:
        checklist_items = audit.template.checklist_items
    evidence = EvidenceFile.query.filter_by(audit_id=audit_id).all()
    
    return render_template('auditor/audit_detail_comprehensive.html', 
                         audit=audit, findings=findings, 
                         checklist_items=checklist_items, evidence=evidence)

# Phase 2: Auditor Preparation Routes
@app.route('/auditor/audit/<int:audit_id>/acknowledge', methods=['POST'])
@role_required('auditor')
def auditor_acknowledge_audit(audit_id):
    """Phase 2: Auditor acknowledges the audit assignment"""
    user = get_current_user()
    audit = Audit.query.filter_by(id=audit_id, auditor_id=user.id).first_or_404()
    
    if audit.status != 'assigned':
        flash('This audit has already been acknowledged or is in a different state.', 'warning')
        return redirect(url_for('auditor_audit_detail', audit_id=audit_id))
    
    # Acknowledge the audit
    audit.auditor_acknowledged_at = datetime.utcnow()
    audit.status = 'acknowledged'
    db.session.commit()
    
    log_audit_action('acknowledge_audit', 'audit', audit.id, f'Auditor acknowledged audit {audit.reference_number}')
    
    # Notify supervisor of acknowledgment
    if audit.supervisor_id:
        create_notification(
            audit.supervisor_id,
            'Audit Acknowledged by Auditor',
            f'Auditor {user.full_name} has acknowledged audit {audit.reference_number} - {audit.title}. They can now proceed with preparation.',
            'audit_acknowledged',
            'audit',
            audit.id
        )
    
    flash('Audit acknowledged successfully. You can now begin your preparation and planning.', 'success')
    return redirect(url_for('auditor_prepare_plan', audit_id=audit_id))

@app.route('/auditor/audit/<int:audit_id>/prepare')
@role_required('auditor')
def auditor_prepare_plan(audit_id):
    """Phase 2: Auditor preparation and planning interface"""
    user = get_current_user()
    audit = Audit.query.filter_by(id=audit_id, auditor_id=user.id).first_or_404()
    
    if audit.status not in ['acknowledged', 'plan_submitted']:
        flash('You must acknowledge the audit first before preparing the plan.', 'warning')
        return redirect(url_for('auditor_audit_detail', audit_id=audit_id))
    
    # Get previous audits in same department for reference
    previous_audits = []
    if audit.department_id:
        previous_audits = Audit.query.filter(
            Audit.department_id == audit.department_id,
            Audit.id != audit.id,
            Audit.status.in_(['closed', 'review'])
        ).order_by(Audit.created_at.desc()).limit(5).all()
    
    return render_template('auditor/prepare_plan.html', audit=audit, previous_audits=previous_audits)

@app.route('/auditor/audit/<int:audit_id>/submit-plan', methods=['POST'])
@role_required('auditor')
def auditor_submit_plan(audit_id):
    """Phase 2: Auditor submits prepared audit plan"""
    user = get_current_user()
    audit = Audit.query.filter_by(id=audit_id, auditor_id=user.id).first_or_404()
    
    if audit.status not in ['acknowledged', 'plan_submitted']:
        flash('Invalid audit status for plan submission.', 'error')
        return redirect(url_for('auditor_audit_detail', audit_id=audit_id))
    
    # Extract plan details
    audit_plan = request.form['audit_plan']
    audit_methodology = request.form['audit_methodology']
    audit_checklist = request.form['audit_checklist']
    data_request_list = request.form.get('data_request_list', '')
    
    # Validate required fields
    if not audit_plan or not audit_methodology:
        flash('Audit plan and methodology are required.', 'error')
        return redirect(url_for('auditor_prepare_plan', audit_id=audit_id))
    
    # Update audit with plan details
    audit.audit_plan = audit_plan
    audit.audit_methodology = audit_methodology
    audit.audit_checklist = audit_checklist
    audit.data_request_list = data_request_list
    audit.plan_submitted_at = datetime.utcnow()
    audit.status = 'plan_submitted'
    
    db.session.commit()
    
    log_audit_action('submit_audit_plan', 'audit', audit.id, f'Auditor submitted plan for audit {audit.reference_number}')
    
    # Notify supervisor for approval
    if audit.supervisor_id:
        create_notification(
            audit.supervisor_id,
            'Audit Plan Ready for Review',
            f'Auditor {user.full_name} has submitted the audit plan for {audit.reference_number} - {audit.title}. Please review and approve.',
            'plan_approval_needed',
            'audit',
            audit.id
        )
    
    # Create document requests for auditee if specified
    if data_request_list and audit.auditee_id:
        document_requests = data_request_list.split('\n')
        for req in document_requests:
            if req.strip():
                doc_request = AuditDocumentRequest()
                doc_request.audit_id = audit.id
                doc_request.requested_by_id = user.id
                doc_request.auditee_id = audit.auditee_id
                doc_request.document_type = 'general'
                doc_request.document_description = req.strip()
                doc_request.priority = audit.priority
                doc_request.due_date = audit.planned_start_date
                db.session.add(doc_request)
        
        db.session.commit()
        
        # Notify auditee of document requests
        create_notification(
            audit.auditee_id,
            'Document Requests for Upcoming Audit',
            f'The auditor has requested documents for audit {audit.reference_number} - {audit.title}. Please check your document requests and respond accordingly.',
            'documents_requested',
            'audit',
            audit.id
        )
    
    flash('Audit plan submitted successfully and sent for supervisor approval. Document requests have been sent to the auditee.', 'success')
    return redirect(url_for('auditor_audit_detail', audit_id=audit_id))

# Phase 3: Supervisor Approval Routes
@app.route('/supervisor/audit/<int:audit_id>/review-plan')
@role_required('supervisor')
def supervisor_review_plan(audit_id):
    """Phase 3: Supervisor reviews auditor's submitted plan"""
    user = get_current_user()
    audit = Audit.query.filter_by(id=audit_id, supervisor_id=user.id).first_or_404()
    
    if audit.status != 'plan_submitted':
        flash('This audit plan has not been submitted or is in a different state.', 'warning')
        return redirect(url_for('supervisor_audit_detail', audit_id=audit_id))
    
    return render_template('supervisor/review_plan.html', audit=audit)

@app.route('/supervisor/audit/<int:audit_id>/approve-plan', methods=['POST'])
@role_required('supervisor')
def supervisor_approve_plan(audit_id):
    """Phase 3: Supervisor approves or requests changes to audit plan"""
    user = get_current_user()
    audit = Audit.query.filter_by(id=audit_id, supervisor_id=user.id).first_or_404()
    
    if audit.status != 'plan_submitted':
        flash('This audit plan cannot be approved at this time.', 'error')
        return redirect(url_for('supervisor_audit_detail', audit_id=audit_id))
    
    action = request.form['action']  # approve or request_changes
    supervisor_feedback = request.form.get('supervisor_feedback', '')
    
    if action == 'approve':
        audit.plan_approved_at = datetime.utcnow()
        audit.status = 'plan_approved'
        audit.supervisor_feedback = supervisor_feedback
        
        db.session.commit()
        
        log_audit_action('approve_audit_plan', 'audit', audit.id, f'Supervisor approved plan for audit {audit.reference_number}')
        
        # Notify auditor of approval
        create_notification(
            audit.auditor_id,
            'Audit Plan Approved - Ready to Begin',
            f'Your audit plan for {audit.reference_number} - {audit.title} has been approved by the supervisor. You may now coordinate with the auditee and begin fieldwork.',
            'plan_approved',
            'audit',
            audit.id
        )
        
        flash('Audit plan approved successfully. Auditor has been notified and can begin fieldwork.', 'success')
        
    else:  # request_changes
        audit.status = 'acknowledged'  # Back to preparation phase
        audit.supervisor_feedback = supervisor_feedback
        
        db.session.commit()
        
        log_audit_action('request_plan_changes', 'audit', audit.id, f'Supervisor requested changes to plan for audit {audit.reference_number}')
        
        # Notify auditor of requested changes
        create_notification(
            audit.auditor_id,
            'Audit Plan Requires Revision',
            f'Your audit plan for {audit.reference_number} - {audit.title} requires revision. Please review the supervisor feedback and resubmit.',
            'plan_revision_requested',
            'audit',
            audit.id
        )
        
        flash('Feedback provided to auditor. They will revise and resubmit the plan.', 'info')
    
    return redirect(url_for('supervisor_audit_detail', audit_id=audit_id))

# Auditee Coordination Routes
@app.route('/auditee/document-requests')
@role_required('auditee')
def auditee_document_requests():
    """View all document requests for auditee"""
    user = get_current_user()
    document_requests = AuditDocumentRequest.query.filter_by(auditee_id=user.id).order_by(
        AuditDocumentRequest.created_at.desc()
    ).all()
    
    return render_template('auditee/document_requests.html', document_requests=document_requests)

@app.route('/auditee/document-request/<int:request_id>/respond', methods=['POST'])
@role_required('auditee')
def auditee_respond_document_request(request_id):
    """Auditee responds to document request"""
    user = get_current_user()
    doc_request = AuditDocumentRequest.query.filter_by(id=request_id, auditee_id=user.id).first_or_404()
    
    response_type = request.form['response_type']  # provided, not_available
    auditee_response = request.form['auditee_response']
    
    doc_request.status = response_type
    doc_request.auditee_response = auditee_response
    doc_request.response_date = datetime.utcnow().date()
    
    db.session.commit()
    
    log_audit_action('respond_document_request', 'audit_document_request', doc_request.id, 
                     f'Auditee responded to document request: {response_type}')
    
    # Notify auditor of response
    create_notification(
        doc_request.requested_by_id,
        'Document Request Response Received',
        f'Auditee has responded to your document request for {doc_request.document_type}: {response_type.replace("_", " ").title()}',
        'document_response',
        'audit',
        doc_request.audit_id
    )
    
    flash('Response submitted successfully. The auditor has been notified.', 'success')
    return redirect(url_for('auditee_document_requests'))

@app.route('/auditee/audit/<int:audit_id>/acknowledge', methods=['POST'])
@role_required('auditee')
def auditee_acknowledge_audit(audit_id):
    """Auditee acknowledges audit notification and coordination"""
    user = get_current_user()
    audit = Audit.query.filter_by(id=audit_id, auditee_id=user.id).first_or_404()
    
    audit.auditee_acknowledged_at = datetime.utcnow()
    access_arrangements = request.form.get('access_arrangements', 'off') == 'on'
    audit.access_arrangements_completed = access_arrangements
    
    db.session.commit()
    
    log_audit_action('acknowledge_audit_auditee', 'audit', audit.id, f'Auditee acknowledged audit {audit.reference_number}')
    
    # Notify auditor and supervisor
    notification_message = f'Auditee {user.full_name} has acknowledged audit {audit.reference_number} - {audit.title} and confirmed access arrangements.'
    
    if audit.auditor_id:
        create_notification(
            audit.auditor_id,
            'Auditee Ready for Audit',
            notification_message,
            'auditee_ready',
            'audit',
            audit.id
        )
    
    if audit.supervisor_id:
        create_notification(
            audit.supervisor_id,
            'Audit Coordination Complete',
            notification_message,
            'coordination_complete',
            'audit',
            audit.id
        )
    
    flash('Audit acknowledged successfully. Access arrangements confirmed.', 'success')
    return redirect(url_for('auditee_dashboard'))

@app.route('/auditor/audit/<int:audit_id>/start', methods=['POST'])
@role_required('auditor')
def auditor_start_audit(audit_id):
    """Start audit execution"""
    user = get_current_user()
    audit = Audit.query.filter_by(id=audit_id, auditor_id=user.id).first_or_404()
    
    if audit.status == 'draft':
        audit.status = 'in_progress'
        audit.actual_start_date = datetime.utcnow().date()
        db.session.commit()
        
        log_audit_action('start_audit', 'audit', audit.id, f'Started audit {audit.id}')
        flash('Audit started successfully!', 'success')
    
    return redirect(url_for('auditor_audit_detail', audit_id=audit_id))

@app.route('/auditor/findings')
@role_required('auditor')
def auditor_findings():
    """Auditor's findings management"""
    user = get_current_user()
    findings = Finding.query.join(Audit).filter(Audit.auditor_id == user.id).order_by(Finding.created_at.desc()).all()
    
    return render_template('auditor/findings.html', findings=findings)

@app.route('/auditor/reports')
@role_required('auditor')
def auditor_reports():
    """Auditor's reports view"""
    user = get_current_user()
    audits = Audit.query.filter_by(auditor_id=user.id).all()
    
    return render_template('auditor/reports.html', audits=audits)

@app.route('/auditor/finding/<int:finding_id>')
@role_required('auditor')
def auditor_finding_detail(finding_id):
    """Auditor's detailed finding view"""
    user = get_current_user()
    finding = Finding.query.join(Audit).filter(
        Finding.id == finding_id, 
        Audit.auditor_id == user.id
    ).first_or_404()
    
    corrective_actions = CorrectiveAction.query.filter_by(finding_id=finding_id).all()
    
    return render_template('auditor/finding_detail.html', 
                         finding=finding, corrective_actions=corrective_actions)

@app.route('/auditor/create-finding/<int:audit_id>', methods=['GET', 'POST'])
@role_required('auditor')
def auditor_create_finding(audit_id):
    """Create new finding during audit"""
    user = get_current_user()
    audit = Audit.query.filter_by(id=audit_id, auditor_id=user.id).first_or_404()
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        severity = request.form['severity']
        category = request.form['category']
        risk_assessment = request.form.get('risk_assessment', '')
        recommendation = request.form.get('recommendation', '')
        auditee_id = request.form.get('auditee_id')
        due_date = datetime.strptime(request.form['due_date'], '%Y-%m-%d').date() if request.form.get('due_date') else None
        
        # Generate finding reference number
        year = datetime.utcnow().year
        count = Finding.query.filter(extract('year', Finding.created_at) == year).count() + 1
        reference_number = f"FND-{year}-{count:04d}"
        
        finding = Finding()
        finding.audit_id = audit_id
        finding.title = title
        finding.description = description
        finding.severity = severity
        finding.category = category
        finding.risk_assessment = risk_assessment
        finding.recommendation = recommendation
        finding.auditee_id = auditee_id
        finding.identified_by_id = user.id
        finding.due_date = due_date
        finding.status = 'open'
        
        db.session.add(finding)
        db.session.commit()
        
        log_audit_action('create_finding', 'finding', finding.id, f'Created finding {reference_number}')
        
        # Notify auditee if assigned
        if auditee_id:
            create_notification(
                auditee_id,
                'New Finding Assigned',
                f'A new finding has been assigned to you: {title}',
                'finding_assigned',
                'finding',
                finding.id
            )
        
        flash('Finding created successfully!', 'success')
        return redirect(url_for('auditor_audit_detail', audit_id=audit_id))
    
    auditees = User.query.filter_by(role='auditee', is_active=True).all()
    return render_template('auditor/create_finding.html', audit=audit, auditees=auditees)

# Auditee workflow routes
@app.route('/auditee/findings')
@role_required('auditee')
def auditee_findings():
    """Auditee's findings view"""
    user = get_current_user()
    findings = Finding.query.filter_by(auditee_id=user.id).order_by(Finding.created_at.desc()).all()
    
    return render_template('auditee/findings.html', findings=findings)

@app.route('/auditee/finding/<int:finding_id>')
@role_required('auditee')
def auditee_finding_detail(finding_id):
    """Auditee's detailed finding view"""
    user = get_current_user()
    finding = Finding.query.filter_by(id=finding_id, auditee_id=user.id).first_or_404()
    
    corrective_actions = CorrectiveAction.query.filter_by(finding_id=finding_id).all()
    evidence = EvidenceFile.query.filter_by(finding_id=finding_id).all()
    
    return render_template('auditee/finding_detail.html', 
                         finding=finding, corrective_actions=corrective_actions, evidence=evidence)

@app.route('/auditee/corrective-actions')
@role_required('auditee')
def auditee_corrective_actions():
    """Auditee's corrective actions view"""
    user = get_current_user()
    actions = CorrectiveAction.query.join(Finding).filter(
        Finding.auditee_id == user.id
    ).order_by(CorrectiveAction.created_at.desc()).all()
    
    return render_template('auditee/corrective_actions.html', actions=actions)

@app.route('/auditee/create-corrective-action/<int:finding_id>', methods=['GET', 'POST'])
@role_required('auditee')
def auditee_create_corrective_action(finding_id):
    """Create corrective action for finding"""
    user = get_current_user()
    finding = Finding.query.filter_by(id=finding_id, auditee_id=user.id).first_or_404()
    
    if request.method == 'POST':
        description = request.form['description']
        action_plan = request.form['action_plan']
        responsible_person = request.form['responsible_person']
        target_completion_date = datetime.strptime(request.form['target_completion_date'], '%Y-%m-%d').date()
        
        action = CorrectiveAction()
        action.action_description = description
        action.responsible_person_id = responsible_person if responsible_person else user.id
        action.planned_completion_date = target_completion_date
        action.finding_id = finding_id
        action.created_by_id = user.id
        
        db.session.add(action)
        
        # Update finding status
        finding.status = 'in_progress'
        db.session.commit()
        
        log_audit_action('create_corrective_action', 'corrective_action', action.id, 
                        f'Created corrective action for finding {finding.id}')
        
        # Notify auditor
        create_notification(
            finding.audit.auditor_id,
            'Corrective Action Proposed',
            f'A corrective action has been proposed for finding: {finding.title}',
            'corrective_action_proposed',
            'corrective_action',
            action.id
        )
        
        flash('Corrective action created successfully!', 'success')
        return redirect(url_for('auditee_finding_detail', finding_id=finding_id))
    
    return render_template('auditee/create_corrective_action.html', finding=finding)

@app.route('/auditee/evidence')
@role_required('auditee')
def auditee_evidence():
    """Auditee's evidence management"""
    user = get_current_user()
    evidence = EvidenceFile.query.join(Finding).filter(
        Finding.auditee_id == user.id
    ).order_by(EvidenceFile.uploaded_at.desc()).all()
    
    return render_template('auditee/evidence.html', evidence=evidence)

@app.route('/auditee/upload-evidence/<int:finding_id>', methods=['GET', 'POST'])
@role_required('auditee')
def auditee_upload_evidence(finding_id):
    """Upload evidence for finding"""
    user = get_current_user()
    finding = Finding.query.filter_by(id=finding_id, auditee_id=user.id).first_or_404()
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description', '')
        evidence_type = request.form['evidence_type']
        
        # Handle file upload
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename:
                file_info = save_uploaded_file(file, 'uploads/evidence')
                if file_info:
                    evidence = EvidenceFile()
                    evidence.original_filename = title
                    evidence.description = description  
                    evidence.filename = file_info['filename']
                    evidence.file_path = file_info['file_path']
                    evidence.file_size = file_info['file_size']
                    evidence.file_type = file_info['file_type']
                    evidence.finding_id = finding_id
                    evidence.uploaded_by_id = user.id
                    
                    db.session.add(evidence)
                    db.session.commit()
                    
                    log_audit_action('upload_evidence', 'evidence', evidence.id, 
                                   f'Uploaded evidence for finding {finding.id}')
                    
                    # Notify auditor
                    create_notification(
                        finding.audit.auditor_id,
                        'Evidence Uploaded',
                        f'Evidence has been uploaded for finding: {finding.title}',
                        'evidence_uploaded',
                        'evidence',
                        evidence.id
                    )
                    
                    flash('Evidence uploaded successfully!', 'success')
                    return redirect(url_for('auditee_finding_detail', finding_id=finding_id))
                else:
                    flash('Failed to upload file. Please try again.', 'error')
            else:
                flash('Please select a file to upload.', 'error')
    
    return render_template('auditee/upload_evidence.html', finding=finding)

@app.route('/auditee/reports')
@role_required('auditee')
def auditee_reports():
    """Auditee's reports view"""
    user = get_current_user()
    findings = Finding.query.filter_by(auditee_id=user.id).all()
    
    return render_template('auditee/reports.html', findings=findings)

@app.route('/supervisor/reports')
@role_required('supervisor')
def supervisor_reports():
    """Supervisor's reports view"""
    user = get_current_user()
    audits = Audit.query.filter_by(supervisor_id=user.id).all()
    
    return render_template('supervisor/reports.html', audits=audits)

# Supervisor evidence review functionality
@app.route('/supervisor/evidence/<int:evidence_id>')
@role_required('supervisor')
def supervisor_review_evidence(evidence_id):
    """Supervisor reviews evidence"""
    evidence = EvidenceFile.query.get_or_404(evidence_id)
    user = get_current_user()
    
    # Check if supervisor has access to this evidence through audit supervision  
    if not evidence.finding or not evidence.finding.audit or evidence.finding.audit.supervisor_id != user.id:
        flash('You do not have permission to review this evidence.', 'error')
        return redirect(url_for('supervisor_dashboard'))
    
    return render_template('supervisor/evidence_review.html', evidence=evidence)

@app.route('/supervisor/evidence/<int:evidence_id>/comment', methods=['POST'])
@role_required('supervisor')
def supervisor_comment_evidence(evidence_id):
    """Supervisor adds comment to evidence"""
    evidence = EvidenceFile.query.get_or_404(evidence_id)
    user = get_current_user()
    
    # Check permission
    if not evidence.finding or not evidence.finding.audit or evidence.finding.audit.supervisor_id != user.id:
        flash('You do not have permission to comment on this evidence.', 'error')
        return redirect(url_for('supervisor_dashboard'))
    
    comment = request.form.get('comment')
    status = request.form.get('status', 'reviewed')
    
    if comment:
        # Add supervisor comment to evidence
        evidence.supervisor_comment = comment
        evidence.supervisor_status = status
        evidence.reviewed_by_id = user.id
        evidence.reviewed_at = datetime.utcnow()
        
        db.session.commit()
        
        # Notify auditee
        create_notification(
            evidence.finding.auditee_id,
            'Evidence Reviewed',
            f'Your evidence for "{evidence.finding.title}" has been reviewed by supervisor.',
            'evidence_reviewed',
            'evidence',
            evidence.id
        )
        
        flash('Comment added successfully!', 'success')
    
    return redirect(url_for('supervisor_review_evidence', evidence_id=evidence_id))

@app.route('/supervisor/evidence/<int:evidence_id>/download')
@role_required('supervisor')
def supervisor_download_evidence(evidence_id):
    """Supervisor downloads evidence file"""
    evidence = EvidenceFile.query.get_or_404(evidence_id)
    user = get_current_user()
    
    # Check permission
    if not evidence.finding or not evidence.finding.audit or evidence.finding.audit.supervisor_id != user.id:
        flash('You do not have permission to download this evidence.', 'error')
        return redirect(url_for('supervisor_dashboard'))
    
    try:
        from flask import send_file
        import os
        
        file_path = evidence.file_path
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True, download_name=evidence.original_filename)
        else:
            flash('File not found.', 'error')
    except Exception as e:
        flash('Error downloading file.', 'error')
    
    return redirect(url_for('supervisor_review_evidence', evidence_id=evidence_id))

# Note: Finding detail routes are defined elsewhere in the file

# Admin routes for audit management
@app.route('/admin/audit/<int:audit_id>')
@role_required('admin')
def admin_audit_detail(audit_id):
    """Admin audit detail view"""
    audit = Audit.query.get_or_404(audit_id)
    findings = Finding.query.filter_by(audit_id=audit_id).all()
    
    return render_template('audits/execute.html', audit=audit, findings=findings, user=get_current_user())

@app.route('/admin/audit/<int:audit_id>/edit', methods=['GET', 'POST'])
@role_required('admin')
def admin_edit_audit(audit_id):
    """Edit audit"""
    audit = Audit.query.get_or_404(audit_id)
    
    if request.method == 'POST':
        audit.title = request.form['title']
        audit.description = request.form['description']
        audit.department_id = request.form['department_id']
        audit.auditor_id = request.form.get('auditor_id')
        audit.auditee_id = request.form.get('auditee_id')
        audit.supervisor_id = request.form.get('supervisor_id')
        audit.audit_type = request.form['audit_type']
        audit.planned_start_date = datetime.strptime(request.form['planned_start_date'], '%Y-%m-%d').date()
        audit.planned_end_date = datetime.strptime(request.form['planned_end_date'], '%Y-%m-%d').date()
        
        db.session.commit()
        
        log_audit_action('edit_audit', 'audit', audit.id, f'Edited audit {audit.reference_number}')
        flash('Audit updated successfully!', 'success')
        return redirect(url_for('admin_audit_detail', audit_id=audit_id))
    
    departments = Department.query.filter_by(is_active=True).all()
    auditors = User.query.filter_by(role='auditor', is_active=True).all()
    auditees = User.query.filter_by(role='auditee', is_active=True).all()
    supervisors = User.query.filter_by(role='supervisor', is_active=True).all()
    
    return render_template('audits/create.html', audit=audit, departments=departments, 
                         auditors=auditors, auditees=auditees, supervisors=supervisors, edit_mode=True)

# Supervisor audit detail route
@app.route('/supervisor/audit/<int:audit_id>')
@role_required('supervisor')
def supervisor_audit_detail(audit_id):
    """Supervisor audit detail view"""
    user = get_current_user()
    audit = Audit.query.filter_by(id=audit_id, supervisor_id=user.id).first_or_404()
    findings = Finding.query.filter_by(audit_id=audit_id).all()
    
    return render_template('audits/execute.html', audit=audit, findings=findings, user=user)

# Auditee audit detail route
@app.route('/auditee/audit/<int:audit_id>')
@role_required('auditee')
def auditee_audit_detail(audit_id):
    """Auditee audit detail view"""
    user = get_current_user()
    audit = Audit.query.filter_by(id=audit_id, auditee_id=user.id).first_or_404()
    findings = Finding.query.filter_by(audit_id=audit_id).all()
    
    return render_template('audits/execute.html', audit=audit, findings=findings, user=user)

# Admin notification management
@app.route('/admin/notifications')
@role_required('admin')
def admin_notifications():
    """Admin view all notifications"""
    notifications = Notification.query.order_by(Notification.created_at.desc()).all()
    return render_template('admin/notifications.html', notifications=notifications)

@app.route('/admin/notification/<int:notification_id>/delete', methods=['POST'])
@role_required('admin')
def admin_delete_notification(notification_id):
    """Admin delete notification"""
    notification = Notification.query.get_or_404(notification_id)
    user = get_current_user()
    
    # Log the deletion
    log_audit_action('delete_notification', 'notification', notification_id, 
                   f'Deleted notification: {notification.title}')
    
    db.session.delete(notification)
    db.session.commit()
    
    flash('Notification deleted successfully!', 'success')
    return redirect(url_for('admin_notifications'))

@app.route('/admin/notifications/delete-all', methods=['POST'])
@role_required('admin')
def admin_delete_all_notifications():
    """Admin delete all notifications"""
    user = get_current_user()
    count = Notification.query.count()
    
    Notification.query.delete()
    db.session.commit()
    
    log_audit_action('delete_all_notifications', 'notification', None, 
                   f'Deleted all {count} notifications')
    
    flash(f'All {count} notifications deleted successfully!', 'success')
    return redirect(url_for('admin_notifications'))

# General notification deletion routes for all user roles
@app.route('/notifications/delete/<int:notification_id>', methods=['POST'])
@login_required
def delete_user_notification(notification_id):
    """Delete a single notification for current user"""
    user = get_current_user()
    notification = Notification.query.filter_by(id=notification_id, user_id=user.id).first_or_404()
    db.session.delete(notification)
    db.session.commit()
    
    flash('Notification deleted successfully!', 'success')
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/notifications/delete_all', methods=['POST'])
@login_required  
def delete_all_user_notifications():
    """Delete all notifications for current user"""
    user = get_current_user()
    try:
        count = Notification.query.filter_by(user_id=user.id).count()
        Notification.query.filter_by(user_id=user.id).delete()
        db.session.commit()
        
        flash(f'All {count} notifications deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting notifications. Please try again.', 'error')
    
    return redirect(request.referrer or url_for('dashboard'))

# Note: Auditee routes are defined elsewhere in the file

# Auditor evidence download route
@app.route('/auditor/evidence/<int:evidence_id>/download')
@role_required('auditor')
def auditor_download_evidence(evidence_id):
    """Auditor downloads evidence file"""
    evidence = EvidenceFile.query.get_or_404(evidence_id)
    user = get_current_user()
    
    # Check permission - auditor can download evidence from their audits
    if not evidence.finding or not evidence.finding.audit or evidence.finding.audit.auditor_id != user.id:
        flash('You do not have permission to download this evidence.', 'error')
        return redirect(url_for('auditor_dashboard'))
    
    try:
        from flask import send_file
        import os
        
        file_path = evidence.file_path
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True, download_name=evidence.original_filename)
        else:
            flash('File not found.', 'error')
    except Exception as e:
        flash('Error downloading file.', 'error')
    
    return redirect(url_for('auditor_finding_detail', finding_id=evidence.finding_id))

# Admin evidence download route
@app.route('/admin/evidence/<int:evidence_id>/download')
@role_required('admin')
def admin_download_evidence(evidence_id):
    """Admin downloads evidence file"""
    evidence = EvidenceFile.query.get_or_404(evidence_id)
    
    try:
        from flask import send_file
        import os
        
        file_path = evidence.file_path
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True, download_name=evidence.original_filename)
        else:
            flash('File not found.', 'error')
    except Exception as e:
        flash('Error downloading file.', 'error')
    
    return redirect(url_for('admin_audit_detail', audit_id=evidence.finding.audit_id if evidence.finding else 1))

# Context processor for template globals
@app.context_processor
def inject_user():
    return dict(current_user=get_current_user())
