from flask import render_template, request, redirect, url_for, flash, session, jsonify, send_file, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from app import app
from firebase_auth import login_required, role_required, get_current_user, log_audit_action, check_password_reset_required
from firebase_config import authenticate_user, create_user_account, get_user_info
from data_store import DATA_STORE, find_user_by_email, initialize_sample_data
# Import utilities - will create these functions if needed
import secrets
import string
import os
import uuid

def generate_password(length=12):
    """Generate a secure random password"""
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(characters) for _ in range(length))

def save_uploaded_file(file):
    """Save uploaded file and return filename"""
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    
    filename = f"{uuid.uuid4()}_{file.filename}"
    filepath = os.path.join('uploads', filename)
    file.save(filepath)
    return filename
from datetime import datetime, timedelta
import os
import uuid
import json
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import io

# Initialize sample data on first import
initialize_sample_data()

@app.route('/')
def landing():
    """Landing page with role-based login options"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/login/<role>')
def login_form(role):
    """Display login form for specific role"""
    valid_roles = ['director', 'head_of_business_control', 'auditor', 'auditee']
    if role not in valid_roles:
        flash('Invalid role specified.', 'error')
        return redirect(url_for('landing'))
    return render_template('login.html', role=role)

@app.route('/login', methods=['POST'])
def login():
    """Process login with Firebase authentication"""
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']
    
    # Authenticate with Firebase or mock
    firebase_user = authenticate_user(email, password)
    if not firebase_user:
        flash('Invalid email or password.', 'error')
        return redirect(url_for('login_form', role=role))
    
    # Get user data from data store
    user_data = find_user_by_email(email)
    if not user_data or user_data.get('role') != role or not user_data.get('is_active', False):
        flash('Invalid email, role, or account inactive.', 'error')
        return redirect(url_for('login_form', role=role))
    
    # Set session
    session['user_id'] = user_data['id']
    session['user_role'] = user_data['role']
    session['firebase_token'] = firebase_user['idToken']
    
    # Update last login
    # Update last login time in data store
    if user_data['id'] in DATA_STORE['users']:
        DATA_STORE['users'][user_data['id']]['last_login'] = datetime.now()
    
    log_audit_action('login', 'user', user_data['id'], f'User {email} logged in')
    
    # Check password reset requirement - skip for development
    if user_data.get('password_reset_required', False) and email not in ["admin@audit.system", "head@audit.system", "auditor@audit.system", "auditee@audit.system"]:
        flash('You must change your password before continuing.', 'warning')
        return redirect(url_for('profile'))
    
    flash(f'Welcome, {user_data.get("first_name", "")} {user_data.get("last_name", "")}!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    user = get_current_user()
    if user:
        log_audit_action('logout', 'user', user['id'], f'User {user.get("email", "")} logged out')
    
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Role-based dashboard"""
    user = get_current_user()
    if not user:
        return redirect(url_for('landing'))
    
    role = user.get('role')
    
    if role == 'director':
        return director_dashboard()
    elif role == 'head_of_business_control':
        return head_of_business_control_dashboard()
    elif role == 'auditor':
        return auditor_dashboard()
    elif role == 'auditee':
        return auditee_dashboard()
    else:
        flash('Invalid role.', 'error')
        return redirect(url_for('landing'))

@app.route('/director_dashboard')
@login_required
@role_required('director')
def director_dashboard():
    """Director dashboard - approve plans and review reports"""
    # Get audits pending approval
    pending_audits = [audit for audit in DATA_STORE['audits'].values() 
                     if audit.get('status') == 'pending_director_approval']
    
    # Get completed reports for review  
    completed_audits = [audit for audit in DATA_STORE['audits'].values() 
                       if audit.get('status') == 'completed']
    
    # Get all audits for overview
    all_audits = list(DATA_STORE['audits'].values())
    
    # Risk overview
    risks = list(DATA_STORE['risk_assessments'].values())
    
    # Dashboard statistics
    stats = {
        'pending_approvals': len(pending_audits),
        'completed_audits': len(completed_audits),
        'total_risks': len(risks),
        'high_risks': len([r for r in risks if r.get('risk_level') == 'high'])
    }
    
    return render_template('director/dashboard.html', 
                         pending_audits=pending_audits,
                         completed_audits=completed_audits,
                         all_audits=all_audits,
                         risks=risks,
                         stats=stats)

@app.route('/head_of_business_control_dashboard')
@login_required
@role_required('head_of_business_control')
def head_of_business_control_dashboard():
    """Head of Business Control dashboard - create plans, assign auditors"""
    # Get drafts and audits in various stages
    draft_audits = [audit for audit in DATA_STORE['audits'].values() 
                   if audit.get('status') == 'draft']
    approved_audits = [audit for audit in DATA_STORE['audits'].values() 
                      if audit.get('status') == 'approved']
    in_progress_audits = [audit for audit in DATA_STORE['audits'].values() 
                         if audit.get('status') == 'in_progress']
    
    # Get auditors for assignment
    auditors = [user for user in DATA_STORE['users'].values() 
               if user.get('role') == 'auditor']
    auditees = [user for user in DATA_STORE['users'].values() 
               if user.get('role') == 'auditee']
    
    # Risk assessments
    risks = list(DATA_STORE['risk_assessments'].values())
    
    # Corrective actions tracking
    all_actions = list(DATA_STORE['corrective_actions'].values())
    overdue_actions = [a for a in all_actions if a.get('target_date') and 
                      datetime.fromisoformat(a['target_date']) < datetime.now() and 
                      a.get('status') != 'completed']
    
    stats = {
        'draft_audits': len(draft_audits),
        'approved_audits': len(approved_audits), 
        'in_progress_audits': len(in_progress_audits),
        'total_risks': len(risks),
        'overdue_actions': len(overdue_actions)
    }
    
    return render_template('head_of_business_control/dashboard.html',
                         draft_audits=draft_audits,
                         approved_audits=approved_audits,
                         in_progress_audits=in_progress_audits,
                         auditors=auditors,
                         auditees=auditees,
                         risks=risks,
                         overdue_actions=overdue_actions,
                         stats=stats)

@app.route('/auditor_dashboard')
@login_required
@role_required('auditor')
def auditor_dashboard():
    """Auditor dashboard - manage assigned audits"""
    user = get_current_user()
    
    # Get audits assigned to this auditor
    assigned_audits = [audit for audit in DATA_STORE['audits'].values() 
                      if audit.get('auditor_id') == user['id']]
    
    # Get findings for audits
    auditor_findings = [finding for finding in DATA_STORE['findings'].values() 
                       if finding.get('audit_id') in [a['id'] for a in assigned_audits]]
    
    # Get messages
    auditor_messages = [msg for msg in DATA_STORE['messages'].values() 
                       if msg.get('recipient_id') == user['id'] or msg.get('sender_id') == user['id']]
    
    # Get evidence files
    evidence_files = [evidence for evidence in DATA_STORE['evidence_files'].values() 
                     if evidence.get('audit_id') in [a['id'] for a in assigned_audits]]
    
    stats = {
        'assigned_audits': len(assigned_audits),
        'total_findings': len(auditor_findings),
        'open_findings': len([f for f in auditor_findings if f.get('status') == 'open']),
        'unread_messages': len([m for m in auditor_messages if not m.get('is_read', True)])
    }
    
    return render_template('auditor/dashboard.html',
                         assigned_audits=assigned_audits,
                         findings=auditor_findings,
                         messages=auditor_messages,
                         evidence_files=evidence_files,
                         stats=stats)

@app.route('/auditee_dashboard')
@login_required
@role_required('auditee')
def auditee_dashboard():
    """Auditee dashboard - respond to audit requests"""
    user = get_current_user()
    
    # Get audits where this user is auditee
    auditee_audits = [audit for audit in DATA_STORE['audits'].values() 
                     if audit.get('auditee_id') == user['id']]
    
    # Get corrective actions assigned to this auditee
    my_actions = [action for action in DATA_STORE['corrective_actions'].values() 
                 if action.get('responsible_person_id') == user['id']]
    
    # Get messages for this auditee
    auditee_messages = [msg for msg in DATA_STORE['messages'].values() 
                       if msg.get('recipient_id') == user['id']]
    
    # Get evidence files uploaded by this auditee
    my_evidence = [evidence for evidence in DATA_STORE['evidence_files'].values() 
                  if evidence.get('uploaded_by') == user['id']]
    
    stats = {
        'active_audits': len([a for a in auditee_audits if a.get('status') in ['in_progress', 'review']]),
        'pending_actions': len([a for a in my_actions if a.get('status') == 'pending']),
        'overdue_actions': len([a for a in my_actions if a.get('target_date') and 
                               datetime.fromisoformat(a['target_date']) < datetime.now() and 
                               a.get('status') != 'completed']),
        'unread_messages': len([m for m in auditee_messages if not m.get('is_read', True)])
    }
    
    return render_template('auditee/dashboard.html',
                         auditee_audits=auditee_audits,
                         my_actions=my_actions,
                         messages=auditee_messages,
                         evidence_files=my_evidence,
                         stats=stats)

# Risk Assessment Routes
@app.route('/risk-assessment')
@login_required
@role_required('head_of_business_control', 'director')
def risk_assessment():
    """Risk assessment management"""
    risks = risk_model.get_all()
    departments = dept_model.get_all()
    
    return render_template('risk_assessment.html', risks=risks, departments=departments)

@app.route('/risk-assessment/create', methods=['GET', 'POST'])
@login_required
@role_required('head_of_business_control')
def create_risk_assessment():
    """Create new risk assessment"""
    if request.method == 'POST':
        try:
            risk_data = {
                'risk_description': request.form['risk_description'],
                'department_id': request.form['department_id'],
                'impact_level': request.form['impact_level'],
                'likelihood_level': request.form['likelihood_level'],
                'mitigation_measures': request.form.get('mitigation_measures', ''),
                'risk_owner': request.form.get('risk_owner', ''),
                'created_by': get_current_user()['id']
            }
            
            risk_id = risk_model.create_risk(risk_data)
            log_audit_action('create', 'risk_assessment', risk_id, 'Risk assessment created')
            
            flash('Risk assessment created successfully.', 'success')
            return redirect(url_for('risk_assessment'))
            
        except Exception as e:
            flash(f'Error creating risk assessment: {str(e)}', 'error')
    
    departments = dept_model.get_all()
    return render_template('create_risk_assessment.html', departments=departments)

# Audit Planning Routes
@app.route('/audit-planning')
@login_required
@role_required('head_of_business_control', 'director')
def audit_planning():
    """Audit planning interface"""
    audits = audit_model.get_all()
    risks = risk_model.get_all()
    departments = dept_model.get_all()
    
    return render_template('audit_planning.html', audits=audits, risks=risks, departments=departments)

@app.route('/audit-planning/create', methods=['GET', 'POST'])
@login_required
@role_required('head_of_business_control')
def create_audit_plan():
    """Create new audit plan"""
    if request.method == 'POST':
        try:
            audit_data = {
                'title': request.form['title'],
                'description': request.form.get('description', ''),
                'audit_type': request.form['audit_type'],
                'department_id': request.form['department_id'],
                'audit_scope': request.form.get('audit_scope', ''),
                'audit_objectives': request.form.get('audit_objectives', ''),
                'planned_start_date': request.form.get('planned_start_date'),
                'planned_end_date': request.form.get('planned_end_date'),
                'priority': request.form.get('priority', 'medium'),
                'created_by_id': get_current_user()['id'],
                'status': 'draft'
            }
            
            audit_id = audit_model.create_audit(audit_data)
            log_audit_action('create', 'audit', audit_id, 'Audit plan created')
            
            flash('Audit plan created successfully.', 'success')
            return redirect(url_for('audit_planning'))
            
        except Exception as e:
            flash(f'Error creating audit plan: {str(e)}', 'error')
    
    departments = dept_model.get_all()
    risks = risk_model.get_all()
    return render_template('create_audit_plan.html', departments=departments, risks=risks)

@app.route('/audit-planning/<audit_id>/submit-for-approval', methods=['POST'])
@login_required
@role_required('head_of_business_control')
def submit_audit_for_approval(audit_id):
    """Submit audit plan to Director for approval"""
    try:
        audit_data = {
            'status': 'pending_director_approval',
            'plan_submitted_at': datetime.now().isoformat()
        }
        
        audit_model.update(audit_id, audit_data)
        log_audit_action('submit_for_approval', 'audit', audit_id, 'Audit plan submitted for director approval')
        
        flash('Audit plan submitted for Director approval.', 'success')
        
    except Exception as e:
        flash(f'Error submitting audit plan: {str(e)}', 'error')
    
    return redirect(url_for('audit_planning'))

@app.route('/director/approve-audit/<audit_id>', methods=['POST'])
@login_required
@role_required('director')
def approve_audit_plan(audit_id):
    """Director approves audit plan"""
    try:
        audit_data = {
            'status': 'approved',
            'director_approved_at': datetime.now().isoformat(),
            'director_feedback': request.form.get('director_feedback', '')
        }
        
        audit_model.update(audit_id, audit_data)
        log_audit_action('approve', 'audit', audit_id, 'Audit plan approved by director')
        
        flash('Audit plan approved successfully.', 'success')
        
    except Exception as e:
        flash(f'Error approving audit plan: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/assign-auditor/<audit_id>', methods=['POST'])
@login_required
@role_required('head_of_business_control')
def assign_auditor(audit_id):
    """Head of Business Control assigns auditor"""
    try:
        audit_data = {
            'auditor_id': request.form['auditor_id'],
            'auditee_id': request.form['auditee_id'],
            'status': 'assigned',
            'auditor_assigned_at': datetime.now().isoformat()
        }
        
        audit_model.update(audit_id, audit_data)
        log_audit_action('assign_auditor', 'audit', audit_id, f'Auditor assigned to audit')
        
        flash('Auditor assigned successfully.', 'success')
        
    except Exception as e:
        flash(f'Error assigning auditor: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

# Messaging System Routes
@app.route('/messages')
@login_required
def messages():
    """View messages"""
    user = get_current_user()
    
    # Get messages for current user
    received_messages = message_model.query('recipient_id', '==', user['id'])
    sent_messages = message_model.query('sender_id', '==', user['id'])
    
    return render_template('messages.html', 
                         received_messages=received_messages,
                         sent_messages=sent_messages)

@app.route('/messages/send', methods=['POST'])
@login_required
def send_message():
    """Send message"""
    try:
        message_data = {
            'audit_id': request.form['audit_id'],
            'sender_id': get_current_user()['id'],
            'recipient_id': request.form['recipient_id'],
            'message_content': request.form['message_content'],
            'message_type': request.form.get('message_type', 'general'),
            'subject': request.form.get('subject', 'Audit Communication')
        }
        
        message_id = message_model.send_message(message_data)
        log_audit_action('send_message', 'message', message_id, 'Message sent')
        
        flash('Message sent successfully.', 'success')
        
    except Exception as e:
        flash(f'Error sending message: {str(e)}', 'error')
    
    return redirect(url_for('messages'))

# Evidence Management Routes
@app.route('/evidence/upload', methods=['POST'])
@login_required
def upload_evidence():
    """Upload evidence file"""
    try:
        if 'file' not in request.files:
            flash('No file selected.', 'error')
            return redirect(request.referrer)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(request.referrer)
        
        # Save file
        filename = save_uploaded_file(file)
        
        evidence_data = {
            'audit_id': request.form['audit_id'],
            'filename': file.filename,
            'file_path': filename,
            'uploaded_by': get_current_user()['id'],
            'file_size': len(file.read()),
            'file_type': file.content_type,
            'description': request.form.get('description', '')
        }
        
        evidence_id = evidence_model.create_evidence(evidence_data)
        log_audit_action('upload_evidence', 'evidence', evidence_id, f'Evidence file uploaded: {file.filename}')
        
        flash('Evidence uploaded successfully.', 'success')
        
    except Exception as e:
        flash(f'Error uploading evidence: {str(e)}', 'error')
    
    return redirect(request.referrer)

# Report Generation Routes
@app.route('/generate-report/<audit_id>')
@login_required
@role_required('auditor', 'director')
def generate_audit_report(audit_id):
    """Generate PDF audit report"""
    try:
        audit = audit_model.get(audit_id)
        if not audit:
            flash('Audit not found.', 'error')
            return redirect(url_for('dashboard'))
        
        findings = finding_model.get_findings_by_audit(audit_id)
        evidence = evidence_model.query('audit_id', '==', audit_id)
        
        # Create PDF report
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=18, spaceAfter=30)
        story.append(Paragraph(f"Audit Report: {audit['title']}", title_style))
        story.append(Spacer(1, 12))
        
        # Audit details
        story.append(Paragraph(f"<b>Reference Number:</b> {audit.get('reference_number', 'N/A')}", styles['Normal']))
        story.append(Paragraph(f"<b>Audit Type:</b> {audit.get('audit_type', 'N/A')}", styles['Normal']))
        story.append(Paragraph(f"<b>Status:</b> {audit.get('status', 'N/A')}", styles['Normal']))
        story.append(Paragraph(f"<b>Priority:</b> {audit.get('priority', 'N/A')}", styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Audit scope and objectives
        if audit.get('audit_scope'):
            story.append(Paragraph("<b>Audit Scope:</b>", styles['Heading2']))
            story.append(Paragraph(audit['audit_scope'], styles['Normal']))
            story.append(Spacer(1, 12))
        
        if audit.get('audit_objectives'):
            story.append(Paragraph("<b>Audit Objectives:</b>", styles['Heading2']))
            story.append(Paragraph(audit['audit_objectives'], styles['Normal']))
            story.append(Spacer(1, 12))
        
        # Findings section
        if findings:
            story.append(Paragraph("<b>Findings:</b>", styles['Heading2']))
            for i, finding in enumerate(findings, 1):
                story.append(Paragraph(f"<b>Finding #{i}: {finding.get('title', 'Untitled')}</b>", styles['Normal']))
                story.append(Paragraph(f"Severity: {finding.get('severity', 'Unknown')}", styles['Normal']))
                story.append(Paragraph(finding.get('description', 'No description provided'), styles['Normal']))
                story.append(Spacer(1, 8))
        
        # Evidence section
        if evidence:
            story.append(Paragraph("<b>Evidence Files:</b>", styles['Heading2']))
            for ev in evidence:
                story.append(Paragraph(f"• {ev.get('filename', 'Unknown file')}", styles['Normal']))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        # Save report record
        report_data = {
            'audit_id': audit_id,
            'report_title': f"Audit Report - {audit['title']}",
            'report_content': 'PDF report generated',
            'generated_by': get_current_user()['id'],
            'status': 'final'
        }
        
        report_id = report_model.create_report(report_data)
        log_audit_action('generate_report', 'report', report_id, 'PDF report generated')
        
        # Return PDF response
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=audit_report_{audit_id}.pdf'
        
        return response
        
    except Exception as e:
        flash(f'Error generating report: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

# Report Library Routes
@app.route('/report-library')
@login_required
@role_required('director', 'head_of_business_control', 'auditor')
def report_library():
    """Central report library"""
    reports = report_model.get_all()
    audits = audit_model.get_all()
    
    # Create audit lookup for report details
    audit_lookup = {audit['id']: audit for audit in audits}
    
    return render_template('report_library.html', reports=reports, audit_lookup=audit_lookup)

# User Management Routes
@app.route('/users')
@login_required
@role_required('head_of_business_control', 'director')
def manage_users():
    """User management"""
    users = user_model.get_all()
    departments = dept_model.get_all()
    
    return render_template('user_management.html', users=users, departments=departments)

@app.route('/users/create', methods=['POST'])
@login_required
@role_required('head_of_business_control')
def create_user():
    """Create new user"""
    try:
        # Generate temporary password
        temp_password = generate_password()
        
        # Create user in Firebase Auth
        firebase_user = create_user_account(
            request.form['email'], 
            temp_password,
            f"{request.form['first_name']} {request.form['last_name']}"
        )
        
        if not firebase_user:
            flash('Error creating user account.', 'error')
            return redirect(url_for('manage_users'))
        
        # Create user record in Firestore
        user_data = {
            'email': request.form['email'],
            'role': request.form['role'],
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'phone': request.form.get('phone', ''),
            'department_id': request.form.get('department_id', ''),
            'firebase_uid': firebase_user['localId'],
            'temporary_password': temp_password,
            'password_reset_required': True
        }
        
        user_id = user_model.create_user(user_data)
        log_audit_action('create', 'user', user_id, f'User created: {request.form["email"]}')
        
        flash(f'User created successfully. Temporary password: {temp_password}', 'success')
        
    except Exception as e:
        flash(f'Error creating user: {str(e)}', 'error')
    
    return redirect(url_for('manage_users'))

# Department Management Routes  
@app.route('/departments')
@login_required
@role_required('head_of_business_control', 'director')
def manage_departments():
    """Department management"""
    departments = dept_model.get_all()
    return render_template('department_management.html', departments=departments)

@app.route('/departments/create', methods=['POST'])
@login_required
@role_required('head_of_business_control')
def create_department():
    """Create new department"""
    try:
        dept_data = {
            'name': request.form['name'],
            'description': request.form.get('description', ''),
            'head_name': request.form.get('head_name', '')
        }
        
        dept_id = dept_model.create_department(dept_data)
        log_audit_action('create', 'department', dept_id, f'Department created: {request.form["name"]}')
        
        flash('Department created successfully.', 'success')
        
    except Exception as e:
        flash(f'Error creating department: {str(e)}', 'error')
    
    return redirect(url_for('manage_departments'))

# API Routes for AJAX calls
@app.route('/api/audit/<audit_id>/findings')
@login_required
def get_audit_findings(audit_id):
    """Get findings for an audit (API)"""
    findings = finding_model.get_findings_by_audit(audit_id)
    return jsonify({'findings': findings})

@app.route('/api/risk-heatmap')
@login_required
def risk_heatmap_data():
    """Get risk data for heatmap"""
    risks = risk_model.get_all()
    departments = dept_model.get_all()
    
    # Create department lookup
    dept_lookup = {dept['id']: dept['name'] for dept in departments}
    
    # Format data for heatmap
    heatmap_data = []
    for risk in risks:
        heatmap_data.append({
            'department': dept_lookup.get(risk.get('department_id', ''), 'Unknown'),
            'risk_score': risk.get('risk_score', 0),
            'risk_level': risk.get('risk_level', 'low'),
            'description': risk.get('risk_description', '')
        })
    
    return jsonify({'heatmap_data': heatmap_data})

# Context processor for templates
@app.context_processor
def inject_user():
    """Inject current user into all templates"""
    return dict(current_user=get_current_user())

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500