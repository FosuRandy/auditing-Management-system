from datetime import datetime
from firebase_config import get_firestore_db
import uuid

class FirebaseModel:
    """Base class for Firebase models"""
    
    def __init__(self, collection_name):
        self.db = get_firestore_db()
        self.collection_name = collection_name
        self.collection = self.db.collection(collection_name) if self.db else None
    
    def create(self, data):
        """Create a new document"""
        try:
            data['created_at'] = datetime.now()
            data['updated_at'] = datetime.now()
            doc_ref = self.collection.add(data)
            return doc_ref[1].id
        except Exception as e:
            print(f"Error creating document: {e}")
            return None
    
    def get(self, doc_id):
        """Get document by ID"""
        try:
            doc = self.collection.document(doc_id).get()
            if doc.exists:
                data = doc.to_dict()
                data['id'] = doc.id
                return data
            return None
        except Exception as e:
            print(f"Error getting document: {e}")
            return None
    
    def update(self, doc_id, data):
        """Update document"""
        try:
            data['updated_at'] = datetime.now()
            self.collection.document(doc_id).update(data)
            return True
        except Exception as e:
            print(f"Error updating document: {e}")
            return False
    
    def delete(self, doc_id):
        """Delete document"""
        try:
            self.collection.document(doc_id).delete()
            return True
        except Exception as e:
            print(f"Error deleting document: {e}")
            return False
    
    def get_all(self):
        """Get all documents"""
        try:
            docs = self.collection.stream()
            results = []
            for doc in docs:
                data = doc.to_dict()
                data['id'] = doc.id
                results.append(data)
            return results
        except Exception as e:
            print(f"Error getting all documents: {e}")
            return []
    
    def query(self, field, operator, value):
        """Query documents"""
        try:
            docs = self.collection.where(field, operator, value).stream()
            results = []
            for doc in docs:
                data = doc.to_dict()
                data['id'] = doc.id
                results.append(data)
            return results
        except Exception as e:
            print(f"Error querying documents: {e}")
            return []

class UserModel(FirebaseModel):
    """User management with Firebase"""
    
    def __init__(self):
        super().__init__('users')
    
    def create_user(self, user_data):
        """Create user with validation"""
        required_fields = ['email', 'role', 'first_name', 'last_name']
        for field in required_fields:
            if field not in user_data:
                raise ValueError(f"Missing required field: {field}")
        
        user_data['is_active'] = True
        user_data['password_reset_required'] = True
        user_data['last_login'] = None
        
        return self.create(user_data)
    
    def get_user_by_email(self, email):
        """Get user by email"""
        users = self.query('email', '==', email)
        return users[0] if users else None
    
    def get_users_by_role(self, role):
        """Get all users with specific role"""
        return self.query('role', '==', role)

class DepartmentModel(FirebaseModel):
    """Department management"""
    
    def __init__(self):
        super().__init__('departments')
    
    def create_department(self, dept_data):
        """Create department with validation"""
        required_fields = ['name']
        for field in required_fields:
            if field not in dept_data:
                raise ValueError(f"Missing required field: {field}")
        
        dept_data['is_active'] = True
        return self.create(dept_data)

class RiskAssessmentModel(FirebaseModel):
    """Risk assessment management"""
    
    def __init__(self):
        super().__init__('risk_assessments')
    
    def create_risk(self, risk_data):
        """Create risk assessment"""
        required_fields = ['risk_description', 'department_id', 'impact_level', 'likelihood_level']
        for field in required_fields:
            if field not in risk_data:
                raise ValueError(f"Missing required field: {field}")
        
        # Calculate risk score
        impact_scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        likelihood_scores = {'rare': 1, 'unlikely': 2, 'possible': 3, 'likely': 4, 'almost_certain': 5}
        
        impact_score = impact_scores.get(risk_data['impact_level'], 2)
        likelihood_score = likelihood_scores.get(risk_data['likelihood_level'], 3)
        risk_data['risk_score'] = impact_score * likelihood_score
        
        # Determine risk level
        if risk_data['risk_score'] <= 4:
            risk_data['risk_level'] = 'low'
        elif risk_data['risk_score'] <= 9:
            risk_data['risk_level'] = 'medium'
        elif risk_data['risk_score'] <= 12:
            risk_data['risk_level'] = 'high'
        else:
            risk_data['risk_level'] = 'critical'
        
        return self.create(risk_data)

class AuditModel(FirebaseModel):
    """Audit management with complete workflow"""
    
    def __init__(self):
        super().__init__('audits')
    
    def create_audit(self, audit_data):
        """Create audit with validation"""
        required_fields = ['title', 'audit_type', 'department_id']
        for field in required_fields:
            if field not in audit_data:
                raise ValueError(f"Missing required field: {field}")
        
        # Generate reference number
        audit_data['reference_number'] = f"AUD-{datetime.now().year}-{str(uuid.uuid4())[:8].upper()}"
        audit_data['status'] = 'draft'  # Initial status
        audit_data['priority'] = audit_data.get('priority', 'medium')
        
        return self.create(audit_data)
    
    def get_audits_by_status(self, status):
        """Get audits by status"""
        return self.query('status', '==', status)
    
    def get_audits_by_auditor(self, auditor_id):
        """Get audits assigned to specific auditor"""
        return self.query('auditor_id', '==', auditor_id)
    
    def get_audits_by_auditee(self, auditee_id):
        """Get audits for specific auditee"""
        return self.query('auditee_id', '==', auditee_id)

class FindingModel(FirebaseModel):
    """Audit findings management"""
    
    def __init__(self):
        super().__init__('findings')
    
    def create_finding(self, finding_data):
        """Create audit finding"""
        required_fields = ['audit_id', 'title', 'description', 'severity']
        for field in required_fields:
            if field not in finding_data:
                raise ValueError(f"Missing required field: {field}")
        
        finding_data['status'] = 'open'
        finding_data['finding_number'] = f"F-{str(uuid.uuid4())[:6].upper()}"
        
        return self.create(finding_data)
    
    def get_findings_by_audit(self, audit_id):
        """Get findings for specific audit"""
        return self.query('audit_id', '==', audit_id)

class CorrectiveActionModel(FirebaseModel):
    """Corrective actions management"""
    
    def __init__(self):
        super().__init__('corrective_actions')
    
    def create_corrective_action(self, action_data):
        """Create corrective action"""
        required_fields = ['finding_id', 'action_description', 'responsible_person', 'target_date']
        for field in required_fields:
            if field not in action_data:
                raise ValueError(f"Missing required field: {field}")
        
        action_data['status'] = 'pending'
        action_data['action_number'] = f"CA-{str(uuid.uuid4())[:6].upper()}"
        
        return self.create(action_data)

class MessageModel(FirebaseModel):
    """Messaging system for auditor-auditee communication"""
    
    def __init__(self):
        super().__init__('messages')
    
    def send_message(self, message_data):
        """Send message between auditor and auditee"""
        required_fields = ['audit_id', 'sender_id', 'recipient_id', 'message_content']
        for field in required_fields:
            if field not in message_data:
                raise ValueError(f"Missing required field: {field}")
        
        message_data['is_read'] = False
        message_data['message_type'] = message_data.get('message_type', 'general')
        
        return self.create(message_data)
    
    def get_audit_messages(self, audit_id):
        """Get all messages for specific audit"""
        return self.query('audit_id', '==', audit_id)

class EvidenceModel(FirebaseModel):
    """Evidence file management"""
    
    def __init__(self):
        super().__init__('evidence_files')
    
    def create_evidence(self, evidence_data):
        """Create evidence record"""
        required_fields = ['audit_id', 'filename', 'file_path', 'uploaded_by']
        for field in required_fields:
            if field not in evidence_data:
                raise ValueError(f"Missing required field: {field}")
        
        evidence_data['file_size'] = evidence_data.get('file_size', 0)
        evidence_data['file_type'] = evidence_data.get('file_type', 'unknown')
        
        return self.create(evidence_data)

class ReportModel(FirebaseModel):
    """Audit report management"""
    
    def __init__(self):
        super().__init__('audit_reports')
    
    def create_report(self, report_data):
        """Create audit report"""
        required_fields = ['audit_id', 'report_title', 'report_content']
        for field in required_fields:
            if field not in report_data:
                raise ValueError(f"Missing required field: {field}")
        
        report_data['status'] = 'draft'
        report_data['report_number'] = f"RPT-{str(uuid.uuid4())[:8].upper()}"
        
        return self.create(report_data)