import os
import json
import logging

# Try importing Firebase with fallback
try:
    import firebase_admin
    from firebase_admin import credentials, firestore, auth as firebase_auth
    FIREBASE_AVAILABLE = True
except ImportError:
    print("Firebase Admin not available, using mock implementation")
    FIREBASE_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Firebase configuration from environment variables or default config
firebase_config = {
    "apiKey": os.environ.get("FIREBASE_API_KEY", "AIzaSyD2twe6wE5tIz5cSeyn-BPV8ozDGAAfEcQ"),
    "authDomain": "audit-management-system-271ea.firebaseapp.com",
    "projectId": os.environ.get("FIREBASE_PROJECT_ID", "audit-management-system-271ea"),
    "storageBucket": "audit-management-system-271ea.firebasestorage.app",
    "messagingSenderId": "1013634535800",
    "appId": os.environ.get("FIREBASE_APP_ID", "1:1013634535800:web:e009d73f0101318678f88d"),
    "measurementId": "G-T675PTHTQ0",
    "databaseURL": "https://audit-management-system-271ea-default-rtdb.firebaseio.com/"
}

# Initialize Firebase or Mock implementation
if FIREBASE_AVAILABLE:
    try:
        # Set project ID environment variable for Firestore
        os.environ['GOOGLE_CLOUD_PROJECT'] = firebase_config["projectId"]
        firebase_admin.initialize_app(options={'projectId': firebase_config["projectId"]})
        db = firestore.client()
        print("Firebase Admin initialized successfully")
    except Exception as e:
        print(f"Firebase initialization error: {e}, using mock implementation")
        FIREBASE_AVAILABLE = False

if not FIREBASE_AVAILABLE:
    # Create comprehensive mock database for development
    import uuid
    from datetime import datetime
    
    # In-memory storage for development
    mock_data_store = {
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
    
    class MockFirestore:
        def collection(self, name):
            return MockCollection(name)
    
    class MockCollection:
        def __init__(self, collection_name):
            self.collection_name = collection_name
            if collection_name not in mock_data_store:
                mock_data_store[collection_name] = {}
        
        def add(self, data):
            doc_id = str(uuid.uuid4())
            data['id'] = doc_id
            data['created_at'] = datetime.now()
            mock_data_store[self.collection_name][doc_id] = data
            print(f"Mock: Added document {doc_id} to {self.collection_name}")
            return (None, type('MockDoc', (), {'id': doc_id}))
        
        def document(self, doc_id):
            return MockDocument(self.collection_name, doc_id)
        
        def stream(self):
            docs = []
            for doc_id, data in mock_data_store[self.collection_name].items():
                mock_doc = type('MockDocStream', (), {
                    'to_dict': lambda: data,
                    'id': doc_id
                })
                docs.append(mock_doc)
            return docs
        
        def where(self, field, op, value):
            filtered_collection = MockCollection(f"{self.collection_name}_filtered")
            mock_data_store[filtered_collection.collection_name] = {}
            
            for doc_id, data in mock_data_store[self.collection_name].items():
                if field in data:
                    if op == '==' and data[field] == value:
                        mock_data_store[filtered_collection.collection_name][doc_id] = data
                    elif op == '!=' and data[field] != value:
                        mock_data_store[filtered_collection.collection_name][doc_id] = data
            
            return filtered_collection
    
    class MockDocument:
        def __init__(self, collection_name, doc_id):
            self.collection_name = collection_name
            self.doc_id = doc_id
        
        def get(self):
            if self.doc_id in mock_data_store[self.collection_name]:
                data = mock_data_store[self.collection_name][self.doc_id]
                return type('MockDocGet', (), {
                    'exists': True,
                    'to_dict': lambda: data,
                    'id': self.doc_id
                })
            return type('MockDocGet', (), {'exists': False})
        
        def update(self, data):
            if self.doc_id in mock_data_store[self.collection_name]:
                data['updated_at'] = datetime.now()
                mock_data_store[self.collection_name][self.doc_id].update(data)
                print(f"Mock: Updated document {self.doc_id} in {self.collection_name}")
        
        def delete(self):
            if self.doc_id in mock_data_store[self.collection_name]:
                del mock_data_store[self.collection_name][self.doc_id]
                print(f"Mock: Deleted document {self.doc_id} from {self.collection_name}")
    
    db = MockFirestore()
    print("Using comprehensive mock Firestore for development")

# Simplified auth functions using requests instead of pyrebase
auth_client = None
db_client = None

def get_firestore_db():
    """Get Firestore database instance"""
    return db

def authenticate_user(email, password):
    """Authenticate user with Firebase"""
    try:
        # For development, use mock authentication for known test accounts
        test_accounts = {
            "admin@audit.system": "admin123",
            "head@audit.system": "admin123", 
            "auditor@audit.system": "admin123",
            "auditee@audit.system": "admin123"
        }
        
        if email in test_accounts and password == test_accounts[email]:
            print(f"Development: Authenticating test user {email}")
            return {
                "localId": f"test-{email.split('@')[0]}",
                "email": email,
                "idToken": f"test-token-{email.split('@')[0]}",
                "refreshToken": f"test-refresh-{email.split('@')[0]}"
            }
        
        # For production users, try Firebase authentication
        if REQUESTS_AVAILABLE:
            api_key = firebase_config["apiKey"]
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Firebase authentication failed: {response.text}")
                return None
        
        return None
    except Exception as e:
        print(f"Authentication error: {e}")
        return None

def create_user_account(email, password, display_name):
    """Create new user account - simplified for development"""
    try:
        if REQUESTS_AVAILABLE and FIREBASE_AVAILABLE:
            # Use Firebase REST API for user creation
            api_key = firebase_config["apiKey"]
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}"
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"User creation failed: {response.text}")
                return None
        else:
            # Mock user creation
            print(f"Mock: Creating user {email}")
            return {
                "localId": f"mock-{uuid.uuid4()}",
                "email": email,
                "idToken": "mock-id-token"
            }
    except Exception as e:
        print(f"User creation error: {e}")
        return None

def get_user_info(id_token):
    """Get user information from token - simplified for development"""
    try:
        if REQUESTS_AVAILABLE and FIREBASE_AVAILABLE:
            # Use Firebase REST API
            api_key = firebase_config["apiKey"]
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={api_key}"
            payload = {"idToken": id_token}
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                return response.json()
        else:
            # Mock user info
            return {"users": [{"email": "admin@audit.system", "localId": "mock-admin-id"}]}
    except Exception as e:
        print(f"Get user info error: {e}")
        return None