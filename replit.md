# Audit Management System

## Overview

This is a comprehensive web-based audit management system built with Flask that provides role-based access control for managing organizational audits. The system supports four distinct user roles (Admin, Supervisor, Auditor, and Auditee) with specialized workflows for audit planning, execution, findings management, and corrective action tracking.

The application focuses on streamlining the audit process from initial planning through final reporting, with emphasis on compliance tracking, document management, and audit trail maintenance. It provides dashboards, notifications, and comprehensive reporting capabilities to support effective audit management across organizations.

**Recent Major Enhancement (August 2025)**: 
- Successfully migrated from Replit Agent to standard Replit environment with full compatibility
- **Migration Complete (August 14, 2025)**: Successfully imported project into Replit environment with all dependencies installed, PostgreSQL database configured, and Flask application running on port 5000
- **MAJOR WORKFLOW TRANSFORMATION (August 14, 2025)**: Completely restructured audit management workflow per user requirements:
  1. Changed "System Administrator" to "Director" 
  2. Changed "Supervisor" to "Head of Business Control"
  3. **NEW WORKFLOW**: Head of Business Control creates audit plans → Director approves plans → Head of Business Control assigns auditors
  4. Updated database schema with new roles and workflow fields
  5. Created dedicated Director dashboard for plan approval
  6. Updated Head of Business Control dashboard for auditor assignment
  7. Granted Head of Business Control user and department management capabilities
- Implemented comprehensive Auditor and Auditee workflows with detailed process flows, role-based dashboards, finding management, corrective action tracking, and evidence upload capabilities
- Fixed critical audit creation error and enhanced user management features
- Resolved database configuration and session management issues
- Added admin notification management with deletion capabilities (delete individual notifications and bulk delete all)
- Fixed model constructor issues and improved error handling throughout the application
- Resolved database schema conflicts and session secret key errors
- Fixed CorrectiveAction model target_completion_date field conflicts
- **COMPLETE FIREBASE MIGRATION (August 21, 2025)**: Successfully migrated entire system from PostgreSQL to Firebase-based architecture:
  - **Firebase Integration**: Full Firebase authentication, Firestore database, and real-time features
  - **10-Step Audit Workflow**: Complete implementation of Risk Assessment, Audit Planning, Engagement Setup, Fieldwork, Execution, Findings & Corrective Action, Reporting, Follow-Up, Dashboards, and Firebase Integration
  - **Comprehensive Security**: Role-based access control, audit logging, secure file management, and password generation
  - **Modern UI**: Bootstrap 5 responsive design with role-specific dashboards for all user types
  - **Production Features**: PDF report generation, messaging system, evidence management, and searchable report library
  - **Default Users**: Created sample users for all roles (Director, Head of Business Control, Auditor, Auditee)
  - **Application Status**: Fully operational at http://localhost:5000/ with complete workflow functionality

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Template Engine**: Jinja2 templates with Bootstrap 5 for responsive UI
- **CSS Framework**: Bootstrap 5 with custom CSS variables for role-based theming
- **JavaScript**: Vanilla JavaScript with modular organization (main.js, dashboard.js)
- **Client-side Features**: Chart.js for analytics, form validation, file upload handling, and real-time notifications

### Backend Architecture
- **Web Framework**: Flask with SQLAlchemy ORM for database operations
- **Database Model**: Relational database design with proper foreign key relationships
- **Authentication**: Session-based authentication with role-based access control (RBAC)
- **Authorization**: Decorator-based permission system for route protection
- **File Management**: Secure file upload system with type validation and UUID-based naming

### Core Data Models
- **User Management**: Users with roles (director, head_of_business_control, auditor, auditee) linked to departments with contact details
- **Organizational Structure**: Departments with dynamic units and text-based department heads
- **Audit Workflow**: Complete audit lifecycle from assignment through completion
- **Findings Management**: Detailed finding classification with severity levels and auditee assignment
- **Corrective Actions**: Action plan tracking with target dates and responsible persons
- **Evidence Management**: File upload system for supporting documentation
- **Notification System**: Real-time notifications for workflow events
- **Audit Trail**: Comprehensive logging system for user actions and system events

### Security Implementation
- **Password Management**: Werkzeug password hashing with auto-generated passwords for new users
- **Session Management**: Flask sessions with configurable secret keys
- **Access Control**: Role-based permissions with function-level authorization decorators
- **Audit Logging**: Complete audit trail of user actions with IP address tracking
- **File Security**: Restricted file types and secure file handling with size limits

### Application Structure
- **Modular Design**: Separate modules for authentication (auth.py), utilities (utils.py), and routes (routes.py)
- **Role-Specific Templates**: Dedicated template directories for auditor/ and auditee/ workflows
- **Template Inheritance**: Base template system with role-specific styling and navigation
- **Workflow Implementation**: Complete Auditor and Auditee process flows with detailed UI
- **Configuration Management**: Environment variable based configuration for database and secrets

## External Dependencies

### Core Framework Dependencies
- **Flask**: Web application framework
- **Flask-SQLAlchemy**: Database ORM integration
- **Werkzeug**: Password hashing and security utilities

### Frontend Dependencies
- **Bootstrap 5**: CSS framework for responsive design
- **Font Awesome 6**: Icon library for UI elements
- **Chart.js**: JavaScript charting library for dashboard analytics

### Database System
- **SQLAlchemy**: ORM with support for multiple database backends
- **Database URL**: Configured via environment variables (DATABASE_URL)
- **Connection Pooling**: Configured with pool recycling and pre-ping for reliability

### Security and Utilities
- **UUID**: For secure file naming and unique identifiers
- **Secrets**: For secure password generation
- **OS**: Environment variable management and file system operations

### Production Considerations
- **ProxyFix**: Werkzeug middleware for proper proxy header handling
- **Logging**: Configurable logging system with debug level support
- **Session Security**: Configurable session secrets via environment variables