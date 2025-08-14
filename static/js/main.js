// Audit Management System - Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Auto-hide alerts after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert');
        alerts.forEach(function(alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);

    // Mark notifications as read
    document.addEventListener('click', function(e) {
        if (e.target.matches('.mark-notification-read')) {
            e.preventDefault();
            const notificationId = e.target.dataset.notificationId;
            
            fetch(`/api/notifications/${notificationId}/mark-read`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    e.target.closest('.notification-item').classList.remove('notification-unread');
                    updateNotificationCount();
                }
            })
            .catch(error => console.error('Error:', error));
        }
    });

    // Update notification count
    function updateNotificationCount() {
        const unreadNotifications = document.querySelectorAll('.notification-unread').length;
        const badge = document.querySelector('.notification-badge');
        if (badge) {
            if (unreadNotifications > 0) {
                badge.textContent = unreadNotifications;
                badge.style.display = 'inline';
            } else {
                badge.style.display = 'none';
            }
        }
    }

    // File upload preview
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(function(input) {
        input.addEventListener('change', function(e) {
            const file = e.target.files[0];
            const preview = input.parentElement.querySelector('.file-preview');
            
            if (file && preview) {
                preview.innerHTML = `
                    <div class="alert alert-info">
                        <i class="fas fa-file me-2"></i>
                        Selected: ${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)
                    </div>
                `;
            }
        });
    });

    // Form validation
    const forms = document.querySelectorAll('.needs-validation');
    forms.forEach(function(form) {
        form.addEventListener('submit', function(e) {
            if (!form.checkValidity()) {
                e.preventDefault();
                e.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });

    // Date input validation
    const dateInputs = document.querySelectorAll('input[type="date"]');
    dateInputs.forEach(function(input) {
        input.addEventListener('change', function() {
            const date = new Date(input.value);
            const today = new Date();
            const startDateInput = document.querySelector('input[name="planned_start_date"]');
            
            if (input.name === 'planned_end_date' && startDateInput) {
                const startDate = new Date(startDateInput.value);
                if (date < startDate) {
                    input.setCustomValidity('End date cannot be before start date');
                } else {
                    input.setCustomValidity('');
                }
            }
        });
    });

    // Auto-refresh dashboard every 5 minutes if on dashboard page
    if (window.location.pathname.includes('dashboard')) {
        setInterval(function() {
            // Refresh notification count
            fetch('/api/notifications/count')
                .then(response => response.json())
                .then(data => {
                    const badge = document.querySelector('.notification-badge');
                    if (badge && data.count > 0) {
                        badge.textContent = data.count;
                        badge.style.display = 'inline';
                    } else if (badge) {
                        badge.style.display = 'none';
                    }
                })
                .catch(error => console.error('Error refreshing notifications:', error));
        }, 300000); // 5 minutes
    }

    // Search functionality
    const searchInputs = document.querySelectorAll('.search-input');
    searchInputs.forEach(function(input) {
        input.addEventListener('input', function() {
            const searchTerm = input.value.toLowerCase();
            const targetTable = document.querySelector(input.dataset.target);
            
            if (targetTable) {
                const rows = targetTable.querySelectorAll('tbody tr');
                rows.forEach(function(row) {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(searchTerm) ? '' : 'none';
                });
            }
        });
    });

    // Confirmation dialogs for delete actions
    const deleteButtons = document.querySelectorAll('.btn-delete');
    deleteButtons.forEach(function(button) {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            
            const message = button.dataset.confirmMessage || 'Are you sure you want to delete this item?';
            if (confirm(message)) {
                if (button.closest('form')) {
                    button.closest('form').submit();
                } else {
                    window.location.href = button.href;
                }
            }
        });
    });
});

// Utility functions
function showAlert(message, type = 'info') {
    const alertContainer = document.querySelector('.alert-container') || document.body;
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    alertContainer.insertBefore(alert, alertContainer.firstChild);
    
    // Auto-hide after 5 seconds
    setTimeout(function() {
        if (alert.parentNode) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }
    }, 5000);
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function getBadgeClass(status) {
    const statusMap = {
        'draft': 'secondary',
        'in_progress': 'warning',
        'review': 'info',
        'completed': 'success',
        'closed': 'dark',
        'open': 'danger',
        'planned': 'secondary',
        'overdue': 'danger',
        'low': 'info',
        'medium': 'warning',
        'high': 'danger',
        'critical': 'danger'
    };
    return statusMap[status] || 'secondary';
}