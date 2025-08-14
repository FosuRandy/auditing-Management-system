// Dashboard-specific JavaScript functionality

(function() {
    'use strict';

    // Dashboard configuration
    const dashboardConfig = {
        chartColors: {
            primary: '#007bff',
            success: '#28a745',
            warning: '#ffc107',
            danger: '#dc3545',
            info: '#17a2b8',
            secondary: '#6c757d',
            light: '#f8f9fa',
            dark: '#343a40'
        },
        animationDuration: 1000
    };

    // Initialize dashboard when DOM is ready
    document.addEventListener('DOMContentLoaded', function() {
        initializeDashboard();
    });

    function initializeDashboard() {
        // Initialize statistics animations
        animateStatistics();
        
        // Initialize refresh functionality
        initializeRefresh();
        
        // Initialize dashboard filters
        initializeDashboardFilters();
        
        // Set up auto-refresh
        setupAutoRefresh();
        
        console.log('Dashboard initialized');
    }

    // Animate statistics counters
    function animateStatistics() {
        const statNumbers = document.querySelectorAll('.dashboard-stat-number, h2, h4');
        
        statNumbers.forEach(function(element) {
            const finalValue = parseInt(element.textContent);
            if (!isNaN(finalValue) && finalValue > 0) {
                animateCounter(element, 0, finalValue, 1500);
            }
        });
    }

    // Animate counter from start to end value
    function animateCounter(element, start, end, duration) {
        const startTime = performance.now();
        const startValue = start;
        const endValue = end;
        
        function updateCounter(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            // Easing function for smooth animation
            const easeOutQuart = 1 - Math.pow(1 - progress, 4);
            const currentValue = Math.round(startValue + (endValue - startValue) * easeOutQuart);
            
            element.textContent = currentValue;
            
            if (progress < 1) {
                requestAnimationFrame(updateCounter);
            }
        }
        
        requestAnimationFrame(updateCounter);
    }

    // Create audit status chart
    function createAuditStatusChart(statusData) {
        const ctx = document.getElementById('auditStatusChart');
        if (!ctx || !statusData) return;

        const labels = Object.keys(statusData);
        const data = Object.values(statusData);
        const colors = labels.map(status => {
            switch(status) {
                case 'closed': return dashboardConfig.chartColors.success;
                case 'in_progress': return dashboardConfig.chartColors.primary;
                case 'review': return dashboardConfig.chartColors.warning;
                case 'planned': return dashboardConfig.chartColors.secondary;
                default: return dashboardConfig.chartColors.info;
            }
        });

        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels.map(label => label.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())),
                datasets: [{
                    data: data,
                    backgroundColor: colors,
                    borderColor: '#fff',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 20,
                            usePointStyle: true
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = ((context.raw / total) * 100).toFixed(1);
                                return `${context.label}: ${context.raw} (${percentage}%)`;
                            }
                        }
                    }
                },
                animation: {
                    animateRotate: true,
                    duration: dashboardConfig.animationDuration
                }
            }
        });
    }

    // Create findings by severity chart
    function createFindingsSeverityChart(findingsData) {
        const ctx = document.getElementById('findingsSeverityChart');
        if (!ctx || !findingsData) return;

        const severityOrder = ['critical', 'high', 'medium', 'low'];
        const labels = [];
        const data = [];
        const colors = [];

        severityOrder.forEach(severity => {
            if (findingsData[severity] !== undefined) {
                labels.push(severity.charAt(0).toUpperCase() + severity.slice(1));
                data.push(findingsData[severity]);
                
                switch(severity) {
                    case 'critical': colors.push(dashboardConfig.chartColors.danger); break;
                    case 'high': colors.push(dashboardConfig.chartColors.warning); break;
                    case 'medium': colors.push(dashboardConfig.chartColors.info); break;
                    case 'low': colors.push(dashboardConfig.chartColors.success); break;
                    default: colors.push(dashboardConfig.chartColors.secondary);
                }
            }
        });

        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Number of Findings',
                    data: data,
                    backgroundColor: colors,
                    borderColor: colors,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            title: function(context) {
                                return `${context[0].label} Severity Findings`;
                            },
                            label: function(context) {
                                return `Count: ${context.raw}`;
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                },
                animation: {
                    duration: dashboardConfig.animationDuration,
                    easing: 'easeOutQuart'
                }
            }
        });
    }

    // Create monthly audit trend chart
    function createMonthlyTrendChart(monthlyData) {
        const ctx = document.getElementById('monthlyTrendChart');
        if (!ctx || !monthlyData) return;

        const labels = monthlyData.map(item => item.month);
        const auditData = monthlyData.map(item => item.audits);
        const findingData = monthlyData.map(item => item.findings);

        new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Audits',
                        data: auditData,
                        borderColor: dashboardConfig.chartColors.primary,
                        backgroundColor: dashboardConfig.chartColors.primary + '20',
                        tension: 0.4,
                        fill: true
                    },
                    {
                        label: 'Findings',
                        data: findingData,
                        borderColor: dashboardConfig.chartColors.warning,
                        backgroundColor: dashboardConfig.chartColors.warning + '20',
                        tension: 0.4,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    intersect: false
                },
                plugins: {
                    legend: {
                        position: 'top'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                },
                animation: {
                    duration: dashboardConfig.animationDuration
                }
            }
        });
    }

    // Create completion rate gauge
    function createCompletionRateGauge(completionRate) {
        const ctx = document.getElementById('completionRateGauge');
        if (!ctx) return;

        const rate = completionRate || 0;
        const remainingRate = 100 - rate;

        new Chart(ctx, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [rate, remainingRate],
                    backgroundColor: [
                        rate >= 80 ? dashboardConfig.chartColors.success : 
                        rate >= 60 ? dashboardConfig.chartColors.warning : 
                        dashboardConfig.chartColors.danger,
                        dashboardConfig.chartColors.light
                    ],
                    borderWidth: 0,
                    cutout: '70%'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        enabled: false
                    }
                },
                animation: {
                    duration: dashboardConfig.animationDuration
                }
            },
            plugins: [{
                beforeDraw: function(chart) {
                    const width = chart.width;
                    const height = chart.height;
                    const ctx = chart.ctx;

                    ctx.restore();
                    const fontSize = (height / 114).toFixed(2);
                    ctx.font = fontSize + "em sans-serif";
                    ctx.textBaseline = "middle";
                    ctx.fillStyle = dashboardConfig.chartColors.dark;

                    const text = rate.toFixed(1) + "%";
                    const textX = Math.round((width - ctx.measureText(text).width) / 2);
                    const textY = height / 2;

                    ctx.fillText(text, textX, textY);
                    ctx.save();
                }
            }]
        });
    }

    // Initialize refresh functionality
    function initializeRefresh() {
        const refreshButton = document.getElementById('refreshDashboard');
        if (refreshButton) {
            refreshButton.addEventListener('click', function() {
                refreshDashboard();
            });
        }
    }

    // Refresh dashboard data
    function refreshDashboard() {
        const refreshButton = document.getElementById('refreshDashboard');
        const originalContent = refreshButton ? refreshButton.innerHTML : '';
        
        if (refreshButton) {
            refreshButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Refreshing...';
            refreshButton.disabled = true;
        }

        // Simulate refresh (in real implementation, this would be an API call)
        setTimeout(function() {
            window.location.reload();
        }, 1000);
    }

    // Initialize dashboard filters
    function initializeDashboardFilters() {
        const timeRangeFilter = document.getElementById('timeRangeFilter');
        const departmentFilter = document.getElementById('departmentFilter');
        
        if (timeRangeFilter) {
            timeRangeFilter.addEventListener('change', function() {
                updateDashboardData();
            });
        }
        
        if (departmentFilter) {
            departmentFilter.addEventListener('change', function() {
                updateDashboardData();
            });
        }
    }

    // Update dashboard data based on filters
    function updateDashboardData() {
        const timeRange = document.getElementById('timeRangeFilter')?.value;
        const department = document.getElementById('departmentFilter')?.value;
        
        // Show loading state
        showLoadingState();
        
        // In a real implementation, this would be an API call
        setTimeout(function() {
            hideLoadingState();
            // Update charts and statistics with new data
        }, 1500);
    }

    // Show loading state
    function showLoadingState() {
        const cards = document.querySelectorAll('.card');
        cards.forEach(function(card) {
            const overlay = document.createElement('div');
            overlay.className = 'loading-overlay d-flex justify-content-center align-items-center';
            overlay.style.cssText = `
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(255, 255, 255, 0.8);
                z-index: 10;
            `;
            overlay.innerHTML = '<div class="spinner-border text-primary" role="status"></div>';
            
            card.style.position = 'relative';
            card.appendChild(overlay);
        });
    }

    // Hide loading state
    function hideLoadingState() {
        const overlays = document.querySelectorAll('.loading-overlay');
        overlays.forEach(function(overlay) {
            overlay.remove();
        });
    }

    // Setup auto-refresh
    function setupAutoRefresh() {
        const autoRefreshInterval = 5 * 60 * 1000; // 5 minutes
        
        setInterval(function() {
            // Only auto-refresh if user is active
            if (document.visibilityState === 'visible') {
                updateStatistics();
            }
        }, autoRefreshInterval);
    }

    // Update statistics without full page reload
    function updateStatistics() {
        // This would typically fetch new data from the server
        console.log('Auto-updating statistics...');
    }

    // Real-time notifications
    function initializeRealTimeNotifications() {
        // This would typically use WebSockets or Server-Sent Events
        // for real-time updates
        console.log('Real-time notifications initialized');
    }

    // Dashboard widget management
    function initializeWidgetManagement() {
        const widgets = document.querySelectorAll('.dashboard-widget');
        
        widgets.forEach(function(widget) {
            // Add minimize/maximize functionality
            const header = widget.querySelector('.card-header');
            if (header) {
                const toggleButton = document.createElement('button');
                toggleButton.className = 'btn btn-sm btn-outline-secondary ms-auto';
                toggleButton.innerHTML = '<i class="fas fa-minus"></i>';
                toggleButton.addEventListener('click', function() {
                    toggleWidget(widget, this);
                });
                
                header.appendChild(toggleButton);
            }
        });
    }

    // Toggle widget visibility
    function toggleWidget(widget, button) {
        const body = widget.querySelector('.card-body');
        const icon = button.querySelector('i');
        
        if (body.style.display === 'none') {
            body.style.display = '';
            icon.className = 'fas fa-minus';
        } else {
            body.style.display = 'none';
            icon.className = 'fas fa-plus';
        }
    }

    // Export dashboard utilities for global use
    window.DashboardUtils = {
        createAuditStatusChart: createAuditStatusChart,
        createFindingsSeverityChart: createFindingsSeverityChart,
        createMonthlyTrendChart: createMonthlyTrendChart,
        createCompletionRateGauge: createCompletionRateGauge,
        refreshDashboard: refreshDashboard,
        updateDashboardData: updateDashboardData
    };

    // Make createAuditStatusChart available globally for template use
    window.createAuditStatusChart = createAuditStatusChart;

})();

// Dashboard-specific helper functions
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function calculatePercentage(value, total) {
    return total > 0 ? ((value / total) * 100).toFixed(1) : 0;
}

function getStatusColor(status) {
    const statusColors = {
        'planned': 'secondary',
        'in_progress': 'primary',
        'review': 'warning',
        'closed': 'success',
        'overdue': 'danger'
    };
    return statusColors[status] || 'secondary';
}

function getPriorityColor(priority) {
    const priorityColors = {
        'low': 'success',
        'medium': 'info',
        'high': 'warning',
        'critical': 'danger'
    };
    return priorityColors[priority] || 'secondary';
}

function formatTimeAgo(date) {
    const now = new Date();
    const diffTime = Math.abs(now - new Date(date));
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;
    if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
    return `${Math.floor(diffDays / 30)} months ago`;
}

function isDueSoon(dueDate, daysThreshold = 3) {
    const now = new Date();
    const due = new Date(dueDate);
    const diffTime = due - now;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    return diffDays <= daysThreshold && diffDays > 0;
}

function isOverdue(dueDate) {
    const now = new Date();
    const due = new Date(dueDate);
    return due < now;
}
