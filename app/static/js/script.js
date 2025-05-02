// Main JavaScript for Port Scanner application

// Execute when DOM is fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap components
    initializeBootstrapComponents();
    
    // Setup alert dismissal
    setupAlertDismiss();
    
    // Setup CIDR validation if on subnet page
    setupCIDRValidation();
    
    // Setup scan type selection
    setupScanTypeSelection();
    
    // Setup dynamic forms
    setupDynamicForms();
    
    // Initialize any charts on the page
    initializeCharts();
});

// Initialize Bootstrap components
function initializeBootstrapComponents() {
    // Initialize all tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize all popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
}

// Setup alert dismissal functionality
function setupAlertDismiss() {
    // Auto-dismiss alerts after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert:not(.alert-persistent)');
        alerts.forEach(function(alert) {
            if (alert && bootstrap.Alert) {
                var bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }
        });
    }, 5000);
    
    // Manual dismiss button handlers
    document.querySelectorAll('.alert .btn-close').forEach(function(button) {
        button.addEventListener('click', function() {
            var alert = this.closest('.alert');
            if (alert && bootstrap.Alert) {
                var bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }
        });
    });
}

// Setup CIDR validation
function setupCIDRValidation() {
    var cidrInput = document.getElementById('cidr');
    if (cidrInput) {
        cidrInput.addEventListener('input', function() {
            validateCIDR(this);
        });
        
        // Validate CIDR on form submit
        var form = cidrInput.closest('form');
        if (form) {
            form.addEventListener('submit', function(e) {
                if (!validateCIDR(cidrInput)) {
                    e.preventDefault();
                }
            });
        }
    }
}

// Validate CIDR format
function validateCIDR(input) {
    if (!input.value) return true;
    
    var cidrPattern = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$/;
    var isValid = cidrPattern.test(input.value);
    
    if (isValid) {
        input.classList.remove('is-invalid');
        input.classList.add('is-valid');
        
        // Get the feedback element
        var feedback = input.nextElementSibling;
        if (feedback && feedback.classList.contains('invalid-feedback')) {
            feedback.style.display = 'none';
        }
    } else {
        input.classList.remove('is-valid');
        input.classList.add('is-invalid');
        
        // Get the feedback element
        var feedback = input.nextElementSibling;
        if (feedback && feedback.classList.contains('invalid-feedback')) {
            feedback.style.display = 'block';
            feedback.textContent = 'Please enter a valid CIDR notation (e.g., 192.168.1.0/24)';
        }
    }
    
    return isValid;
}

// Setup scan type selection
function setupScanTypeSelection() {
    var scanTypeSelect = document.getElementById('scan_type');
    if (scanTypeSelect) {
        scanTypeSelect.addEventListener('change', function() {
            var portRangeDiv = document.getElementById('port_range_div');
            if (portRangeDiv) {
                if (this.value === 'port_scan') {
                    portRangeDiv.style.display = 'block';
                } else {
                    portRangeDiv.style.display = 'none';
                }
            }
        });
        
        // Trigger change event on page load
        var event = new Event('change');
        scanTypeSelect.dispatchEvent(event);
    }
}

// Setup dynamic forms
function setupDynamicForms() {
    // Handle frequency selection for scan schedules
    var frequencySelect = document.getElementById('frequency');
    if (frequencySelect) {
        frequencySelect.addEventListener('change', function() {
            var weeklyOptions = document.getElementById('weekly_options');
            var monthlyOptions = document.getElementById('monthly_options');
            
            if (weeklyOptions && monthlyOptions) {
                if (this.value === 'weekly') {
                    weeklyOptions.style.display = 'block';
                    monthlyOptions.style.display = 'none';
                } else if (this.value === 'monthly') {
                    weeklyOptions.style.display = 'none';
                    monthlyOptions.style.display = 'block';
                } else {
                    weeklyOptions.style.display = 'none';
                    monthlyOptions.style.display = 'none';
                }
            }
        });
        
        // Trigger change event on page load
        var event = new Event('change');
        frequencySelect.dispatchEvent(event);
    }
    
    // Handle target list selection for scans
    var targetListSelect = document.getElementById('target_list_id');
    if (targetListSelect) {
        targetListSelect.addEventListener('change', function() {
            var customTargetsDiv = document.getElementById('custom_targets_div');
            if (customTargetsDiv) {
                if (this.value === 'custom') {
                    customTargetsDiv.style.display = 'block';
                } else {
                    customTargetsDiv.style.display = 'none';
                }
            }
        });
        
        // Trigger change event on page load
        var event = new Event('change');
        targetListSelect.dispatchEvent(event);
    }
}

// Initialize charts on the page
function initializeCharts() {
    // Port Distribution Chart
    var portDistributionCtx = document.getElementById('portDistributionChart');
    if (portDistributionCtx) {
        var chartData = JSON.parse(portDistributionCtx.getAttribute('data-chart'));
        createChart(portDistributionCtx, 'bar', chartData.labels, chartData.data, {
            title: 'Top Ports Distribution',
            yAxisTitle: 'Number of Hosts'
        });
    }
    
    // Scan Results Chart
    var scanResultsCtx = document.getElementById('scanResultsChart');
    if (scanResultsCtx) {
        var chartData = JSON.parse(scanResultsCtx.getAttribute('data-chart'));
        createChart(scanResultsCtx, 'line', chartData.labels, chartData.data, {
            title: 'Scan Results Over Time',
            yAxisTitle: 'Count'
        });
    }
}

// Create a chart with the specified parameters
function createChart(ctx, type, labels, data, options = {}) {
    return new Chart(ctx, {
        type: type,
        data: {
            labels: labels,
            datasets: [{
                label: options.title || 'Data',
                data: data,
                backgroundColor: 'rgba(78, 115, 223, 0.2)',
                borderColor: 'rgba(78, 115, 223, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: options.yAxisTitle || ''
                    }
                }
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                },
                title: {
                    display: true,
                    text: options.title || ''
                }
            }
        }
    });
}

// Function to update real-time scan progress
function updateScanProgress(scanId) {
    if (!scanId) return;
    
    const interval = setInterval(function() {
        fetch(`/scan/${scanId}/status`)
            .then(response => response.json())
            .then(data => {
                const progressBar = document.getElementById('scan-progress-bar');
                const statusElement = document.getElementById('scan-status');
                
                if (progressBar && statusElement) {
                    // Update progress bar
                    if (data.progress) {
                        progressBar.style.width = `${data.progress}%`;
                        progressBar.setAttribute('aria-valuenow', data.progress);
                    }
                    
                    // Update status text
                    if (data.status) {
                        statusElement.textContent = data.status;
                        
                        // If scan is completed or failed, stop the interval
                        if (data.status === 'completed' || data.status === 'failed') {
                            clearInterval(interval);
                            
                            // Reload the page to show results
                            setTimeout(() => {
                                window.location.reload();
                            }, 1000);
                        }
                    }
                }
            })
            .catch(error => {
                console.error('Error updating scan progress:', error);
                clearInterval(interval);
            });
    }, 5000); // Check every 5 seconds
}

// Export report to CSV
function exportToCSV(tableId, filename) {
    var table = document.getElementById(tableId);
    if (!table) return;
    
    var rows = table.querySelectorAll('tr');
    var csv = [];
    
    for (var i = 0; i < rows.length; i++) {
        var row = [], cols = rows[i].querySelectorAll('td, th');
        
        for (var j = 0; j < cols.length; j++) {
            // Remove HTML, replace double quotes with two double quotes
            var data = cols[j].innerText.replace(/(\r\n|\n|\r)/gm, '').replace(/"/g, '""');
            row.push('"' + data + '"');
        }
        
        csv.push(row.join(','));
    }
    
    // Download CSV file
    downloadCSV(csv.join('\n'), filename);
}

function downloadCSV(csv, filename) {
    var csvFile;
    var downloadLink;
    
    // Create CSV file
    csvFile = new Blob([csv], {type: 'text/csv'});
    
    // Create download link
    downloadLink = document.createElement('a');
    
    // File name
    downloadLink.download = filename;
    
    // Create link to file
    downloadLink.href = window.URL.createObjectURL(csvFile);
    
    // Hide download link
    downloadLink.style.display = 'none';
    
    // Add link to DOM
    document.body.appendChild(downloadLink);
    
    // Click download link
    downloadLink.click();
    
    // Remove link from DOM
    document.body.removeChild(downloadLink);
} 