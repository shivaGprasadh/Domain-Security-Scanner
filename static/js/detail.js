/**
 * Domain Security Scanner - Detail Page JavaScript
 * 
 * Handles the interactive features of the domain detail page
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Function to format dates in readable format
    const formatDates = function() {
        const dateElements = document.querySelectorAll('.format-date');
        dateElements.forEach(function(element) {
            const dateStr = element.textContent.trim();
            if (dateStr && dateStr !== 'N/A') {
                try {
                    const date = new Date(dateStr);
                    element.textContent = date.toLocaleDateString();
                } catch (e) {
                    // Keep original format if parsing fails
                }
            }
        });
    };
    
    // Call date formatting function
    formatDates();
    
    // Format the JSON data for better readability
    const rawJson = document.getElementById('rawJson');
    if (rawJson) {
        try {
            const jsonData = JSON.parse(rawJson.textContent);
            rawJson.textContent = JSON.stringify(jsonData, null, 2);
        } catch (e) {
            console.error('Error parsing JSON:', e);
        }
    }
    
    // Security score indicator animation
    const animateScoreGauge = function() {
        const gaugeElement = document.querySelector('.security-gauge');
        if (gaugeElement) {
            // Add a simple pulse animation
            gaugeElement.style.transition = 'transform 0.5s ease';
            gaugeElement.style.transform = 'scale(1.1)';
            
            setTimeout(function() {
                gaugeElement.style.transform = 'scale(1)';
            }, 500);
        }
    };
    
    // Call score gauge animation
    animateScoreGauge();
    
    // Tab change event handling
    const tabLinks = document.querySelectorAll('button[data-bs-toggle="tab"]');
    tabLinks.forEach(function(tabLink) {
        tabLink.addEventListener('shown.bs.tab', function (event) {
            // You can add custom behavior when tabs are changed
            // For example, resize charts if they're inside tabs
            window.dispatchEvent(new Event('resize'));
        });
    });
    
    // Copy raw JSON to clipboard functionality
    const addCopyButton = function() {
        const rawJsonElement = document.getElementById('rawJson');
        if (rawJsonElement) {
            const copyButton = document.createElement('button');
            copyButton.className = 'btn btn-sm btn-outline-secondary position-absolute top-0 end-0 m-2';
            copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy';
            copyButton.addEventListener('click', function() {
                navigator.clipboard.writeText(rawJsonElement.textContent).then(function() {
                    // Success feedback
                    copyButton.innerHTML = '<i class="fas fa-check"></i> Copied!';
                    setTimeout(function() {
                        copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy';
                    }, 2000);
                }, function() {
                    // Error feedback
                    copyButton.innerHTML = '<i class="fas fa-times"></i> Failed';
                    setTimeout(function() {
                        copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy';
                    }, 2000);
                });
            });
            
            rawJsonElement.parentNode.style.position = 'relative';
            rawJsonElement.parentNode.appendChild(copyButton);
        }
    };
    
    // Add copy button to raw JSON
    addCopyButton();
});
