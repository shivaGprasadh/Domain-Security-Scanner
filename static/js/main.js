/**
 * Domain Security Scanner - Main JavaScript
 * 
 * Handles the interactive features of the main scanner page
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Handle scan button
    const scanButton = document.querySelector('button[type="submit"]');
    if (scanButton) {
        scanButton.addEventListener('click', function() {
            // Show loading state
            this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Scanning...';
            this.disabled = true;
            
            // Submit the form
            this.form.submit();
        });
    }
    
    // Format dates
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
    
    // Sort table functionality (if needed)
    const tableHeaders = document.querySelectorAll('th[data-sort]');
    tableHeaders.forEach(function(header) {
        header.addEventListener('click', function() {
            const table = this.closest('table');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const index = Array.from(this.parentNode.children).indexOf(this);
            const direction = this.dataset.direction === 'asc' ? -1 : 1;
            
            // Sort rows
            rows.sort(function(a, b) {
                const cellA = a.children[index].textContent.trim();
                const cellB = b.children[index].textContent.trim();
                
                return cellA.localeCompare(cellB) * direction;
            });
            
            // Update direction for next click
            this.dataset.direction = direction === 1 ? 'asc' : 'desc';
            
            // Clear old rows
            while (tbody.firstChild) {
                tbody.removeChild(tbody.firstChild);
            }
            
            // Add sorted rows
            rows.forEach(function(row) {
                tbody.appendChild(row);
            });
        });
    });
});
