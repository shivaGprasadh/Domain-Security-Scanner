/**
 * Domain Security Scanner - Pagination and Sorting
 * 
 * Handles pagination, sorting, and filtering for the domain list
 */

document.addEventListener('DOMContentLoaded', function() {
    // Pagination configuration
    const itemsPerPage = 5; // Number of domains to display per page
    let currentPage = 1;
    
    // Helper function to get all table rows as an array for sorting
    function getTableRows() {
        return Array.from(document.querySelectorAll('#domainsTableBody tr.domain-row'));
    }
    
    // Helper function to apply sorted rows to the table
    function applySort(sortedRows) {
        const tbody = document.getElementById('domainsTableBody');
        // Remove all existing rows
        while (tbody.firstChild) {
            tbody.removeChild(tbody.firstChild);
        }
        // Add sorted rows
        sortedRows.forEach(row => {
            tbody.appendChild(row);
        });
    }
    
    // Show the specified page of data
    function showPage(page, rows) {
        // Calculate start and end indices
        const startIndex = (page - 1) * itemsPerPage;
        const endIndex = startIndex + itemsPerPage;
        
        // Hide all rows
        rows.forEach(row => {
            row.style.display = 'none';
        });
        
        // Show only rows for the current page
        for (let i = startIndex; i < endIndex && i < rows.length; i++) {
            rows[i].style.display = '';
        }
    }
    
    // Pagination functionality
    function setupPagination() {
        const rows = getTableRows();
        const totalPages = Math.ceil(rows.length / itemsPerPage);
        
        // Only show pagination if we have more than one page
        if (totalPages <= 1) {
            document.getElementById('paginationContainer').innerHTML = '';
            showPage(1, rows);
            return;
        }
        
        // Generate pagination controls
        let paginationHTML = '';
        
        // Previous button
        paginationHTML += `
            <li class="page-item ${currentPage === 1 ? 'disabled' : ''}">
                <a class="page-link" href="#" data-page="${currentPage - 1}" aria-label="Previous">
                    <span aria-hidden="true">&laquo;</span>
                </a>
            </li>
        `;
        
        // Page numbers
        for (let i = 1; i <= totalPages; i++) {
            paginationHTML += `
                <li class="page-item ${currentPage === i ? 'active' : ''}">
                    <a class="page-link" href="#" data-page="${i}">${i}</a>
                </li>
            `;
        }
        
        // Next button
        paginationHTML += `
            <li class="page-item ${currentPage === totalPages ? 'disabled' : ''}">
                <a class="page-link" href="#" data-page="${currentPage + 1}" aria-label="Next">
                    <span aria-hidden="true">&raquo;</span>
                </a>
            </li>
        `;
        
        // Add pagination to the DOM
        document.getElementById('paginationContainer').innerHTML = paginationHTML;
        
        // Add event listeners to pagination links
        document.querySelectorAll('#paginationContainer .page-link').forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                const pageNum = parseInt(this.getAttribute('data-page'));
                // Only navigate if it's a valid page
                if (pageNum >= 1 && pageNum <= totalPages && pageNum !== currentPage) {
                    currentPage = pageNum;
                    showPage(currentPage, rows);
                    setupPagination(); // Update pagination UI
                }
            });
        });
        
        // Show the current page
        showPage(currentPage, rows);
    }
    
    // Initialize pagination when DOM is fully loaded
    if (document.getElementById('domainsTableBody')) {
        setupPagination();
        
        // Force trigger pagination on initial load to ensure rows are properly displayed
        const initialRows = getTableRows();
        showPage(currentPage, initialRows);
        
        // Set up event listeners for sorting buttons if they exist
        const sortDomainAsc = document.getElementById('sortDomainAsc');
        const sortDomainDesc = document.getElementById('sortDomainDesc');
        const sortRankAsc = document.getElementById('sortRankAsc');
        const sortRankDesc = document.getElementById('sortRankDesc');
        
        // Security rank order for sorting (best to worst)
        const rankOrder = {'A+': 0, 'A': 1, 'B+': 2, 'B': 3, 'C': 4, 'D': 5, 'E': 6};
        
        if (sortDomainAsc) {
            sortDomainAsc.addEventListener('click', function() {
                const rows = getTableRows();
                const sortedRows = rows.sort((a, b) => {
                    const domainA = a.querySelector('.domain-name').textContent.toLowerCase();
                    const domainB = b.querySelector('.domain-name').textContent.toLowerCase();
                    return domainA.localeCompare(domainB);
                });
                applySort(sortedRows);
                // Reset pagination after sorting
                currentPage = 1;
                setupPagination();
            });
        }
        
        if (sortDomainDesc) {
            sortDomainDesc.addEventListener('click', function() {
                const rows = getTableRows();
                const sortedRows = rows.sort((a, b) => {
                    const domainA = a.querySelector('.domain-name').textContent.toLowerCase();
                    const domainB = b.querySelector('.domain-name').textContent.toLowerCase();
                    return domainB.localeCompare(domainA);
                });
                applySort(sortedRows);
                // Reset pagination after sorting
                currentPage = 1;
                setupPagination();
            });
        }
        
        if (sortRankAsc) {
            sortRankAsc.addEventListener('click', function() {
                const rows = getTableRows();
                const sortedRows = rows.sort((a, b) => {
                    const rankA = a.querySelector('.security-badge').textContent.trim();
                    const rankB = b.querySelector('.security-badge').textContent.trim();
                    return rankOrder[rankA] - rankOrder[rankB];
                });
                applySort(sortedRows);
                // Reset pagination after sorting
                currentPage = 1;
                setupPagination();
            });
        }
        
        if (sortRankDesc) {
            sortRankDesc.addEventListener('click', function() {
                const rows = getTableRows();
                const sortedRows = rows.sort((a, b) => {
                    const rankA = a.querySelector('.security-badge').textContent.trim();
                    const rankB = b.querySelector('.security-badge').textContent.trim();
                    return rankOrder[rankB] - rankOrder[rankA];
                });
                applySort(sortedRows);
                // Reset pagination after sorting
                currentPage = 1;
                setupPagination();
            });
        }
        
        // Domain filtering logic
        const domainFilter = document.getElementById('domainFilter');
        if (domainFilter) {
            domainFilter.addEventListener('input', function() {
                const filterValue = this.value.toLowerCase();
                const rows = document.querySelectorAll('#domainsTableBody tr.domain-row');
                
                // If filter is empty, use pagination
                if (filterValue === '') {
                    // Reset to show all rows through pagination
                    rows.forEach(row => row.classList.remove('filtered-out'));
                    currentPage = 1;
                    setupPagination();
                    return;
                }
                
                // When filtering, show all matching rows without pagination
                document.getElementById('paginationContainer').innerHTML = '';
                
                let visibleCount = 0;
                rows.forEach(row => {
                    const domainName = row.querySelector('.domain-name').textContent.toLowerCase();
                    if (domainName.includes(filterValue)) {
                        row.style.display = '';
                        visibleCount++;
                    } else {
                        row.style.display = 'none';
                    }
                });
            });
        }
    }
});