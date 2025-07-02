/**
 * SCAN MANAGER
 * Manages scanned websites table with real-time filtering and search
 */

// Prevent duplicate class declaration
if (typeof window.ScanManager === 'undefined') {
    
class ScanManager {
    constructor() {
        this.scans = [];
        this.filteredScans = [];
        this.currentPage = 1;
        this.pageSize = 20;
        this.totalPages = 1;
        
        this.filters = {
            result: 'all',
            time: 'all',
            search: ''
        };
        
        this.initializeElements();
        this.setupEventListeners();
        this.loadScansData();
        
        // Set up auto-refresh every 10 seconds
        this.refreshInterval = setInterval(() => {
            this.loadScansData(false); // Silent refresh
        }, 10000);
        
        console.log('[SCAN-MANAGER] Initialized');
    }
    
    /**
     * Initialize DOM elements
     */
    initializeElements() {
        this.tableBody = document.getElementById('scans-table-body');
        this.pagination = document.getElementById('pagination');
        this.totalScansCount = document.getElementById('total-scans-count');
        
        // Filter elements
        this.resultFilter = document.getElementById('result-filter');
        this.timeFilter = document.getElementById('time-filter');
        this.searchInput = document.getElementById('search-input');
        this.refreshBtn = document.getElementById('refresh-btn');
        
        // Threat summary elements
        this.threatMalicious = document.getElementById('threat-malicious');
        this.threatSuspicious = document.getElementById('threat-suspicious');
        this.threatClean = document.getElementById('threat-clean');
    }
    
    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Filter change handlers
        if (this.resultFilter) {
            this.resultFilter.addEventListener('change', () => {
                this.filters.result = this.resultFilter.value;
                this.applyFilters();
            });
        }
        
        if (this.timeFilter) {
            this.timeFilter.addEventListener('change', () => {
                this.filters.time = this.timeFilter.value;
                this.applyFilters();
            });
        }
        
        // Search input handler with debounce
        if (this.searchInput) {
            let searchTimeout;
            this.searchInput.addEventListener('input', () => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.filters.search = this.searchInput.value.toLowerCase();
                    this.applyFilters();
                }, 300);
            });
        }
        
        // Refresh button handler
        if (this.refreshBtn) {
            this.refreshBtn.addEventListener('click', () => {
                this.loadScansData(true);
            });
        }
    }
    
    /**
     * Load scans data from API
     */
    async loadScansData(showLoading = true) {
        try {
            if (showLoading) {
                this.showLoading();
            }
            
            const response = await fetch('/api/recent-activity');
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.scans = data.activity_data || [];
                this.updateThreatSummary();
                this.applyFilters();
                
                if (this.totalScansCount) {
                    this.totalScansCount.textContent = this.scans.length.toLocaleString();
                }
            } else {
                throw new Error(data.message || 'Failed to load scan data');
            }
            
        } catch (error) {
            console.error('[SCAN-MANAGER] Failed to load scans:', error);
            this.showError('Failed to load scan data. Please try again.');
        }
    }
    
    /**
     * Apply filters to scan data
     */
    applyFilters() {
        this.filteredScans = this.scans.filter(scan => {
            // Result filter
            if (this.filters.result !== 'all') {
                const scanResult = scan.scan_details?.scan_result || 'unknown';
                if (scanResult !== this.filters.result) {
                    return false;
                }
            }
            
            // Time filter
            if (this.filters.time !== 'all') {
                const scanTime = new Date(scan.timestamp);
                const now = new Date();
                const diffDays = (now - scanTime) / (1000 * 60 * 60 * 24);
                
                switch (this.filters.time) {
                    case 'today':
                        if (diffDays > 1) return false;
                        break;
                    case 'week':
                        if (diffDays > 7) return false;
                        break;
                    case 'month':
                        if (diffDays > 30) return false;
                        break;
                }
            }
            
            // Search filter
            if (this.filters.search) {
                const domain = scan.scan_details?.domain || '';
                const url = scan.scan_details?.url || '';
                const searchText = this.filters.search;
                
                if (!domain.toLowerCase().includes(searchText) && 
                    !url.toLowerCase().includes(searchText)) {
                    return false;
                }
            }
            
            return true;
        });
        
        // Reset to first page when filters change
        this.currentPage = 1;
        this.updatePagination();
        this.renderTable();
    }
    
    /**
     * Update threat summary counters
     */
    updateThreatSummary() {
        const maliciousCount = this.scans.filter(s => s.scan_details?.scan_result === 'malicious').length;
        const suspiciousCount = this.scans.filter(s => s.scan_details?.scan_result === 'suspicious').length;
        const cleanCount = this.scans.filter(s => s.scan_details?.scan_result === 'clean').length;
        
        if (this.threatMalicious) {
            this.animateCounter(this.threatMalicious, maliciousCount);
        }
        if (this.threatSuspicious) {
            this.animateCounter(this.threatSuspicious, suspiciousCount);
        }
        if (this.threatClean) {
            this.animateCounter(this.threatClean, cleanCount);
        }
    }
    
    /**
     * Animate counter updates
     */
    animateCounter(element, targetValue) {
        const currentValue = parseInt(element.textContent) || 0;
        const difference = targetValue - currentValue;
        
        if (difference === 0) return;
        
        const steps = 10;
        const stepValue = difference / steps;
        let currentStep = 0;
        
        const animation = setInterval(() => {
            currentStep++;
            const newValue = Math.round(currentValue + (stepValue * currentStep));
            element.textContent = newValue.toLocaleString();
            
            if (currentStep >= steps) {
                clearInterval(animation);
                element.textContent = targetValue.toLocaleString();
            }
        }, 50);
    }
    
    /**
     * Render the scans table
     */
    renderTable() {
        if (!this.tableBody) return;
        
        const startIndex = (this.currentPage - 1) * this.pageSize;
        const endIndex = startIndex + this.pageSize;
        const pageScans = this.filteredScans.slice(startIndex, endIndex);
        
        if (pageScans.length === 0) {
            this.showNoResults();
            return;
        }
        
        this.tableBody.innerHTML = pageScans.map(scan => {
            const details = scan.scan_details || {};
            const user = scan.user || {};
            
            return `
                <tr>
                    <td>
                        <a href="${details.url || '#'}" 
                           target="_blank" 
                           class="domain-link" 
                           title="${details.url || 'No URL'}">
                            ${this.truncateText(details.domain || 'Unknown', 30)}
                        </a>
                    </td>
                    <td>
                        <span class="status-badge status-${details.scan_result || 'unknown'}">
                            ${(details.scan_result || 'unknown').toUpperCase()}
                        </span>
                    </td>
                    <td>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <div class="confidence-bar">
                                <div class="confidence-fill ${this.getConfidenceClass(details.confidence_score)}" 
                                     style="width: ${details.confidence_score || 0}%">
                                </div>
                            </div>
                            <span style="font-size: 0.8rem; color: var(--cyber-text-muted);">
                                ${Math.round(details.confidence_score || 0)}%
                            </span>
                        </div>
                    </td>
                    <td>
                        <div style="font-size: 0.85rem;">
                            <div style="font-weight: 600;">${user.display_name || user.username || 'Unknown'}</div>
                            ${user.username ? `<div style="color: var(--cyber-text-muted); font-size: 0.75rem;">@${user.username}</div>` : ''}
                        </div>
                    </td>
                    <td>
                        <div style="font-size: 0.85rem;">
                            <div>${this.formatDate(scan.timestamp)}</div>
                            <div style="color: var(--cyber-text-muted); font-size: 0.75rem;">
                                ${this.getTimeAgo(scan.timestamp)}
                            </div>
                        </div>
                    </td>
                    <td>
                        <span style="font-size: 0.8rem; color: var(--cyber-text-muted);">
                            ${this.formatAction(details.action_taken)}
                        </span>
                    </td>
                </tr>
            `;
        }).join('');
    }
    
    /**
     * Update pagination controls
     */
    updatePagination() {
        this.totalPages = Math.ceil(this.filteredScans.length / this.pageSize);
        
        if (!this.pagination || this.totalPages <= 1) {
            if (this.pagination) this.pagination.innerHTML = '';
            return;
        }
        
        const maxVisiblePages = 5;
        const startPage = Math.max(1, this.currentPage - Math.floor(maxVisiblePages / 2));
        const endPage = Math.min(this.totalPages, startPage + maxVisiblePages - 1);
        
        let paginationHTML = '';
        
        // Previous button
        paginationHTML += `
            <button class="pagination-btn" ${this.currentPage === 1 ? 'disabled' : ''} 
                    onclick="window.scanManager.goToPage(${this.currentPage - 1})">
                ← Prev
            </button>
        `;
        
        // Page numbers
        if (startPage > 1) {
            paginationHTML += `
                <button class="pagination-btn" onclick="window.scanManager.goToPage(1)">1</button>
            `;
            if (startPage > 2) {
                paginationHTML += `<span style="color: var(--cyber-text-muted);">...</span>`;
            }
        }
        
        for (let i = startPage; i <= endPage; i++) {
            paginationHTML += `
                <button class="pagination-btn ${i === this.currentPage ? 'active' : ''}" 
                        onclick="window.scanManager.goToPage(${i})">
                    ${i}
                </button>
            `;
        }
        
        if (endPage < this.totalPages) {
            if (endPage < this.totalPages - 1) {
                paginationHTML += `<span style="color: var(--cyber-text-muted);">...</span>`;
            }
            paginationHTML += `
                <button class="pagination-btn" onclick="window.scanManager.goToPage(${this.totalPages})">
                    ${this.totalPages}
                </button>
            `;
        }
        
        // Next button
        paginationHTML += `
            <button class="pagination-btn" ${this.currentPage === this.totalPages ? 'disabled' : ''} 
                    onclick="window.scanManager.goToPage(${this.currentPage + 1})">
                Next →
            </button>
        `;
        
        this.pagination.innerHTML = paginationHTML;
    }
    
    /**
     * Go to specific page
     */
    goToPage(page) {
        if (page >= 1 && page <= this.totalPages) {
            this.currentPage = page;
            this.renderTable();
            this.updatePagination();
        }
    }
    
    /**
     * Show loading state
     */
    showLoading() {
        if (this.tableBody) {
            this.tableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="no-results">
                        <div class="loading-spinner"></div>
                        Loading scan data...
                    </td>
                </tr>
            `;
        }
    }
    
    /**
     * Show no results message
     */
    showNoResults() {
        if (this.tableBody) {
            this.tableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="no-results">
                        No scans found matching your filters.
                        <br>
                        <small style="color: var(--cyber-text-muted);">
                            Try adjusting your search or filter criteria.
                        </small>
                    </td>
                </tr>
            `;
        }
        
        if (this.pagination) {
            this.pagination.innerHTML = '';
        }
    }
    
    /**
     * Show error message
     */
    showError(message) {
        if (this.tableBody) {
            this.tableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="no-results">
                        <span style="color: var(--cyber-danger);">⚠ ${message}</span>
                        <br>
                        <button onclick="window.scanManager.loadScansData(true)" 
                                style="margin-top: 10px; padding: 5px 15px; background: transparent; border: 1px solid var(--cyber-primary); color: var(--cyber-primary); border-radius: 4px; cursor: pointer;">
                            Retry
                        </button>
                    </td>
                </tr>
            `;
        }
    }
    
    /**
     * Utility functions
     */
    truncateText(text, maxLength) {
        if (!text) return 'N/A';
        return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
    }
    
    getConfidenceClass(score) {
        if (score >= 80) return 'high';
        if (score >= 50) return 'medium';
        return 'low';
    }
    
    formatDate(timestamp) {
        if (!timestamp) return 'Unknown';
        const date = new Date(timestamp);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
    }
    
    getTimeAgo(timestamp) {
        if (!timestamp) return 'Unknown';
        
        const now = new Date();
        const scanTime = new Date(timestamp);
        const diffMs = now - scanTime;
        const diffMins = Math.floor(diffMs / 60000);
        
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        
        const diffHours = Math.floor(diffMins / 60);
        if (diffHours < 24) return `${diffHours}h ago`;
        
        const diffDays = Math.floor(diffHours / 24);
        return `${diffDays}d ago`;
    }
    
    formatAction(action) {
        if (!action) return 'None';
        return action.replace(/_/g, ' ').toUpperCase();
    }
    
    /**
     * Cleanup
     */
    destroy() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
        console.log('[SCAN-MANAGER] Destroyed');
    }
}

// Global access
window.ScanManager = ScanManager;

} // End duplicate prevention check