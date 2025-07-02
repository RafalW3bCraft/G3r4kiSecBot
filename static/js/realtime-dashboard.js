/**
 * NEONGUARD REAL-TIME DASHBOARD
 * Live data updates and cyber effects
 */

class CyberDashboard {
    constructor() {
        this.updateInterval = 5000; // 5 seconds for security data
        this.slowUpdateInterval = 30000; // 30 seconds for system metrics
        this.isActive = true;
        this.lastUpdate = new Date();
        
        this.initializeRealTime();
        this.setupEventListeners();
        
        console.log('[CYBER-DASHBOARD] Initialized with real-time updates');
    }
    
    /**
     * Initialize real-time data updates
     */
    initializeRealTime() {
        // Fast updates for security data
        this.fastUpdateTimer = setInterval(() => {
            if (this.isActive) {
                this.updateSecurityData();
                this.updateRecentActivity();
            }
        }, this.updateInterval);
        
        // Slower updates for system metrics
        this.slowUpdateTimer = setInterval(() => {
            if (this.isActive) {
                this.updateSystemMetrics();
                this.updateThreatLevel();
            }
        }, this.slowUpdateInterval);
        
        // Initial data load
        this.loadInitialData();
    }
    
    /**
     * Setup event listeners for page visibility and interactions
     */
    setupEventListeners() {
        // Pause updates when page is hidden
        document.addEventListener('visibilitychange', () => {
            this.isActive = !document.hidden;
            if (this.isActive) {
                console.log('[CYBER-DASHBOARD] Resumed real-time updates');
                this.loadInitialData();
            } else {
                console.log('[CYBER-DASHBOARD] Paused real-time updates');
            }
        });
        
        // Handle window focus/blur
        window.addEventListener('focus', () => {
            this.isActive = true;
            this.loadInitialData();
        });
        
        window.addEventListener('blur', () => {
            this.isActive = false;
        });
    }
    
    /**
     * Load initial data on dashboard load
     */
    async loadInitialData() {
        try {
            await Promise.all([
                this.updateSystemMetrics(),
                this.updateSecurityData(),
                this.updateRecentActivity(),
                this.updateThreatLevel()
            ]);
            
            this.lastUpdate = new Date();
            this.updateLastScanTime();
            
        } catch (error) {
            console.error('[CYBER-DASHBOARD] Initial data load failed:', error);
            this.showAlert('System initialization error', 'danger');
        }
    }
    
    /**
     * Update system metrics from /api/realtime-stats
     */
    async updateSystemMetrics() {
        try {
            const response = await fetch('/api/realtime-stats');
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.renderSystemStats(data.stats);
                this.updateSystemHealth(data.stats);
            }
            
        } catch (error) {
            console.error('[CYBER-DASHBOARD] System metrics update failed:', error);
            this.handleUpdateError('system-metrics');
        }
    }
    
    /**
     * Update security data and scan results
     */
    async updateSecurityData() {
        try {
            const response = await fetch('/api/recent-activity');
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.renderSecurityFeed(data.activity_data || []);
                this.updateThreatCounters(data.activity_data || []);
            }
            
        } catch (error) {
            console.error('[CYBER-DASHBOARD] Security data update failed:', error);
            this.handleUpdateError('security-data');
        }
    }
    
    /**
     * Update recent activity feed
     */
    async updateRecentActivity() {
        // This will be implemented in the dashboard template
        // For now, just update the timestamp
        this.updateLastScanTime();
    }
    
    /**
     * Update threat level indicator
     */
    async updateThreatLevel() {
        try {
            const response = await fetch('/api/system-health');
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.updateThreatLevelDisplay(data.threat_level || 'MINIMAL');
            }
            
        } catch (error) {
            console.error('[CYBER-DASHBOARD] Threat level update failed:', error);
            // Don't show error for this, just keep current level
        }
    }
    
    /**
     * Render system statistics with animations
     */
    renderSystemStats(stats) {
        // Update counters with animation
        this.animateCounter('total-groups', stats.total_groups || 0);
        this.animateCounter('total-scans', stats.total_scans || 0);
        this.animateCounter('threats-blocked', stats.threats_blocked || 0);
        this.animateCounter('active-users', stats.active_users || 0);
        
        // Update percentages
        this.updatePercentage('threat-detection-rate', stats.threat_detection_rate || 0);
        this.updatePercentage('system-uptime', stats.system_uptime || '99.9%');
        
        // Update today's metrics
        this.animateCounter('scans-today', stats.scans_today || 0);
        this.animateCounter('threats-today', stats.threats_today || 0);
        this.animateCounter('new-users-today', stats.new_users_today || 0);
    }
    
    /**
     * Animate counter with cyber effect
     */
    animateCounter(elementId, targetValue) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
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
            
            // Add glow effect during animation
            element.style.textShadow = '0 0 10px currentColor';
            
            if (currentStep >= steps) {
                clearInterval(animation);
                element.textContent = targetValue.toLocaleString();
                
                // Remove glow after animation
                setTimeout(() => {
                    element.style.textShadow = '';
                }, 500);
            }
        }, 50);
    }
    
    /**
     * Update percentage values
     */
    updatePercentage(elementId, value) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        if (typeof value === 'string' && value.includes('%')) {
            element.textContent = value;
        } else {
            element.textContent = value + '%';
        }
        
        // Add pulse effect for important metrics
        if (elementId === 'system-uptime') {
            element.classList.add('pulse');
            setTimeout(() => element.classList.remove('pulse'), 1000);
        }
    }
    
    /**
     * Render security activity feed
     */
    renderSecurityFeed(activities) {
        const feedContainer = document.getElementById('security-feed');
        if (!feedContainer) return;
        
        // Limit to latest 10 activities for performance
        const latestActivities = activities.slice(0, 10);
        
        feedContainer.innerHTML = latestActivities.map(activity => {
            const severityClass = this.getSeverityClass(activity.scan_details?.scan_result);
            const timeAgo = this.getTimeAgo(activity.timestamp);
            
            return `
                <div class="security-feed-item ${severityClass}">
                    <div class="feed-icon">
                        ${this.getSecurityIcon(activity.scan_details?.scan_result)}
                    </div>
                    <div class="feed-content">
                        <div class="feed-title">
                            ${activity.scan_details?.domain || 'Unknown Domain'}
                        </div>
                        <div class="feed-details">
                            Result: ${activity.scan_details?.scan_result || 'Unknown'} • 
                            Confidence: ${activity.scan_details?.confidence_score || 0}%
                        </div>
                        <div class="feed-time">${timeAgo}</div>
                    </div>
                    <div class="feed-status ${severityClass}">
                        ${activity.scan_details?.scan_result?.toUpperCase() || 'UNKNOWN'}
                    </div>
                </div>
            `;
        }).join('');
    }
    
    /**
     * Update threat counters based on activity data
     */
    updateThreatCounters(activities) {
        const maliciousCount = activities.filter(a => a.scan_details?.scan_result === 'malicious').length;
        const suspiciousCount = activities.filter(a => a.scan_details?.scan_result === 'suspicious').length;
        const cleanCount = activities.filter(a => a.scan_details?.scan_result === 'clean').length;
        
        this.animateCounter('malicious-count', maliciousCount);
        this.animateCounter('suspicious-count', suspiciousCount);
        this.animateCounter('clean-count', cleanCount);
    }
    
    /**
     * Update system health indicators
     */
    updateSystemHealth(stats) {
        const healthElement = document.getElementById('system-health');
        if (!healthElement) return;
        
        const uptime = parseFloat(stats.system_uptime) || 99.9;
        let healthStatus = 'optimal';
        let healthColor = 'var(--cyber-secondary)';
        
        if (uptime < 95) {
            healthStatus = 'critical';
            healthColor = 'var(--cyber-danger)';
        } else if (uptime < 98) {
            healthStatus = 'warning';
            healthColor = 'var(--cyber-warning)';
        }
        
        healthElement.textContent = healthStatus.toUpperCase();
        healthElement.style.color = healthColor;
    }
    
    /**
     * Update threat level display
     */
    updateThreatLevelDisplay(level) {
        const threatElement = document.getElementById('threat-level');
        if (!threatElement) return;
        
        threatElement.textContent = level.toUpperCase();
        
        // Update color based on threat level
        const colors = {
            'MINIMAL': 'var(--cyber-secondary)',
            'LOW': 'var(--cyber-primary)',
            'MODERATE': 'var(--cyber-warning)',
            'HIGH': 'var(--cyber-danger)',
            'CRITICAL': 'var(--cyber-accent)'
        };
        
        threatElement.style.color = colors[level.toUpperCase()] || colors['MINIMAL'];
    }
    
    /**
     * Update last scan time
     */
    updateLastScanTime() {
        const lastScanElement = document.getElementById('last-scan');
        if (!lastScanElement) return;
        
        const now = new Date();
        const timeString = now.toLocaleTimeString('en-US', { 
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
        
        lastScanElement.textContent = timeString;
    }
    
    /**
     * Get severity CSS class for scan results
     */
    getSeverityClass(result) {
        const classes = {
            'malicious': 'severity-high',
            'suspicious': 'severity-medium', 
            'clean': 'severity-low'
        };
        return classes[result] || 'severity-unknown';
    }
    
    /**
     * Get security icon for scan results
     */
    getSecurityIcon(result) {
        const icons = {
            'malicious': '⚠',
            'suspicious': '⚡',
            'clean': '✓'
        };
        return icons[result] || '?';
    }
    
    /**
     * Get human-readable time ago
     */
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
    
    /**
     * Handle update errors gracefully
     */
    handleUpdateError(source) {
        console.warn(`[CYBER-DASHBOARD] ${source} update failed, retrying...`);
        
        // Show connection status
        const statusElement = document.querySelector('.system-status');
        if (statusElement) {
            statusElement.textContent = 'RECONNECTING';
            statusElement.className = 'system-status warning';
            
            setTimeout(() => {
                statusElement.textContent = 'ONLINE';
                statusElement.className = 'system-status online';
            }, 3000);
        }
    }
    
    /**
     * Show alert message
     */
    showAlert(message, type = 'info') {
        if (typeof showAlert === 'function') {
            showAlert(message, type);
        } else {
            console.log(`[CYBER-DASHBOARD] Alert: ${message}`);
        }
    }
    
    /**
     * Cleanup timers when dashboard is destroyed
     */
    destroy() {
        if (this.fastUpdateTimer) {
            clearInterval(this.fastUpdateTimer);
        }
        if (this.slowUpdateTimer) {
            clearInterval(this.slowUpdateTimer);
        }
        
        this.isActive = false;
        console.log('[CYBER-DASHBOARD] Destroyed');
    }
}

/**
 * URL Scanner functionality
 */
class URLScanner {
    constructor() {
        this.isScanning = false;
        this.setupScanner();
    }
    
    setupScanner() {
        const scanForm = document.getElementById('url-scan-form');
        const scanInput = document.getElementById('url-input');
        const scanButton = document.getElementById('scan-button');
        
        if (!scanForm || !scanInput || !scanButton) return;
        
        scanForm.addEventListener('submit', (e) => {
            e.preventDefault();
            this.scanURL(scanInput.value.trim());
        });
        
        // Enter key support
        scanInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !this.isScanning) {
                this.scanURL(scanInput.value.trim());
            }
        });
    }
    
    async scanURL(url) {
        if (!url || this.isScanning) return;
        
        this.isScanning = true;
        this.updateScanButton('SCANNING...', true);
        
        try {
            const response = await fetch('/api/scan-url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.displayScanResult(data.result);
                this.showAlert('Scan completed successfully', 'success');
            } else {
                this.showAlert(data.message || 'Scan failed', 'danger');
            }
            
        } catch (error) {
            console.error('[URL-SCANNER] Scan failed:', error);
            this.showAlert('Network error during scan', 'danger');
        } finally {
            this.isScanning = false;
            this.updateScanButton('SCAN URL', false);
        }
    }
    
    updateScanButton(text, disabled) {
        const scanButton = document.getElementById('scan-button');
        if (!scanButton) return;
        
        scanButton.textContent = text;
        scanButton.disabled = disabled;
        
        if (disabled) {
            scanButton.classList.add('scanning');
        } else {
            scanButton.classList.remove('scanning');
        }
    }
    
    displayScanResult(result) {
        const resultContainer = document.getElementById('scan-result');
        if (!resultContainer) return;
        
        const severityClass = result.scan_result === 'malicious' ? 'danger' : 
                             result.scan_result === 'suspicious' ? 'warning' : 'success';
        
        resultContainer.innerHTML = `
            <div class="scan-result-card ${severityClass}">
                <div class="result-header">
                    <span class="result-icon">${this.getResultIcon(result.scan_result)}</span>
                    <span class="result-status">${result.scan_result.toUpperCase()}</span>
                    <span class="result-confidence">${result.confidence_score}%</span>
                </div>
                <div class="result-details">
                    <p><strong>Domain:</strong> ${result.domain}</p>
                    <p><strong>Scan Time:</strong> ${new Date().toLocaleString()}</p>
                    ${result.threat_sources ? `<p><strong>Threat Sources:</strong> ${result.threat_sources.join(', ')}</p>` : ''}
                </div>
            </div>
        `;
        
        resultContainer.style.display = 'block';
    }
    
    getResultIcon(result) {
        const icons = {
            'malicious': '⚠',
            'suspicious': '⚡',
            'clean': '✓'
        };
        return icons[result] || '?';
    }
    
    showAlert(message, type) {
        if (typeof showAlert === 'function') {
            showAlert(message, type);
        }
    }
}

// Global instances
window.CyberDashboard = CyberDashboard;
window.URLScanner = URLScanner;