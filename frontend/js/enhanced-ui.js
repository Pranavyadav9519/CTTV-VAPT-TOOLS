/* ===================================
  ENHANCED UI MODULE - Polish & Completeness
  Form validation, filtering, sorting, better UX
  =================================== */

class EnhancedUI {
    constructor() {
        this.scanFilters = {
            severity: 'all',
            status: 'all',
            searchTerm: ''
        };
        this.sortBy = 'date';
        this.sortOrder = 'desc';
        this.init();
    }

    init() {
        this.setupFormValidation();
        this.setupAdvancedOptions();
        this.setupFiltering();
        this.setupNotifications();
        this.setupKeyboardShortcuts();
    }

    // ========================================================================
    // INPUT VALIDATION & FORM ENHANCEMENTS
    // ========================================================================

    setupFormValidation() {
        const targetInput = document.getElementById('target-input');
        const scanButton = document.querySelector('.btn-scan');

        if (targetInput) {
            // Real-time validation
            targetInput.addEventListener('input', (e) => {
                this.validateNetworkInput(e.target.value);
            });

            // Paste event
            targetInput.addEventListener('paste', (e) => {
                setTimeout(() => this.validateNetworkInput(e.target.value), 10);
            });

            // Format on blur
            targetInput.addEventListener('blur', () => {
                this.formatNetworkInput(targetInput.value);
            });
        }

        if (scanButton) {
            scanButton.addEventListener('click', (e) => {
                e.preventDefault();
                this.validateAndStartScan();
            });
        }
    }

    validateNetworkInput(value) {
        const parsePanel = document.getElementById('parse-panel');
        if (!value.trim()) {
            if (parsePanel) parsePanel.style.display = 'none';
            return;
        }

        const validation = this.parseNetworkTarget(value);
        
        if (validation.valid) {
            this.displayParseResults(validation);
            if (parsePanel) parsePanel.style.display = 'block';
        } else {
            if (parsePanel) parsePanel.style.display = 'none';
        }
    }

    parseNetworkTarget(target) {
        target = target.trim();

        // Single IP
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipRegex.test(target)) {
            const parts = target.split('.');
            if (parts.every(p => parseInt(p) <= 255)) {
                return {
                    valid: true,
                    type: 'Single IP',
                    normalized: target,
                    hosts: 1,
                    scope: 'Single Device',
                    duration: '30 seconds',
                    mode: 'Passive (Recommended)'
                };
            }
        }

        // IP Range
        const rangeRegex = /^(\d{1,3}\.){3}\d{1,3}\s*-\s*(\d{1,3}\.){3}\d{1,3}$/;
        if (rangeRegex.test(target)) {
            const [start, end] = target.split('-').map(s => s.trim());
            const startNum = this.ipToNumber(start);
            const endNum = this.ipToNumber(end);
            if (startNum && endNum && startNum < endNum) {
                const hosts = endNum - startNum + 1;
                return {
                    valid: true,
                    type: 'IP Range',
                    normalized: `${start} - ${end}`,
                    hosts: hosts,
                    scope: `${hosts} potential devices`,
                    duration: hosts < 100 ? '2-5 minutes' : '5-15 minutes',
                    mode: hosts < 50 ? 'Active' : 'Passive (Recommended)'
                };
            }
        }

        // CIDR
        const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
        if (cidrRegex.test(target)) {
            const [ip, mask] = target.split('/');
            const maskNum = parseInt(mask);
            if (maskNum >= 0 && maskNum <= 32) {
                const hosts = Math.pow(2, 32 - maskNum);
                return {
                    valid: true,
                    type: 'CIDR Subnet',
                    normalized: target,
                    hosts: hosts,
                    scope: `${hosts} potential hosts`,
                    duration: hosts <= 256 ? '3-8 minutes' : '10-30 minutes',
                    mode: hosts <= 256 ? 'Active' : 'Passive (Recommended)'
                };
            }
        }

        return { valid: false };
    }

    ipToNumber(ip) {
        const parts = ip.split('.');
        if (parts.length !== 4) return null;
        const nums = parts.map(p => parseInt(p));
        if (nums.some(n => isNaN(n) || n < 0 || n > 255)) return null;
        return (nums[0] << 24) + (nums[1] << 16) + (nums[2] << 8) + nums[3];
    }

    displayParseResults(validation) {
        document.getElementById('detected-type').textContent = validation.type;
        document.getElementById('normalized-target').textContent = validation.normalized;
        document.getElementById('host-count').textContent = validation.hosts;
        document.getElementById('estimated-scan-scope').textContent = validation.scope;
        document.getElementById('estimated-duration').textContent = validation.duration;
        document.getElementById('recommended-scan-mode').textContent = validation.mode;

        // Warning for large ranges
        if (validation.hosts > 256) {
            const warning = document.getElementById('safety-warning');
            if (warning) {
                warning.textContent = '⚠️ Large network range detected. This may take considerable time to scan.';
                warning.style.display = 'block';
            }
        }
    }

    formatNetworkInput(value) {
        const targetInput = document.getElementById('target-input');
        if (!targetInput) return;

        // Clean up spaces
        const formatted = value.replace(/\s+/g, ' ').trim();
        targetInput.value = formatted;
    }

    validateAndStartScan() {
        const targetInput = document.getElementById('target-input');
        const manualContainer = document.getElementById('manual-target-container');

        // Check if manual input is enabled
        const manualEnabled = manualContainer && manualContainer.style.display !== 'none';

        if (manualEnabled && !targetInput.value.trim()) {
            this.showError('Please enter a valid network range');
            return;
        }

        const validation = this.parseNetworkTarget(targetInput.value);
        if (manualEnabled && !validation.valid) {
            this.showError('Invalid network range. Use: Single IP, IP Range (x.x.x.x-y.y.y.y), or CIDR (x.x.x.x/24)');
            return;
        }

        // Trigger scan
        this.startScan();
    }

    // ========================================================================
    // ADVANCED OPTIONS & SETTINGS
    // ========================================================================

    setupAdvancedOptions() {
        const toggle = document.querySelector('.options-toggle');
        const content = document.querySelector('.options-content');

        if (toggle && content) {
            toggle.addEventListener('click', () => {
                const isOpen = content.style.display !== 'none';
                content.style.display = isOpen ? 'none' : 'block';
                toggle.querySelector('i').style.transform = isOpen ? 'rotate(0deg)' : 'rotate(180deg)';
            });
        }

        // Manual target checkbox
        const manualCheckbox = document.getElementById('allow-manual-target');
        const manualContainer = document.getElementById('manual-target-container');

        if (manualCheckbox && manualContainer) {
            manualCheckbox.addEventListener('change', (e) => {
                manualContainer.style.display = e.target.checked ? 'block' : 'none';
            });
        }
    }

    // ========================================================================
    // FILTERING & SORTING
    // ========================================================================

    setupFiltering() {
        // Create filter controls if they don't exist
        this.createFilterControls();

        // Severity filter
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('filter-severity')) {
                this.scanFilters.severity = e.target.dataset.severity;
                this.applyFilters();
            }
        });

        // Status filter
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('filter-status')) {
                this.scanFilters.status = e.target.dataset.status;
                this.applyFilters();
            }
        });

        // Sort
        document.addEventListener('change', (e) => {
            if (e.target.id === 'sort-select') {
                this.sortBy = e.target.value;
                this.applyFilters();
            }
        });

        // Search
        document.addEventListener('input', (e) => {
            if (e.target.id === 'search-scans') {
                this.scanFilters.searchTerm = e.target.value.toLowerCase();
                this.applyFilters();
            }
        });
    }

    createFilterControls() {
        const scansSection = document.querySelector('.scans-grid');
        if (!scansSection || scansSection.querySelector('.filter-controls')) return;

        const filterHTML = `
        <div class="filter-controls">
            <div class="filter-group">
                <label>Severity:</label>
                <div class="filter-buttons">
                    <button class="filter-severity active" data-severity="all">All</button>
                    <button class="filter-severity" data-severity="critical">Critical</button>
                    <button class="filter-severity" data-severity="high">High</button>
                    <button class="filter-severity" data-severity="medium">Medium</button>
                </div>
            </div>
            
            <div class="filter-group">
                <label>Status:</label>
                <div class="filter-buttons">
                    <button class="filter-status active" data-status="all">All</button>
                    <button class="filter-status" data-status="completed">Completed</button>
                    <button class="filter-status" data-status="running">Running</button>
                    <button class="filter-status" data-status="failed">Failed</button>
                </div>
            </div>
            
            <div class="filter-group">
                <label for="sort-select">Sort by:</label>
                <select id="sort-select" class="form-select">
                    <option value="date">Date (Newest)</option>
                    <option value="vulnerabilities">Vulnerabilities</option>
                    <option value="duration">Duration</option>
                    <option value="devices">Devices Found</option>
                </select>
            </div>
            
            <div class="filter-group">
                <label for="search-scans">Search:</label>
                <input type="text" id="search-scans" class="form-input" placeholder="Search by range or name...">
            </div>
        </div>
        `;

        scansSection.insertAdjacentHTML('beforebegin', filterHTML);
    }

    applyFilters() {
        const scans = document.querySelectorAll('.scan-item');
        let visibleCount = 0;

        scans.forEach(scan => {
            let visible = true;

            // Apply filters
            if (this.scanFilters.severity !== 'all') {
                const severity = scan.dataset.severity;
                visible = visible && (severity === this.scanFilters.severity);
            }

            if (this.scanFilters.status !== 'all') {
                const status = scan.dataset.status;
                visible = visible && (status === this.scanFilters.status);
            }

            if (this.scanFilters.searchTerm) {
                const text = scan.textContent.toLowerCase();
                visible = visible && text.includes(this.scanFilters.searchTerm);
            }

            scan.style.display = visible ? 'block' : 'none';
            if (visible) visibleCount++;
        });

        // Show "no results" message if needed
        this.updateEmptyState(visibleCount === 0);
    }

    updateEmptyState(isEmpty) {
        let emptyMsg = document.querySelector('.scans-grid .empty-results-msg');
        if (isEmpty) {
            if (!emptyMsg) {
                const msg = document.createElement('p');
                msg.className = 'empty-results-msg';
                msg.textContent = 'No scans match the selected filters';
                document.querySelector('.scans-grid').appendChild(msg);
            }
        } else {
            if (emptyMsg) emptyMsg.remove();
        }
    }

    // ========================================================================
    // NOTIFICATIONS & ALERTS
    // ========================================================================

    setupNotifications() {
        // Create notification container
        if (!document.querySelector('.notification-container')) {
            const container = document.createElement('div');
            container.className = 'notification-container';
            document.body.appendChild(container);
        }
    }

    showNotification(message, type = 'info', duration = 3000) {
        const container = document.querySelector('.notification-container');
        if (!container) return;

        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${this.getTypeIcon(type)}"></i>
                <span>${message}</span>
            </div>
            <button class="notification-close" onclick="this.parentElement.remove()">×</button>
        `;

        container.appendChild(notification);

        if (duration > 0) {
            setTimeout(() => notification.remove(), duration);
        }

        return notification;
    }

    showError(message, duration = 5000) {
        return this.showNotification(message, 'error', duration);
    }

    showSuccess(message, duration = 3000) {
        return this.showNotification(message, 'success', duration);
    }

    showWarning(message, duration = 4000) {
        return this.showNotification(message, 'warning', duration);
    }

    getTypeIcon(type) {
        const icons = {
            'success': 'check-circle',
            'error': 'exclamation-circle',
            'warning': 'exclamation-triangle',
            'info': 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    // ========================================================================
    // KEYBOARD SHORTCUTS
    // ========================================================================

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl+Enter to start scan
            if (e.ctrlKey && e.key === 'Enter') {
                const scanBtn = document.querySelector('.btn-scan');
                if (scanBtn && scanBtn.offsetParent !== null) { // visible check
                    this.validateAndStartScan();
                }
            }

            // Ctrl+K to focus search
            if (e.ctrlKey && e.key === 'k') {
                e.preventDefault();
                const searchInput = document.getElementById('search-scans');
                if (searchInput) searchInput.focus();
            }

            // Escape to clear filters
            if (e.key === 'Escape') {
                this.clearFilters();
            }
        });
    }

    clearFilters() {
        this.scanFilters = { severity: 'all', status: 'all', searchTerm: '' };
        
        // Reset UI
        document.querySelectorAll('.filter-buttons button').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.severity === 'all' || btn.dataset.status === 'all');
        });
        
        const searchInput = document.getElementById('search-scans');
        if (searchInput) searchInput.value = '';
        
        this.applyFilters();
    }

    // ========================================================================
    // SCAN MANAGEMENT
    // ========================================================================

    startScan() {
        this.showSuccess('Scan started successfully!');
        // Call existing scan start function if available
        if (window.startScan) {
            window.startScan();
        }
    }

    // ========================================================================
    // RESULTS DISPLAY ENHANCEMENTS
    // ========================================================================

    displayResultsWithPagination(devices) {
        const itemsPerPage = 10;
        let currentPage = 1;

        const createPagination = (total) => {
            const pages = Math.ceil(total / itemsPerPage);
            if (pages <= 1) return '';

            let html = '<div class="pagination">';
            for (let i = 1; i <= pages; i++) {
                html += `<button class="page-btn ${i === 1 ? 'active' : ''}" data-page="${i}">${i}</button>`;
            }
            html += '</div>';
            return html;
        };

        const showPage = (page) => {
            const start = (page - 1) * itemsPerPage;
            const end = start + itemsPerPage;
            const pageDevices = devices.slice(start, end);

            const container = document.getElementById('results-container');
            container.innerHTML = pageDevices.map(device => `
                <div class="device-result">
                    <div class="device-header">
                        <span class="device-ip">${device.ip || 'Unknown'}</span>
                        <span class="device-manufacturer">${device.manufacturer || 'Unknown'}</span>
                    </div>
                    <div class="device-details">
                        ${device.vulnerabilities ? `<span class="device-vulns">⚠️ ${device.vulnerabilities.length} vulnerabilities</span>` : ''}
                        ${device.ports ? `<span class="device-ports">🔌 ${device.ports.length} open ports</span>` : ''}
                    </div>
                </div>
            `).join('');

            container.insertAdjacentHTML('afterend', createPagination(devices.length));

            // Pagination event listeners
            document.querySelectorAll('.page-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    currentPage = parseInt(btn.dataset.page);
                    document.querySelectorAll('.page-btn').forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    showPage(currentPage);
                });
            });
        };

        showPage(1);
    }
}

// Initialize enhanced UI when DOM is ready
let enhancedUI = null;
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        enhancedUI = new EnhancedUI();
    });
} else {
    enhancedUI = new EnhancedUI();
}

// Export for use in other scripts
if (typeof window !== 'undefined') {
    window.EnhancedUI = EnhancedUI;
}
