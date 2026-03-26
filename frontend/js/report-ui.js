/* ===================================
  REPORT GENERATION UI MODULE
  Handles report generation, viewing, and download
  =================================== */

class ReportUI {
    constructor() {
        this.currentScanId = null;
        this.currentReport = null;
        this.reportGenerating = false;
        this.initUI();
    }

    initUI() {
        // Create report panel in DOM
        this.createReportPanel();
        this.setupEventListeners();
    }

    createReportPanel() {
        // Check if report panel already exists
        if (document.getElementById('report-panel')) return;

        const reportHTML = `
        <div id="report-panel" class="report-panel" style="display: none;">
            <div class="report-header">
                <h3>📊 Report Generation</h3>
                <button class="close-btn" onclick="reportUI.closeReportPanel()">×</button>
            </div>
            
            <div class="report-body">
                <!-- Report Generation Status -->
                <div id="report-status" class="report-section" style="display: none;">
                    <div class="status-message" id="report-status-message"></div>
                    <div class="progress-bar" id="report-progress">
                        <div class="progress-fill"></div>
                    </div>
                </div>

                <!-- Report Preview -->
                <div id="report-preview" class="report-section" style="display: none;">
                    <div class="preview-header">
                        <h4>Report Preview</h4>
                        <span class="timestamp" id="report-timestamp"></span>
                    </div>

                    <!-- Quick Stats -->
                    <div class="stats-grid">
                        <div class="stat-item">
                            <div class="stat-value" id="stat-hosts">0</div>
                            <div class="stat-label">Hosts Scanned</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value" id="stat-cctv">0</div>
                            <div class="stat-label">CCTV Devices</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value" id="stat-vulns">0</div>
                            <div class="stat-label">Vulnerabilities</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value" id="stat-risk">N/A</div>
                            <div class="stat-label">Risk Level</div>
                        </div>
                    </div>

                    <!-- Risk Summary -->
                    <div class="risk-summary">
                        <h5>Vulnerability Summary</h5>
                        <div class="risk-bars">
                            <div class="risk-item">
                                <span class="risk-label critical">Critical</span>
                                <div class="risk-bar">
                                    <div class="risk-fill critical" id="risk-critical"></div>
                                </div>
                                <span class="risk-count" id="count-critical">0</span>
                            </div>
                            <div class="risk-item">
                                <span class="risk-label high">High</span>
                                <div class="risk-bar">
                                    <div class="risk-fill high" id="risk-high"></div>
                                </div>
                                <span class="risk-count" id="count-high">0</span>
                            </div>
                            <div class="risk-item">
                                <span class="risk-label medium">Medium</span>
                                <div class="risk-bar">
                                    <div class="risk-fill medium" id="risk-medium"></div>
                                </div>
                                <span class="risk-count" id="count-medium">0</span>
                            </div>
                            <div class="risk-item">
                                <span class="risk-label low">Low</span>
                                <div class="risk-bar">
                                    <div class="risk-fill low" id="risk-low"></div>
                                </div>
                                <span class="risk-count" id="count-low">0</span>
                            </div>
                        </div>
                    </div>

                    <!-- Recommendations -->
                    <div class="recommendations-section">
                        <h5>Key Recommendations</h5>
                        <div id="recommendations-list" class="recommendations-list"></div>
                    </div>

                    <!-- Export Options -->
                    <div class="export-section">
                        <h5>Export Report</h5>
                        <div class="export-buttons">
                            <button class="btn-export" onclick="reportUI.exportReport('json')">
                                📄 JSON Export
                            </button>
                            <button class="btn-export" onclick="reportUI.exportReport('html')">
                                🌐 HTML Export
                            </button>
                            <button class="btn-export" onclick="reportUI.viewFullReport()">
                                👁️ View Full Report
                            </button>
                        </div>
                    </div>
                </div>

                <!-- No Report Message -->
                <div id="report-empty" class="empty-state" style="display: none;">
                    <p>No report generated yet.</p>
                    <p>Complete a scan and generate a report to see results here.</p>
                </div>

                <!-- Error Message -->
                <div id="report-error" class="error-box" style="display: none;">
                    <span id="report-error-message"></span>
                </div>
            </div>

            <!-- Report Actions -->
            <div class="report-footer">
                <button class="btn btn-primary" id="btn-generate-report" onclick="reportUI.generateReport()">
                    Generate Report
                </button>
                <button class="btn btn-secondary" onclick="reportUI.closeReportPanel()">
                    Close
                </button>
            </div>
        </div>`;

        // Insert at end of body
        document.body.insertAdjacentHTML('beforeend', reportHTML);
    }

    setupEventListeners() {
        // Listen for scan completion to enable report generation
        if (window.socket) {
            window.socket.on('scan_complete', (data) => {
                this.currentScanId = data.scan_id || data.scanId;
                this.onScanComplete();
            });
        }
    }

    onScanComplete() {
        // Show notification
        showNotification('Scan complete! You can now generate a report.', 'success');
        
        // Show report generation button if results panel exists
        const resultsSection = document.querySelector('.results-section');
        if (resultsSection) {
            const reportBtn = document.createElement('button');
            reportBtn.className = 'btn btn-primary';
            reportBtn.innerHTML = '📊 Generate Report';
            reportBtn.onclick = () => this.showReportPanel();
            
            const actionContainer = resultsSection.querySelector('.action-buttons');
            if (actionContainer) {
                actionContainer.appendChild(reportBtn);
            }
        }
    }

    showReportPanel() {
        const panel = document.getElementById('report-panel');
        if (panel) {
            panel.style.display = 'block';
            this.resetReportDisplay();
        }
    }

    closeReportPanel() {
        const panel = document.getElementById('report-panel');
        if (panel) {
            panel.style.display = 'none';
        }
    }

    resetReportDisplay() {
        document.getElementById('report-status').style.display = 'none';
        document.getElementById('report-preview').style.display = 'none';
        document.getElementById('report-empty').style.display = 'block';
        document.getElementById('report-error').style.display = 'none';
    }

    async generateReport() {
        if (!this.currentScanId) {
            this.showError('No active scan to generate report for.');
            return;
        }

        if (this.reportGenerating) {
            this.showError('Report is already being generated.');
            return;
        }

        this.reportGenerating = true;
        const btn = document.getElementById('btn-generate-report');
        const originalText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '⏳ Generating...';

        try {
            // Show status
            document.getElementById('report-status').style.display = 'block';
            document.getElementById('report-empty').style.display = 'none';
            document.getElementById('report-error').style.display = 'none';

            const response = await fetch(`/api/scan/${this.currentScanId}/report`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Report generation failed');
            }

            const result = await response.json();
            this.currentReport = result;
            this.displayReport(result);

            showNotification('Report generated successfully!', 'success');

        } catch (error) {
            console.error('Report generation error:', error);
            this.showError(`Error: ${error.message}`);
        } finally {
            this.reportGenerating = false;
            btn.disabled = false;
            btn.innerHTML = originalText;
            document.getElementById('report-status').style.display = 'none';
        }
    }

    displayReport(reportData) {
        try {
            const preview = reportData.preview || {};
            const stats = preview.statistics || {};
            const risk = preview.risk_level || {};

            // Update statistics
            document.getElementById('stat-hosts').textContent = stats.total_hosts || 0;
            document.getElementById('stat-cctv').textContent = stats.cctv_devices || 0;
            document.getElementById('stat-vulns').textContent = stats.total_vulnerabilities || 0;
            document.getElementById('stat-risk').textContent = risk.rating || 'N/A';
            document.getElementById('report-timestamp').textContent = 
                `Generated: ${new Date(reportData.generated_at).toLocaleString()}`;

            // Update risk bars
            const severity = preview.severity_summary || 
                           reportData.enriched_data?.risk_summary || {};
            
            document.getElementById('count-critical').textContent = severity.critical || 0;
            document.getElementById('count-high').textContent = severity.high || 0;
            document.getElementById('count-medium').textContent = severity.medium || 0;
            document.getElementById('count-low').textContent = severity.low || 0;

            // Scale bars based on max severity
            const maxCount = Math.max(
                severity.critical || 0,
                severity.high || 0,
                severity.medium || 0,
                severity.low || 0,
                1
            );

            const setCriticalWidth = () => {
                const width = ((severity.critical || 0) / maxCount) * 100;
                document.getElementById('risk-critical').style.width = width + '%';
            };
            const setHighWidth = () => {
                const width = ((severity.high || 0) / maxCount) * 100;
                document.getElementById('risk-high').style.width = width + '%';
            };
            const setMediumWidth = () => {
                const width = ((severity.medium || 0) / maxCount) * 100;
                document.getElementById('risk-medium').style.width = width + '%';
            };
            const setLowWidth = () => {
                const width = ((severity.low || 0) / maxCount) * 100;
                document.getElementById('risk-low').style.width = width + '%';
            };

            setCriticalWidth();
            setHighWidth();
            setMediumWidth();
            setLowWidth();

            // Display recommendations
            const recList = document.getElementById('recommendations-list');
            recList.innerHTML = '';
            const recommendations = preview.recommendations || [];
            
            if (recommendations.length === 0) {
                recList.innerHTML = '<p style="color: #999;">No critical recommendations</p>';
            } else {
                recommendations.forEach(rec => {
                    const item = document.createElement('div');
                    item.className = 'recommendation-item';
                    item.innerHTML = `
                        <strong>[${rec.priority || 'INFO'}]</strong>
                        <p>${rec.recommendation || 'N/A'}</p>
                        <small>Action: ${rec.action || 'N/A'}</small>
                    `;
                    recList.appendChild(item);
                });
            }

            // Show preview, hide empty state
            document.getElementById('report-preview').style.display = 'block';
            document.getElementById('report-empty').style.display = 'none';

        } catch (error) {
            console.error('Error displaying report:', error);
            this.showError('Error displaying report data');
        }
    }

    async exportReport(format) {
        if (!this.currentScanId) {
            this.showError('No report available for export');
            return;
        }

        try {
            const response = await fetch(`/api/scan/${this.currentScanId}/report/export/${format}`);
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Export failed');
            }

            // Create download
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `VAPT_Report_${this.currentScanId}.${format}`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();

            showNotification(`Report exported as ${format.toUpperCase()}`, 'success');

        } catch (error) {
            console.error('Export error:', error);
            this.showError(`Export failed: ${error.message}`);
        }
    }

    viewFullReport() {
        if (!this.currentReport) {
            this.showError('No report available');
            return;
        }

        // Open report details in new modal or window
        const modal = this.createReportModal(this.currentReport);
        modal.style.display = 'block';
    }

    createReportModal(reportData) {
        // Check if modal already exists
        let modal = document.getElementById('report-modal');
        if (modal) {
            modal.remove();
        }

        const reports = reportData.reports || {};
        const execSummary = reports.executive_summary || {};

        const modalHTML = `
        <div id="report-modal" class="modal" style="display: block;">
            <div class="modal-content report-modal-content">
                <div class="modal-header">
                    <h2>${execSummary.title || 'Report'}</h2>
                    <button class="close-btn" onclick="this.closest('.modal').remove()">×</button>
                </div>
                <div class="modal-body">
                    <div class="report-content">
                        ${this.formatReportSections(execSummary.sections || [])}
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-primary" onclick="reportUI.exportReport('html')">Export as HTML</button>
                    <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Close</button>
                </div>
            </div>
        </div>`;

        document.body.insertAdjacentHTML('beforeend', modalHTML);
        return document.getElementById('report-modal');
    }

    formatReportSections(sections) {
        return sections.map(section => `
            <div class="report-section">
                <h3>${section.heading || ''}</h3>
                <div class="section-content">
                    ${section.content ? `<p>${section.content}</p>` : ''}
                    ${section.items ? `<ul>${section.items.map(item => `<li>${item}</li>`).join('')}</ul>` : ''}
                </div>
            </div>
        `).join('');
    }

    showError(message) {
        const errorDiv = document.getElementById('report-error');
        const errorMsg = document.getElementById('report-error-message');
        if (errorDiv && errorMsg) {
            errorMsg.textContent = message;
            errorDiv.style.display = 'block';
        }
        console.error('ReportUI Error:', message);
    }
}

// Initialize report UI when document is ready
let reportUI = null;
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        reportUI = new ReportUI();
    });
} else {
    reportUI = new ReportUI();
}
