// frontend/static/app.js
class ArgusScanner {
    constructor() {
        console.log('ArgusScanner initializing...');
        this.initializeEventListeners();
        this.currentScanData = null;
    }

    initializeEventListeners() {
        console.log('Setting up event listeners...');
        
        // Form submission
        const scanForm = document.getElementById('scanForm');
        if (scanForm) {
            scanForm.addEventListener('submit', (e) => {
                e.preventDefault();
                console.log('Form submitted');
                this.startScan();
            });
        }

        // Demo scan button
        const demoBtn = document.getElementById('demoBtn');
        if (demoBtn) {
            demoBtn.addEventListener('click', () => {
                console.log('Demo button clicked');
                this.startDemoScan();
            });
        } else {
            console.error('Demo button not found!');
        }

        // Tab navigation
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.switchTab(e.target.dataset.tab);
            });
        });

        // Export button
        const exportBtn = document.getElementById('exportBtn');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                this.exportReport();
            });
        }

        console.log('Event listeners set up successfully');
    }

    async startScan() {
        const formData = new FormData(document.getElementById('scanForm'));
        const repositoryUrl = formData.get('repository_url');
        const localPath = formData.get('scan_local_path');

        if (!repositoryUrl && !localPath) {
            alert('Please provide either a repository URL or local path');
            return;
        }

        this.showLoading();

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail);
            }

            const data = await response.json();
            this.currentScanData = data;
            this.displayResults(data);

        } catch (error) {
            this.showError(error.message);
        }
    }

    async startDemoScan() {
        console.log('Starting demo scan...');
        this.showLoading();

        try {
            console.log('Sending request to /api/demo-scan');
            const response = await fetch('/api/demo-scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            console.log('Response status:', response.status);

            if (!response.ok) {
                const error = await response.json();
                console.error('API Error:', error);
                throw new Error(error.detail || 'Demo scan failed');
            }

            const data = await response.json();
            console.log('Demo scan successful:', data);
            this.currentScanData = data;
            this.displayResults(data);

        } catch (error) {
            console.error('Demo scan error:', error);
            this.showError(error.message);
        }
    }

    showLoading() {
        console.log('Showing loading...');
        this.hideAllSections();
        const loadingSection = document.getElementById('loadingSection');
        if (loadingSection) {
            loadingSection.style.display = 'block';
            
            // Simulate loading steps
            setTimeout(() => {
                const step1 = document.getElementById('step1');
                if (step1) step1.classList.add('active');
            }, 500);
            setTimeout(() => {
                const step2 = document.getElementById('step2');
                if (step2) step2.classList.add('active');
            }, 2000);
            setTimeout(() => {
                const step3 = document.getElementById('step3');
                if (step3) step3.classList.add('active');
            }, 4000);
        } else {
            console.error('Loading section not found!');
        }
    }

    displayResults(data) {
        console.log('Full API response:', data);
        
        this.hideAllSections();
        const resultsSection = document.getElementById('resultsSection');
        if (!resultsSection) {
            console.error('Results section not found');
            return;
        }
        
        resultsSection.style.display = 'block';
        
        // Extract data with correct structure from API response
        const report = data.report;
        const scanResults = data.scan_results;
        const vulnerabilityMatches = data.vulnerability_matches || [];
        
        console.log('Extracted data:', {
            report: report,
            scanResults: scanResults,
            vulnerabilityMatches: vulnerabilityMatches
        });
        
        // Update overview
        this.updateOverview(report, scanResults, vulnerabilityMatches);
        
        // Update all tabs
        this.updateFrameworksTab(scanResults.frameworks || []);
        this.updatePatternsTab(scanResults.code_patterns || []);
        this.updateVulnerabilitiesTab(vulnerabilityMatches);
        this.updateRecommendationsTab(report.recommendations || []);
        this.updateExecutiveSummary(report.executive_summary || {});
    }

    updateOverview(report, scanResults, vulnerabilityMatches) {
        console.log('Updating overview with:', {
            report: report,
            scanResults: scanResults,
            vulnerabilityMatches: vulnerabilityMatches
        });
        
        // Update risk score
        const riskScore = document.getElementById('riskScore');
        const riskLevel = document.getElementById('riskLevel');
        
        if (riskScore && riskLevel && report && report.risk_assessment) {
            riskScore.textContent = (report.risk_assessment.overall_score || 0) + '/10';
            riskLevel.textContent = report.risk_assessment.risk_level || 'UNKNOWN';
        } else {
            if (riskScore) riskScore.textContent = '0/10';
            if (riskLevel) riskLevel.textContent = 'UNKNOWN';
        }
        
        // Update stats - use the actual scan_results data
        const filesScanned = document.getElementById('filesScanned');
        const patternsFound = document.getElementById('patternsFound');
        const vulnerabilities = document.getElementById('vulnerabilities');
        
        if (filesScanned) {
            const fileCount = scanResults?.file_count || 0;
            filesScanned.textContent = fileCount;
            console.log('Set files scanned to:', fileCount);
        }
        
        if (patternsFound) {
            const patternCount = (scanResults?.code_patterns || []).length;
            patternsFound.textContent = patternCount;
            console.log('Set patterns found to:', patternCount);
        }
        
        if (vulnerabilities) {
            const vulnCount = vulnerabilityMatches.length;
            vulnerabilities.textContent = vulnCount;
            console.log('Set vulnerabilities to:', vulnCount);
        }
        
        // Update risk score card color based on level
        const riskCard = document.querySelector('.risk-score-card');
        if (riskCard && report && report.risk_assessment) {
            const level = report.risk_assessment.risk_level;
            if (level === 'HIGH') {
                riskCard.style.background = 'linear-gradient(135deg, #ff6b6b 0%, #ff8e53 100%)';
            } else if (level === 'MEDIUM') {
                riskCard.style.background = 'linear-gradient(135deg, #feca57 0%, #ff9ff3 100%)';
            } else {
                riskCard.style.background = 'linear-gradient(135deg, #48dbfb 0%, #0abde3 100%)';
            }
        }
    }

    updateExecutiveSummary(summary) {
        const container = document.getElementById('executiveSummary');
        if (!container) {
            console.error('Executive summary container not found');
            return;
        }
        
        console.log('Updating executive summary with:', summary);
        
        const keyFindings = summary.key_findings || ['Demo scan completed successfully', 'Security analysis in progress'];
        
        let html = `
            <div class="summary-card">
                <h4>Key Findings</h4>
                <ul>
                    ${keyFindings.map(finding => `<li>${finding}</li>`).join('')}
                </ul>
            </div>
        `;
        
        if (summary.immediate_actions_required) {
            html += `
                <div class="alert alert-warning">
                    <strong>⚠️ Immediate Actions Required</strong>
                    <p>High-severity security patterns detected that require immediate attention.</p>
                </div>
            `;
        }
        
        container.innerHTML = html;
    }

    updateFrameworksTab(frameworks) {
        const container = document.getElementById('frameworksList');
        if (!container) {
            console.error('Frameworks container not found');
            return;
        }
        
        console.log('Updating frameworks with:', frameworks);
        
        if (!frameworks || frameworks.length === 0) {
            container.innerHTML = '<p>No AI/ML frameworks detected.</p>';
            return;
        }

        const html = frameworks.map(framework => 
            `<span class="framework-tag">${framework}</span>`
        ).join('');
        
        container.innerHTML = `
            <p>The following AI/ML frameworks were detected:</p>
            <div class="frameworks-container" style="margin-top: 15px;">${html}</div>
        `;
    }

    updatePatternsTab(patterns) {
        const container = document.getElementById('patternsList');
        if (!container) {
            console.error('Patterns container not found');
            return;
        }
        
        console.log('Updating patterns with:', patterns?.length, 'patterns');
        
        if (!patterns || patterns.length === 0) {
            container.innerHTML = '<p>No security patterns detected.</p>';
            return;
        }

        // Show first 10 patterns to avoid overwhelming the UI
        const displayPatterns = patterns.slice(0, 10);
        
        const html = displayPatterns.map(pattern => `
            <div class="pattern-item ${(pattern.severity || 'medium').toLowerCase()}-severity">
                <h4>${pattern.description || 'Security Pattern'}</h4>
                <p><strong>Type:</strong> ${pattern.type || 'Unknown'}</p>
                <p><strong>File:</strong> ${pattern.file || 'Unknown'}${pattern.line ? ':' + pattern.line : ''}</p>
                <p><strong>Severity:</strong> ${pattern.severity || 'MEDIUM'}</p>
                <p><strong>Context:</strong> <code>${(pattern.context || 'No context available').substring(0, 100)}...</code></p>
            </div>
        `).join('');
        
        if (patterns.length > 10) {
            container.innerHTML = html + `<p><strong>Showing 10 of ${patterns.length} patterns found.</strong></p>`;
        } else {
            container.innerHTML = html;
        }
    }

    updateVulnerabilitiesTab(vulnerabilities) {
        const container = document.getElementById('vulnerabilitiesList');
        if (!container) {
            console.error('Vulnerabilities container not found');
            return;
        }
        
        console.log('Updating vulnerabilities with:', vulnerabilities?.length, 'items');
        
        if (!vulnerabilities || vulnerabilities.length === 0) {
            container.innerHTML = '<p>No similar vulnerabilities found in knowledge base.</p>';
            return;
        }

        const html = vulnerabilities.map(vuln => `
            <div class="vulnerability-item">
                <h4>[${vuln.source || 'Unknown'}] ${vuln.title || 'Untitled Vulnerability'}</h4>
                <p>${(vuln.description || 'No description available').substring(0, 300)}...</p>
                <div class="vuln-meta">
                    <span class="relevance">Relevance: ${((vuln.relevance_score || 0) * 100).toFixed(1)}%</span>
                    <span class="severity">Severity: ${vuln.severity || 'MEDIUM'}</span>
                </div>
            </div>
        `).join('');
        
        container.innerHTML = html;
    }

    updateRecommendationsTab(recommendations) {
        const container = document.getElementById('recommendationsList');
        if (!container) {
            console.error('Recommendations container not found');
            return;
        }
        
        console.log('Updating recommendations with:', recommendations?.length, 'items');
        
        if (!recommendations || recommendations.length === 0) {
            container.innerHTML = '<p>No specific recommendations generated.</p>';
            return;
        }

        const html = recommendations.map(rec => `
            <div class="recommendation-item">
                <h4>[${rec.priority || 'MEDIUM'}] ${rec.title || 'Security Recommendation'}</h4>
                <p>${rec.description || 'No description available'}</p>
                ${rec.action_items && rec.action_items.length > 0 ? `
                    <h5>Action Items:</h5>
                    <ul>
                        ${rec.action_items.map(item => `<li>${item}</li>`).join('')}
                    </ul>
                ` : ''}
            </div>
        `).join('');
        
        container.innerHTML = html;
    }

    switchTab(tabName) {
        console.log('Switching to tab:', tabName);
        
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        const activeTab = document.querySelector(`[data-tab="${tabName}"]`);
        if (activeTab) {
            activeTab.classList.add('active');
        }

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        const activeContent = document.getElementById(tabName);
        if (activeContent) {
            activeContent.classList.add('active');
        }
    }

    async exportReport() {
        if (!this.currentScanData) {
            alert('No scan data to export');
            return;
        }

        try {
            const response = await fetch('/api/export-pdf', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(this.currentScanData)
            });

            if (!response.ok) {
                throw new Error('Failed to generate PDF');
            }

            // Create download link for PDF
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = `argus_security_report_${new Date().toISOString().slice(0,10)}.pdf`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            console.log('PDF export successful');
            
        } catch (error) {
            console.error('Export failed:', error);
            alert('Failed to export PDF: ' + error.message);
        }
    }

    showError(message) {
        console.log('Showing error:', message);
        this.hideAllSections();
        const errorSection = document.getElementById('errorSection');
        const errorMessage = document.getElementById('errorMessage');
        
        if (errorSection && errorMessage) {
            errorSection.style.display = 'block';
            errorMessage.textContent = message;
        } else {
            console.error('Error section elements not found!');
            // Fallback alert
            alert('Error: ' + message);
        }
    }

    hideAllSections() {
        const sections = ['loadingSection', 'resultsSection', 'errorSection'];
        sections.forEach(sectionId => {
            const section = document.getElementById(sectionId);
            if (section) {
                section.style.display = 'none';
            }
        });
        
        // Reset loading steps
        document.querySelectorAll('.step').forEach(step => {
            step.classList.remove('active');
        });
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, initializing ArgusScanner...');
    new ArgusScanner();
});

// Add some additional CSS for alerts and enhanced styling
const additionalCSS = `
.alert {
    padding: 20px;
    margin: 20px 0;
    border-radius: 12px;
    border: 1px solid;
    backdrop-filter: blur(10px);
}

.alert-warning {
    background: rgba(255, 165, 2, 0.1);
    border-color: rgba(255, 165, 2, 0.3);
    color: #ffa502;
}

.summary-card {
    background: rgba(255, 255, 255, 0.03);
    padding: 32px;
    border-radius: 16px;
    margin: 20px 0;
    border: 1px solid rgba(255, 255, 255, 0.1);
    backdrop-filter: blur(10px);
}

.vuln-meta {
    display: flex;
    gap: 16px;
    margin-top: 16px;
    font-size: 0.9rem;
}

.relevance, .severity {
    padding: 6px 12px;
    border-radius: 20px;
    background: rgba(255, 255, 255, 0.1);
    border: 1px solid rgba(255, 255, 255, 0.2);
    backdrop-filter: blur(10px);
}

.frameworks-container {
    margin-top: 15px;
}

code {
    background: rgba(0, 212, 255, 0.1);
    color: var(--accent-blue, #00d4ff);
    padding: 4px 8px;
    border-radius: 6px;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 0.9rem;
    border: 1px solid rgba(0, 212, 255, 0.2);
}

@keyframes slideInUp {
    from {
        opacity: 0;
        transform: translateY(30px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}
`;

// Inject additional CSS
const style = document.createElement('style');
style.textContent = additionalCSS;
document.head.appendChild(style);