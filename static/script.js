// ZeroDayGuard - JavaScript Frontend

// Global state for tracking scan results
window.currentScanResult = null;
window.previousScanResult = null;

document.addEventListener('DOMContentLoaded', function() {
    // Elements - Single File
    const codeEditor = document.getElementById('codeEditor');
    const scanBtn = document.getElementById('scanBtn');
    const clearBtn = document.getElementById('clearBtn');
    const languageSelect = document.getElementById('languageSelect');
    const scanStatus = document.getElementById('scanStatus');
    const resultsContainer = document.getElementById('resultsContainer');
    const examplesContainer = document.getElementById('examplesContainer');
    
    // Elements - Project Scanner
    const projectFile = document.getElementById('projectFile');
    const browseBtn = document.getElementById('browseBtn');
    const uploadArea = document.getElementById('uploadArea');
    const uploadStatus = document.getElementById('uploadStatus');
    const projectResults = document.getElementById('projectResults');
    const projectReportContainer = document.getElementById('projectReportContainer');
    const newScanBtn = document.getElementById('newScanBtn');
    
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const tab = this.dataset.tab;
            
            // Update active tab button
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            
            // Show corresponding content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
                content.style.display = 'none';
            });
            
            const targetContent = tab === 'single' ? 
                document.getElementById('single-scanner') : 
                document.getElementById('project-scanner');
            
            targetContent.classList.add('active');
            targetContent.style.display = 'block';
        });
    });
    
    // Project upload handlers
    browseBtn.addEventListener('click', () => projectFile.click());
    projectFile.addEventListener('change', handleProjectUpload);
    
    if (newScanBtn) {
        newScanBtn.addEventListener('click', resetProjectScanner);
    }
    
    // Drag and drop
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('dragging');
    });
    
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('dragging');
    });
    
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('dragging');
        
        const files = e.dataTransfer.files;
        if (files.length > 0 && files[0].name.endsWith('.zip')) {
            projectFile.files = files;
            handleProjectUpload();
        } else {
            alert('Please drop a ZIP file');
        }
    });
    
    uploadArea.addEventListener('click', (e) => {
        if (e.target === uploadArea || e.target.closest('.upload-area')) {
            projectFile.click();
        }
    });
    
    // Load examples
    loadExamples();
    
    // Event listeners
    scanBtn.addEventListener('click', () => window.scanCode());
    clearBtn.addEventListener('click', clearEditor);
    
    async function loadExamples() {
        try {
            const response = await fetch('/api/examples');
            const examples = await response.json();
            
            examplesContainer.innerHTML = '';
            
            for (const [key, example] of Object.entries(examples)) {
                const card = document.createElement('div');
                card.className = 'example-card';
                card.innerHTML = `
                    <div class="example-name">${example.name}</div>
                    <div class="example-cwe">${example.cwe}</div>
                `;
                card.addEventListener('click', () => {
                    codeEditor.value = example.code;
                });
                examplesContainer.appendChild(card);
            }
        } catch (error) {
            console.error('Failed to load examples:', error);
        }
    }
    
    // Make scanCode globally accessible for rescan
    window.scanCode = async function() {
        const code = codeEditor.value.trim();
        
        if (!code) {
            alert('Please enter some code to scan');
            return;
        }
        
        // Update status
        scanStatus.textContent = 'Scanning...';
        scanStatus.className = 'scan-status scanning';
        scanBtn.disabled = true;
        
        // Show loading
        resultsContainer.innerHTML = `
            <div class="empty-state">
                <svg class="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                    <circle cx="12" cy="12" r="10" stroke-width="2"/>
                    <path d="M12 6v6l4 2" stroke-width="2"/>
                </svg>
                <p>Analyzing code for vulnerabilities...</p>
            </div>
        `;
        
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    code: code,
                    language: languageSelect.value
                })
            });
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Scan failed: ${response.status} - ${errorText}`);
            }
            
            const result = await response.json();
            
            console.log('Scan result received:', result);
            
            // Store previous and current results for comparison
            if (window.currentScanResult) {
                window.previousScanResult = window.currentScanResult;
            }
            window.currentScanResult = result;
            
            console.log('Stored - Previous:', window.previousScanResult, 'Current:', window.currentScanResult);
            
            displayResults(result, window.previousScanResult);
            
            scanStatus.textContent = 'Scan complete';
            scanStatus.className = 'scan-status';
            
        } catch (error) {
            console.error('Scan error:', error);
            
            // Check if it's a network error
            if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
                resultsContainer.innerHTML = `
                    <div class="empty-state">
                        <p style="color: var(--danger);">❌ Cannot connect to server. Please check if the server is running on http://localhost:5000</p>
                    </div>
                `;
                showNotification('❌ Server connection failed. Is the Flask server running?', 'error');
            } else {
                resultsContainer.innerHTML = `
                    <div class="empty-state">
                        <p style="color: var(--danger);">Error: ${error.message}</p>
                    </div>
                `;
                showNotification('❌ Scan failed: ' + error.message, 'error');
            }
            scanStatus.textContent = 'Scan failed';
            scanStatus.className = 'scan-status';
        } finally {
            scanBtn.disabled = false;
        }
    }
    
    function displayResults(result, previousResult = null) {
        const isVulnerable = result.vulnerable;
        const riskLevel = result.risk_level.toLowerCase();
        
        // Calculate improvement - ALWAYS show if there's a previous result
        let improvementHtml = '';
        if (previousResult && previousResult.cwe_patterns) {
            const prevVulnCount = previousResult.cwe_patterns.length || 0;
            const currVulnCount = result.cwe_patterns ? result.cwe_patterns.length : 0;
            const fixed = prevVulnCount - currVulnCount;
            const prevConfidence = previousResult.confidence || 0;
            const currConfidence = result.confidence || 0;
            
            console.log('Comparison:', { prevVulnCount, currVulnCount, fixed, prevConfidence, currConfidence });
            
            if (fixed > 0) {
                improvementHtml = `
                    <div style="background: linear-gradient(135deg, rgba(34, 197, 94, 0.15), rgba(34, 197, 94, 0.05)); border: 3px solid var(--success); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; animation: slideDown 0.5s ease-out, pulse 0.5s ease-out;">
                        <div style="font-size: 1.5rem; font-weight: 700; color: var(--success); margin-bottom: 0.75rem; text-align: center;">
                            🎉 Excellent! You Fixed ${fixed} Vulnerability${fixed > 1 ? 'ies' : ''}! 🎉
                        </div>
                        <div style="display: flex; justify-content: space-around; margin-top: 1rem; font-size: 1.1rem;">
                            <div style="text-align: center;">
                                <div style="color: var(--danger); font-weight: 600; font-size: 1.3rem;">${prevVulnCount}</div>
                                <div style="color: var(--text-secondary); font-size: 0.9rem;">Before</div>
                            </div>
                            <div style="color: var(--success); font-size: 2rem; align-self: center;">→</div>
                            <div style="text-align: center;">
                                <div style="color: var(--success); font-weight: 600; font-size: 1.3rem;">${currVulnCount}</div>
                                <div style="color: var(--text-secondary); font-size: 0.9rem;">After</div>
                            </div>
                        </div>
                        ${currConfidence > prevConfidence ? `
                            <div style="text-align: center; margin-top: 1rem; color: var(--success); font-weight: 600;">
                                📈 Confidence improved: ${prevConfidence}% → ${currConfidence}%
                            </div>
                        ` : ''}
                    </div>
                `;
                showNotification(`🎉 Amazing! Fixed ${fixed} vulnerability${fixed > 1 ? 'ies' : ''}!`, 'success');
            } else if (fixed < 0) {
                improvementHtml = `
                    <div style="background: rgba(239, 68, 68, 0.1); border: 2px solid var(--danger); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; animation: slideDown 0.5s ease-out;">
                        <div style="font-size: 1.1rem; font-weight: 600; color: var(--danger);">
                            ⚠️ New vulnerabilities detected: ${Math.abs(fixed)} more than before
                        </div>
                        <div style="color: var(--text-secondary); margin-top: 0.5rem;">
                            Previous: ${prevVulnCount} → Current: ${currVulnCount}
                        </div>
                    </div>
                `;
                showNotification(`⚠️ Warning: ${Math.abs(fixed)} new vulnerabilities found!`, 'warning');
            } else if (currVulnCount === 0 && prevVulnCount === 0) {
                improvementHtml = `
                    <div style="background: rgba(34, 197, 94, 0.1); border: 2px solid var(--success); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; animation: slideDown 0.5s ease-out;">
                        <div style="font-size: 1.2rem; font-weight: 600; color: var(--success); text-align: center;">
                            ✅ Perfect! Code remains secure - No vulnerabilities found!
                        </div>
                    </div>
                `;
                showNotification('✅ Code still secure!', 'success');
            } else {
                improvementHtml = `
                    <div style="background: rgba(234, 179, 8, 0.1); border: 2px solid var(--warning); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; animation: slideDown 0.5s ease-out;">
                        <div style="font-size: 1.1rem; font-weight: 600; color: var(--warning); text-align: center;">
                            📊 Re-scan Complete
                        </div>
                        <div style="color: var(--text-secondary); text-align: center; margin-top: 0.5rem;">
                            Still ${currVulnCount} vulnerability${currVulnCount > 1 ? 'ies' : ''} remaining - Keep fixing!
                        </div>
                    </div>
                `;
                showNotification(`📊 Re-scan done: ${currVulnCount} vulnerabilities remain`, 'info');
            }
        }
        
        let html = improvementHtml + `
            <div class="result-summary">
                <div class="vulnerability-badge ${isVulnerable ? 'vulnerable' : 'safe'}">
                    <span>${isVulnerable ? '⚠️ VULNERABLE' : '✅ SAFE'}</span>
                </div>
                
                <div style="margin-top: 1rem;">
                    <span class="risk-level ${riskLevel}">${result.risk_level} RISK</span>
                </div>
                
                <div class="confidence-bar">
                    <div class="confidence-label">
                        <span>Confidence</span>
                        <span><strong>${result.confidence}%</strong></span>
                    </div>
                    <div class="confidence-progress">
                        <div class="confidence-fill" style="width: ${result.confidence}%"></div>
                    </div>
                </div>
            </div>
        `;
        
        // CWE Patterns with detailed locations
        if (result.cwe_patterns && result.cwe_patterns.length > 0) {
            // Count fixable vulnerabilities
            const fixableCount = result.cwe_patterns.filter(cwe => typeof cwe === 'object' && cwe.cwe).length;
            
            html += `
                <div class="result-section">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                        <h4>🎯 Detected Vulnerabilities</h4>
                        ${fixableCount > 0 ? `<button class="btn btn-primary" onclick="fixAllVulnerabilities()" style="font-size: 0.9rem; padding: 0.6rem 1.2rem;">🔧 Fix All (${fixableCount})</button>` : ''}
                    </div>
                    <ul class="cwe-list">
                        ${result.cwe_patterns.map(cwe => {
                            // Check if cwe is an object (new format) or string (old format)
                            if (typeof cwe === 'object' && cwe.cwe) {
                                return `
                                    <li class="cwe-item" data-vuln='${JSON.stringify(cwe).replace(/'/g, "&apos;")}'>
                                        <div style="display: flex; justify-content: space-between; align-items: start; gap: 1rem;">
                                            <div style="flex: 1;">
                                                <div style="font-weight: 600; color: var(--danger);">${escapeHtml(cwe.cwe)}</div>
                                                <div style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.25rem;">
                                                    📍 Line ${cwe.line}: <code style="background: var(--bg-primary); padding: 0.2rem 0.4rem; border-radius: 3px;">${escapeHtml(cwe.code.substring(0, 60))}${cwe.code.length > 60 ? '...' : ''}</code>
                                                </div>
                                                ${cwe.description ? `<div style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.25rem;">${escapeHtml(cwe.description)}</div>` : ''}
                                            </div>
                                            <button class="btn btn-primary fix-btn" onclick="fixVulnerability(this)" style="padding: 0.5rem 1rem; font-size: 0.85rem; white-space: nowrap;">
                                                🔧 Fix
                                            </button>
                                        </div>
                                        <div class="fix-result" style="display: none; margin-top: 1rem; padding: 1rem; background: var(--bg-primary); border-radius: 6px; border-left: 3px solid var(--success);"></div>
                                    </li>
                                `;
                            } else {
                                return `<li class="cwe-item">${escapeHtml(cwe)}</li>`;
                            }
                        }).join('')}
                    </ul>
                </div>
            `;
        }
        
        // Dangerous Functions with locations
        if (result.dangerous_functions && result.dangerous_functions.length > 0) {
            html += `
                <div class="result-section">
                    <h4>⚠️ Dangerous Functions</h4>
                    <ul class="func-list">
                        ${result.dangerous_functions.map(func => {
                            // Check if func is an object (new format) or string (old format)
                            if (typeof func === 'object' && func.function) {
                                return `
                                    <li class="func-item">
                                        <div style="font-weight: 600;">${escapeHtml(func.function)}()</div>
                                        <div style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.25rem;">
                                            📍 Line ${func.line}: <code style="background: var(--bg-primary); padding: 0.2rem 0.4rem; border-radius: 3px;">${escapeHtml(func.code.substring(0, 60))}${func.code.length > 60 ? '...' : ''}</code>
                                        </div>
                                    </li>
                                `;
                            } else {
                                return `<li class="func-item">${escapeHtml(func)}()</li>`;
                            }
                        }).join('')}
                    </ul>
                </div>
            `;
        }
        
        // Recommendations
        if (result.recommendations && result.recommendations.length > 0) {
            html += `
                <div class="result-section">
                    <h4>💡 Security Recommendations</h4>
                    <ul class="rec-list">
                        ${result.recommendations.map(rec => `
                            <li class="rec-item">${escapeHtml(rec)}</li>
                        `).join('')}
                    </ul>
                </div>
            `;
        }
        
        // Code Metrics
        if (result.code_metrics) {
            const metrics = result.code_metrics;
            html += `
                <div class="result-section">
                    <h4>📊 Code Metrics</h4>
                    <div class="metrics-grid">
                        <div class="metric-card">
                            <div class="metric-value">${metrics.lines_of_code}</div>
                            <div class="metric-label">Lines of Code</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">${metrics.functions}</div>
                            <div class="metric-label">Functions</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">${metrics.variables}</div>
                            <div class="metric-label">Variables</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">${metrics.complexity.toFixed(1)}</div>
                            <div class="metric-label">Complexity</div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        resultsContainer.innerHTML = html;
        
        // Smooth scroll to results
        resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
    
    function clearEditor() {
        codeEditor.value = '';
        resultsContainer.innerHTML = `
            <div class="empty-state">
                <svg class="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                    <circle cx="12" cy="12" r="10" stroke-width="2"/>
                    <path d="M12 6v6l4 2" stroke-width="2"/>
                </svg>
                <p>Click "Scan Code" to analyze for vulnerabilities</p>
            </div>
        `;
        scanStatus.textContent = 'Ready to scan';
        scanStatus.className = 'scan-status';
    }
    
    function escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }
    
    async function handleProjectUpload() {
        const file = projectFile.files[0];
        
        if (!file) return;
        
        if (!file.name.endsWith('.zip')) {
            alert('Please select a ZIP file');
            return;
        }
        
        // Show upload status
        uploadArea.style.display = 'none';
        uploadStatus.style.display = 'block';
        
        const formData = new FormData();
        formData.append('project', file);
        
        try {
            const response = await fetch('/api/scan-project', {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                throw new Error('Upload failed');
            }
            
            const report = await response.json();
            displayProjectReport(report);
            
        } catch (error) {
            console.error('Upload error:', error);
            alert('Error scanning project: ' + error.message);
            resetProjectScanner();
        }
    }
    
    function displayProjectReport(report) {
        uploadStatus.style.display = 'none';
        projectResults.style.display = 'block';
        
        const summary = report.summary;
        const riskBreakdown = report.risk_breakdown;
        
        // Determine score color
        let scoreClass = 'high';
        if (summary.security_score < 50) scoreClass = 'low';
        else if (summary.security_score < 75) scoreClass = 'medium';
        
        let html = `
            <div class="security-score-card">
                <div class="score-circle ${scoreClass}" style="--score-percent: ${summary.security_score}%">
                    <div class="score-inner">
                        <span>${summary.security_score}</span>
                    </div>
                </div>
                <h3>Security Score</h3>
                <div class="risk-level ${summary.overall_risk.toLowerCase()}">${summary.overall_risk} RISK</div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-box-value">${summary.scanned_files}</div>
                    <div class="stat-box-label">Files Scanned</div>
                </div>
                <div class="stat-box">
                    <div class="stat-box-value" style="color: var(--danger)">${summary.vulnerable_files}</div>
                    <div class="stat-box-label">Vulnerable Files</div>
                </div>
                <div class="stat-box">
                    <div class="stat-box-value" style="color: var(--success)">${summary.safe_files}</div>
                    <div class="stat-box-label">Safe Files</div>
                </div>
                <div class="stat-box">
                    <div class="stat-box-value" style="color: var(--critical)">${riskBreakdown.critical}</div>
                    <div class="stat-box-label">Critical Issues</div>
                </div>
            </div>
        `;
        
        // Top vulnerabilities with Fix buttons
        if (report.top_vulnerabilities && report.top_vulnerabilities.length > 0) {
            const totalFixable = report.top_vulnerabilities.reduce((sum, v) => sum + (v.locations ? v.locations.length : 0), 0);
            
            html += `
                <div class="vulnerabilities-section">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                        <h4>Top Vulnerabilities Found</h4>
                        ${totalFixable > 0 ? `<button class="btn btn-primary" onclick="fixAllProjectVulnerabilities()" style="font-size: 0.9rem; padding: 0.6rem 1.2rem;">🔧 Fix All (${totalFixable})</button>` : ''}
                    </div>
            `;
            
            report.top_vulnerabilities.forEach(vuln => {
                // Handle both old format (affected_files) and new format (locations)
                if (vuln.locations && vuln.locations.length > 0) {
                    html += `<div class="cwe-group" style="margin-bottom: 1.5rem;">
                        <div style="font-weight: 600; color: var(--danger); font-size: 1.1rem; margin-bottom: 0.75rem;">
                            ${escapeHtml(vuln.cwe)}
                            <span style="color: var(--text-secondary); font-size: 0.9rem; font-weight: normal;"> - ${vuln.count} occurrence(s)</span>
                        </div>
                        <ul class="cwe-list" style="list-style: none; padding: 0;">`;
                    
                    vuln.locations.forEach(loc => {
                        const vulnData = {
                            cwe: vuln.cwe,
                            line: loc.line,
                            code: loc.code,
                            severity: loc.severity,
                            description: loc.description,
                            file: loc.file
                        };
                        
                        html += `
                            <li class="cwe-item" data-vuln='${JSON.stringify(vulnData).replace(/'/g, "&apos;")}' style="margin-bottom: 0.75rem;">
                                <div style="display: flex; justify-content: space-between; align-items: start; gap: 1rem;">
                                    <div style="flex: 1;">
                                        <div style="font-size: 0.85rem; color: var(--text-secondary);">
                                            📁 <strong>${escapeHtml(loc.file)}</strong> - Line ${loc.line}
                                        </div>
                                        <div style="font-size: 0.85rem; font-family: var(--font-mono); margin-top: 0.25rem;">
                                            <code style="background: var(--bg-primary); padding: 0.2rem 0.4rem; border-radius: 3px; display: inline-block; max-width: 600px; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(loc.code.substring(0, 80))}${loc.code.length > 80 ? '...' : ''}</code>
                                        </div>
                                        ${loc.description ? `<div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">${escapeHtml(loc.description)}</div>` : ''}
                                    </div>
                                    <button class="btn btn-primary fix-btn" onclick="fixVulnerability(this)" style="padding: 0.5rem 1rem; font-size: 0.85rem; white-space: nowrap;">
                                        🔧 Fix
                                    </button>
                                </div>
                                <div class="fix-result" style="display: none; margin-top: 1rem; padding: 1rem; background: var(--bg-primary); border-radius: 6px; border-left: 3px solid var(--success);"></div>
                            </li>
                        `;
                    });
                    
                    html += `</ul></div>`;
                } else {
                    // Fallback for old format
                    let locationInfo = '';
                    if (vuln.affected_files && vuln.affected_files.length > 0) {
                        locationInfo = vuln.affected_files.map(f => escapeHtml(f)).join(', ');
                    }
                    
                    html += `
                        <div class="vulnerability-item">
                            <div class="vulnerability-header">
                                <span class="vulnerability-cwe">${escapeHtml(vuln.cwe)}</span>
                                <span class="vulnerability-count">${vuln.count} occurrence(s)</span>
                            </div>
                            <div class="affected-files">
                                <strong>Locations:</strong> ${locationInfo || 'No location details available'}
                            </div>
                        </div>
                    `;
                }
            });
            
            html += `</div>`;
        }
        
        // Critical files
        if (report.critical_files && report.critical_files.length > 0) {
            html += `
                <div class="files-list">
                    <h4>⚠️ Critical Files (Immediate Attention Required)</h4>
            `;
            
            report.critical_files.forEach(file => {
                html += `
                    <div class="file-item">
                        <div class="file-info">
                            <div class="file-name">${escapeHtml(file.path)}</div>
                            <div class="file-details">
                                ${file.cwe_patterns.length} vulnerabilities | 
                                ${file.lines_of_code} LOC | 
                                Confidence: ${file.confidence}%
                            </div>
                        </div>
                        <div class="file-risk risk-level critical">CRITICAL</div>
                    </div>
                `;
            });
            
            html += `</div>`;
        }
        
        // High risk files
        if (report.high_risk_files && report.high_risk_files.length > 0) {
            html += `
                <div class="files-list">
                    <h4>🔴 High Risk Files</h4>
            `;
            
            report.high_risk_files.forEach(file => {
                html += `
                    <div class="file-item">
                        <div class="file-info">
                            <div class="file-name">${escapeHtml(file.path)}</div>
                            <div class="file-details">
                                ${file.cwe_patterns.join(', ')}
                            </div>
                        </div>
                        <div class="file-risk risk-level high">HIGH</div>
                    </div>
                `;
            });
            
            html += `</div>`;
        }
        
        projectReportContainer.innerHTML = html;
    }
    
    function resetProjectScanner() {
        uploadArea.style.display = 'block';
        uploadStatus.style.display = 'none';
        projectResults.style.display = 'none';
        projectFile.value = '';
    }
    
    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Ctrl+Enter to scan
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            scanCode();
        }
        
        // Ctrl+K to clear
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            clearEditor();
        }
        
        // Ctrl+Shift+F to fix all
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'F') {
            e.preventDefault();
            fixAllVulnerabilities();
        }
    });
});

// ========== VULNERABILITY FIX FUNCTIONS ==========

// Fix single vulnerability
async function fixVulnerability(button) {
    const listItem = button.closest('.cwe-item');
    const vulnData = JSON.parse(listItem.getAttribute('data-vuln'));
    const code = document.getElementById('codeEditor').value;
    const language = document.getElementById('languageSelect').value;
    const fixResultDiv = listItem.querySelector('.fix-result');
    
    button.disabled = true;
    button.innerHTML = '⏳ Fixing...';
    
    try {
        const response = await fetch('/api/fix', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                code: code,
                vulnerability: vulnData,
                language: language
            })
        });
        
        const result = await response.json();
        
        if (result.can_fix) {
            // Show success popup with more details
            const fileName = vulnData.file ? `in ${vulnData.file}` : '';
            showNotification(`✅ Fixed ${vulnData.cwe} ${fileName} at line ${vulnData.line}!`, 'success');
            
            fixResultDiv.innerHTML = `
                <div style="color: var(--success); font-weight: 600; margin-bottom: 0.5rem; font-size: 1.1rem; animation: pulse 0.5s ease-out;">✅ Fix Applied Successfully</div>
                <div style="margin-bottom: 0.5rem;">
                    <strong>Original (Vulnerable):</strong>
                    <pre style="background: rgba(239, 68, 68, 0.1); padding: 0.75rem; border-radius: 6px; margin-top: 0.25rem; overflow-x: auto; border-left: 3px solid var(--danger);"><code>${escapeHtml(result.original)}</code></pre>
                </div>
                <div style="margin-bottom: 0.5rem;">
                    <strong>Fixed (Secure):</strong>
                    <pre style="background: rgba(34, 197, 94, 0.1); padding: 0.75rem; border-radius: 6px; margin-top: 0.25rem; overflow-x: auto; border-left: 3px solid var(--success);"><code>${escapeHtml(result.fixed)}</code></pre>
                </div>
                <div style="display: flex; gap: 0.5rem; margin-top: 1rem;">
                    <button class="btn btn-primary apply-rescan-btn">
                        ✅ Apply & Re-scan
                    </button>
                    <button class="btn btn-secondary apply-editor-btn">
                        Apply to Editor
                    </button>
                </div>
            `;
            fixResultDiv.style.display = 'block';
            
            // Add event listeners to the buttons
            const rescanBtn = fixResultDiv.querySelector('.apply-rescan-btn');
            const editorBtn = fixResultDiv.querySelector('.apply-editor-btn');
            
            console.log('Buttons found:', { rescanBtn: !!rescanBtn, editorBtn: !!editorBtn });
            
            if (rescanBtn) {
                rescanBtn.addEventListener('click', () => {
                    console.log('Rescan button clicked!');
                    applyFixAndRescan(result.original, result.fixed);
                });
            }
            if (editorBtn) {
                editorBtn.addEventListener('click', () => {
                    console.log('Editor button clicked!');
                    applyFix(result.original, result.fixed);
                });
            }
            
            button.innerHTML = '✅ Fixed';
            button.style.background = 'var(--success)';
            button.disabled = true;
        } else {
            // Show warning popup
            showNotification('⚠️ Cannot auto-fix this vulnerability. Check remediation guide below.', 'warning');
            
            // Parse the remediation guide from the reason
            const reason = result.reason || 'Manual review required.';
            const parts = reason.split('|');
            let guideHtml = '';
            
            if (parts.length === 3) {
                // We have a detailed guide: title|steps|example
                const [title, steps, example] = parts;
                const stepsList = steps.split('\n').filter(s => s.trim()).map(step => 
                    `<li style="margin-bottom: 0.5rem;">${escapeHtml(step)}</li>`
                ).join('');
                
                guideHtml = `
                    <div class="remediation-guide" style="margin-top: 1rem; background: rgba(234, 179, 8, 0.05); border: 2px solid var(--warning); border-radius: 8px; overflow: hidden;">
                        <div class="guide-header" style="background: rgba(234, 179, 8, 0.15); padding: 0.75rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center;" onclick="this.parentElement.classList.toggle('expanded')">
                            <strong style="color: var(--warning);">📖 Click to view Step-by-Step Fix Guide</strong>
                            <span class="expand-icon" style="font-size: 1.2rem; transition: transform 0.3s;">▼</span>
                        </div>
                        <div class="guide-content" style="padding: 1rem; display: none;">
                            <h4 style="color: var(--warning); margin: 0 0 0.75rem 0; font-size: 1.1rem;">${escapeHtml(title)}</h4>
                            <ol style="margin: 0 0 1rem 1.25rem; padding: 0; line-height: 1.6;">
                                ${stepsList}
                            </ol>
                            ${example ? `
                                <div style="margin-top: 0.75rem;">
                                    <strong style="color: var(--success);">✅ Example Secure Code:</strong>
                                    <pre style="background: var(--bg-secondary); padding: 0.75rem; border-radius: 6px; margin-top: 0.5rem; overflow-x: auto; border-left: 3px solid var(--success);"><code>${escapeHtml(example)}</code></pre>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                `;
            }
            
            fixResultDiv.innerHTML = `
                <div style="color: var(--warning); font-weight: 600; margin-bottom: 0.5rem; font-size: 1.1rem;">⚠️ Cannot Auto-Fix - Manual Remediation Required</div>
                <div style="font-size: 0.9rem; background: rgba(234, 179, 8, 0.1); padding: 0.75rem; border-radius: 6px; margin-top: 0.5rem;">
                    This vulnerability requires careful manual review and code changes. Follow the remediation guide below.
                </div>
                ${guideHtml}
                ${result.manual_fix ? `<div style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.5rem; padding: 0.5rem; background: var(--bg-primary); border-radius: 4px;"><strong>Note:</strong> ${escapeHtml(result.manual_fix).replace(/\\n/g, '<br>')}</div>` : ''}
                ${result.explanation ? `<div style="margin-top: 1rem; padding: 0.75rem; background: rgba(59, 130, 246, 0.1); border-left: 3px solid var(--primary); border-radius: 4px;"><strong style="color: var(--primary);">🔍 Threat Explanation:</strong><div style="margin-top: 0.5rem; color: var(--text-primary); line-height: 1.6;">${escapeHtml(result.explanation).replace(/\\n/g, '<br>')}</div></div>` : ''}
            `;
            
            // Add CSS for expandable guide
            const style = document.createElement('style');
            style.textContent = `
                .remediation-guide.expanded .guide-content { display: block !important; }
                .remediation-guide.expanded .expand-icon { transform: rotate(180deg); }
                .remediation-guide .guide-header:hover { background: rgba(234, 179, 8, 0.25); }
            `;
            if (!document.querySelector('style[data-guide-style]')) {
                style.setAttribute('data-guide-style', 'true');
                document.head.appendChild(style);
            }
            fixResultDiv.style.display = 'block';
            fixResultDiv.style.borderLeftColor = 'var(--warning)';
            button.innerHTML = '🔧 Fix';
            button.disabled = false;
        }
    } catch (error) {
        console.error('Fix error:', error);
        
        // Show error popup
        showNotification('❌ Error: ' + error.message, 'error');
        
        fixResultDiv.innerHTML = `
            <div style="color: var(--danger); font-weight: 600; margin-bottom: 0.5rem;">❌ Fix Failed</div>
            <div style="background: rgba(239, 68, 68, 0.1); padding: 0.75rem; border-radius: 6px; border-left: 3px solid var(--danger);">${escapeHtml(error.message)}</div>
        `;
        fixResultDiv.style.display = 'block';
        fixResultDiv.style.borderLeftColor = 'var(--danger)';
        button.innerHTML = '🔧 Fix';
        button.disabled = false;
    }
}

// Apply fix to editor
function applyFix(original, fixed) {
    const editor = document.getElementById('codeEditor');
    const code = editor.value;
    
    // Replace the vulnerable line
    const updatedCode = code.replace(original, fixed);
    editor.value = updatedCode;
    
    // Show success notification
    showNotification('✅ Fix applied to editor!', 'success');
}

// Apply fix and automatically rescan
async function applyFixAndRescan(original, fixed) {
    const editor = document.getElementById('codeEditor');
    const code = editor.value;
    
    console.log('Original code:', code);
    console.log('Looking for:', original);
    console.log('Replacing with:', fixed);
    
    // Replace the vulnerable line
    const updatedCode = code.replace(original, fixed);
    
    console.log('Updated code:', updatedCode);
    console.log('Code changed:', code !== updatedCode);
    
    editor.value = updatedCode;
    
    // Show notification
    showNotification('✅ Fix applied! Re-scanning code...', 'info');
    
    console.log('Before rescan - Previous result:', window.currentScanResult);
    
    // Wait a moment for UI update
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Trigger rescan
    try {
        console.log('Triggering rescan after fix...');
        await window.scanCode();
        console.log('Rescan completed successfully');
        console.log('After rescan - Previous:', window.previousScanResult);
        console.log('After rescan - Current:', window.currentScanResult);
    } catch (error) {
        console.error('Re-scan error:', error);
        showNotification('❌ Re-scan failed: ' + error.message, 'error');
    }
}

// Fix all vulnerabilities
async function fixAllVulnerabilities() {
    const code = document.getElementById('codeEditor').value;
    const language = document.getElementById('languageSelect').value;
    
    // Get all vulnerabilities
    const cweItems = document.querySelectorAll('.cwe-item[data-vuln]');
    if (cweItems.length === 0) {
        alert('No vulnerabilities to fix!');
        return;
    }
    
    const vulnerabilities = Array.from(cweItems).map(item => 
        JSON.parse(item.getAttribute('data-vuln'))
    );
    
    if (!confirm(`Fix all ${vulnerabilities.length} vulnerabilities?`)) {
        return;
    }
    
    const resultsContainer = document.getElementById('resultsContainer');
    resultsContainer.innerHTML = `
        <div style="text-align: center; padding: 2rem;">
            <div class="spinner" style="margin: 0 auto 1rem;"></div>
            <div>Fixing ${vulnerabilities.length} vulnerabilities...</div>
        </div>
    `;
    
    try {
        const response = await fetch('/api/fix-file', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                code: code,
                vulnerabilities: vulnerabilities,
                language: language
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            // Update editor with fixed code
            document.getElementById('codeEditor').value = result.fixed_code;
            
            // Display results
            let html = `
                <div class="result-summary">
                    <div class="vulnerability-badge safe">
                        <span style="font-size: 1.5rem;">✅</span>
                        <span>Fixed ${result.successful_fixes}/${result.total_fixes} Vulnerabilities</span>
                    </div>
                </div>
                <div class="result-section">
                    <h4>🔧 Fixes Applied</h4>
                    <ul class="cwe-list">
            `;
            
            result.fixes_applied.forEach(fix => {
                if (fix.success) {
                    html += `
                        <li class="cwe-item" style="border-left-color: var(--success);">
                            <div style="font-weight: 600; color: var(--success);">✅ ${escapeHtml(fix.cwe)}</div>
                            <div style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.25rem;">
                                Line ${fix.line}: ${escapeHtml(fix.original.substring(0, 60))}...
                            </div>
                        </li>
                    `;
                } else {
                    html += `
                        <li class="cwe-item" style="border-left-color: var(--warning);">
                            <div style="font-weight: 600; color: var(--warning);">⚠️ ${escapeHtml(fix.cwe)}</div>
                            <div style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.25rem;">
                                ${escapeHtml(fix.reason || 'Could not auto-fix')}
                            </div>
                        </li>
                    `;
                }
            });
            
            html += `
                    </ul>
                </div>
                <div style="text-align: center; padding: 2rem; background: rgba(34, 197, 94, 0.1); border-radius: 8px; margin-top: 1rem;">
                    <div style="font-size: 1.2rem; font-weight: 600; color: var(--success); margin-bottom: 1rem;">✅ Fixes Applied Successfully!</div>
                    <div style="display: flex; gap: 1rem; justify-content: center;">
                        <button class="btn btn-primary" onclick="window.scanCode(); showNotification('🔄 Re-scanning code...', 'info');">🔄 Re-scan Fixed Code</button>
                        <button class="btn btn-secondary" onclick="downloadFixedCode()">💾 Download Fixed Code</button>
                    </div>
                </div>
            `;
            
            // Show success popup
            showNotification(`✅ Successfully fixed ${result.successful_fixes} out of ${result.total_fixes} vulnerabilities!`, 'success');
            
            // Auto-rescan after 3 seconds
            setTimeout(async () => {
                showNotification('🔄 Auto re-scanning to verify fixes...', 'info');
                await new Promise(resolve => setTimeout(resolve, 500));
                try {
                    await window.scanCode();
                } catch (error) {
                    console.error('Auto rescan failed:', error);
                    showNotification('❌ Auto rescan failed: ' + error.message, 'error');
                }
            }, 3000);
            
            resultsContainer.innerHTML = html;
        }
    } catch (error) {
        console.error('Fix all error:', error);
        resultsContainer.innerHTML = `
            <div style="text-align: center; padding: 2rem; color: var(--danger);">
                ❌ Error fixing vulnerabilities: ${escapeHtml(error.message)}
            </div>
        `;
    }
}

// Fix all vulnerabilities in project scan
async function fixAllProjectVulnerabilities() {
    const cweItems = document.querySelectorAll('.cwe-item[data-vuln]');
    if (cweItems.length === 0) {
        showNotification('No vulnerabilities to fix!', 'info');
        return;
    }
    
    const initialCount = cweItems.length;
    
    if (!confirm(`Fix all ${cweItems.length} vulnerabilities found in the project?`)) {
        return;
    }
    
    // Show progress notification
    showNotification(`Fixing ${cweItems.length} vulnerabilities...`, 'info');
    
    let fixed = 0;
    let failed = 0;
    
    for (let i = 0; i < cweItems.length; i++) {
        const item = cweItems[i];
        const button = item.querySelector('.fix-btn');
        if (button && !button.disabled) {
            try {
                await fixVulnerability(button);
                fixed++;
                // Update progress
                showNotification(`Progress: ${i + 1}/${cweItems.length} - Fixed ${fixed} vulnerabilities`, 'info');
            } catch (error) {
                failed++;
            }
        }
    }
    
    // Update the displayed stats
    updateProjectStats(fixed, failed, initialCount);
    
    // Show final result notification
    showNotification(`✅ Fixed ${fixed} vulnerabilities${failed > 0 ? ` | ⚠️ ${failed} failed` : ''}`, 'success');
    
    // Update the project statistics with improvement banner
    updateProjectStats(fixed, failed, initialCount);
}

// Update project statistics and score after fixes
function updateProjectStats(fixed, failed, initialCount) {
    const remaining = initialCount - fixed;
    
    // Store previous values before update
    const scoreInner = document.querySelector('.score-inner span');
    const criticalBox = document.querySelectorAll('.stat-box-value')[3];
    
    const previousScore = scoreInner ? parseInt(scoreInner.textContent) || 0 : 0;
    const previousCritical = criticalBox ? parseInt(criticalBox.textContent) || 0 : 0;
    
    // Update vulnerability count boxes
    const statBoxes = document.querySelectorAll('.stat-box-value');
    if (statBoxes.length >= 4) {
        // Update critical issues count (4th stat box)
        const newCritical = Math.max(0, previousCritical - fixed);
        criticalBox.textContent = newCritical;
        
        // Animate the change
        criticalBox.style.animation = 'pulse 0.5s ease-out';
    }
    
    // Calculate new security score
    const scoreCircle = document.querySelector('.score-circle');
    const riskLevel = document.querySelector('.security-score-card .risk-level');
    
    if (scoreCircle && scoreInner && remaining >= 0) {
        // Calculate improvement (each fix improves score)
        const improvementPerFix = fixed > 0 ? Math.min(10, 50 / initialCount) : 0;
        const newScore = Math.min(100, Math.round(previousScore + (fixed * improvementPerFix)));
        
        // Update score with animation
        scoreInner.textContent = newScore;
        scoreCircle.style.setProperty('--score-percent', `${newScore}%`);
        scoreCircle.style.animation = 'pulse 0.8s ease-out';
        
        // Update risk level based on new score
        let newRiskLevel = 'CRITICAL';
        let riskClass = 'critical';
        
        if (newScore >= 75) {
            newRiskLevel = 'LOW';
            riskClass = 'low';
        } else if (newScore >= 50) {
            newRiskLevel = 'MEDIUM';
            riskClass = 'medium';
        } else if (newScore >= 25) {
            newRiskLevel = 'HIGH';
            riskClass = 'high';
        }
        
        if (riskLevel) {
            riskLevel.textContent = `${newRiskLevel} RISK`;
            riskLevel.className = `risk-level ${riskClass}`;
        }
        
        // Update score circle class for color
        scoreCircle.className = `score-circle ${riskClass}`;
        
        // Show improvement banner at the top (like code editor)
        if (fixed > 0) {
            const improvementBanner = document.createElement('div');
            improvementBanner.style.cssText = 'background: linear-gradient(135deg, rgba(34, 197, 94, 0.15), rgba(34, 197, 94, 0.05)); border: 3px solid var(--success); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; animation: slideDown 0.5s ease-out, pulse 0.5s ease-out;';
            improvementBanner.innerHTML = `
                <div style="font-size: 1.5rem; font-weight: 700; color: var(--success); margin-bottom: 0.75rem; text-align: center;">
                    🎉 Excellent! You Fixed ${fixed} Vulnerability${fixed > 1 ? 'ies' : ''}! 🎉
                </div>
                <div style="display: flex; justify-content: space-around; margin-top: 1rem; font-size: 1.1rem;">
                    <div style="text-align: center;">
                        <div style="color: var(--danger); font-weight: 600; font-size: 1.3rem;">${previousCritical}</div>
                        <div style="color: var(--text-secondary); font-size: 0.9rem;">Before</div>
                    </div>
                    <div style="color: var(--success); font-size: 2rem; align-self: center;">→</div>
                    <div style="text-align: center;">
                        <div style="color: var(--success); font-weight: 600; font-size: 1.3rem;">${Math.max(0, previousCritical - fixed)}</div>
                        <div style="color: var(--text-secondary); font-size: 0.9rem;">After</div>
                    </div>
                </div>
                ${newScore > previousScore ? `
                    <div style="text-align: center; margin-top: 1rem; color: var(--success); font-weight: 600;">
                        📈 Security Score improved: ${previousScore} → ${newScore}
                    </div>
                ` : ''}
            `;
            
            // Insert at top of project results
            const projectReportContainer = document.getElementById('projectReportContainer');
            if (projectReportContainer && projectReportContainer.firstChild) {
                projectReportContainer.insertBefore(improvementBanner, projectReportContainer.firstChild);
            }
        }
        
        // Show score improvement notification
        showNotification(`📈 Security Score: ${previousScore} → ${newScore} (+${newScore - previousScore})`, 'success');
    }
}

function escapeHtml(text) {
    if (!text) return '';
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.toString().replace(/[&<>"']/g, m => map[m]);
}

// Show notification popup
function showNotification(message, type = 'info') {
    // Create notification container if it doesn't exist
    let container = document.getElementById('notification-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'notification-container';
        container.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 10000; max-width: 400px;';
        document.body.appendChild(container);
    }
    
    // Create notification element
    const notification = document.createElement('div');
    const colors = {
        success: { bg: 'rgba(34, 197, 94, 0.95)', border: '#22c55e', icon: '✅' },
        error: { bg: 'rgba(239, 68, 68, 0.95)', border: '#ef4444', icon: '❌' },
        warning: { bg: 'rgba(234, 179, 8, 0.95)', border: '#eab308', icon: '⚠️' },
        info: { bg: 'rgba(99, 102, 241, 0.95)', border: '#6366f1', icon: 'ℹ️' }
    };
    
    const color = colors[type] || colors.info;
    
    notification.style.cssText = `
        background: ${color.bg};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        margin-bottom: 10px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        border-left: 4px solid ${color.border};
        animation: slideInRight 0.3s ease-out;
        display: flex;
        align-items: center;
        gap: 0.75rem;
        font-weight: 500;
    `;
    
    notification.innerHTML = `
        <span style="font-size: 1.2rem;">${color.icon}</span>
        <span style="flex: 1;">${escapeHtml(message)}</span>
        <button onclick="this.parentElement.remove()" style="background: none; border: none; color: white; font-size: 1.2rem; cursor: pointer; padding: 0; opacity: 0.8;" onmouseover="this.style.opacity='1'" onmouseout="this.style.opacity='0.8'">×</button>
    `;
    
    container.appendChild(notification);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

// Download fixed code
function downloadFixedCode() {
    const code = document.getElementById('codeEditor').value;
    const blob = new Blob([code], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'fixed_code.txt';
    a.click();
    URL.revokeObjectURL(url);
    showNotification('✅ Fixed code downloaded!', 'success');
}
