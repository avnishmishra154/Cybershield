// Main Scanner Application
class CyberShieldScanner {
    constructor() {
        this.scanHistory = [];
        this.init();
    }

    init() {
        this.hideLoadingScreen();
        this.setupEventListeners();
        this.setupMockData();
        this.initializeCharts();
        this.initAuth();
    }

    hideLoadingScreen() {
        setTimeout(() => {
            document.getElementById('loadingScreen').classList.add('hidden');
            setTimeout(() => {
                document.getElementById('loadingScreen').style.display = 'none';
            }, 500);
        }, 1500);
    }

    setupEventListeners() {
        // Tab switching
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchTab(e));
        });

        // File upload
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        
        if (uploadArea) {
            uploadArea.addEventListener('click', () => fileInput.click());
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadArea.classList.add('dragover');
            });
            uploadArea.addEventListener('dragleave', () => {
                uploadArea.classList.remove('dragover');
            });
            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadArea.classList.remove('dragover');
                this.handleFiles(e.dataTransfer.files);
            });
        }
        
        if (fileInput) {
            fileInput.addEventListener('change', (e) => this.handleFiles(e.target.files));
        }

        // Scan buttons
        document.getElementById('scanFileBtn')?.addEventListener('click', () => this.scanFiles());
        document.getElementById('scanUrlBtn')?.addEventListener('click', () => this.scanURL());
        document.getElementById('scanHashBtn')?.addEventListener('click', () => this.scanHash());

        // Start scan button
        document.querySelector('.start-scan-btn')?.addEventListener('click', () => {
            document.querySelector('.scanner-section').scrollIntoView({ behavior: 'smooth' });
        });

        // Menu toggle
        document.getElementById('menuToggle')?.addEventListener('click', () => {
            document.querySelector('.nav-menu').classList.toggle('active');
        });

        // Modal close
        document.querySelector('.close-modal')?.addEventListener('click', () => {
            document.getElementById('resultsModal').classList.remove('active');
        });

        // Close modal on outside click
        document.getElementById('resultsModal')?.addEventListener('click', (e) => {
            if (e.target === document.getElementById('resultsModal')) {
                document.getElementById('resultsModal').classList.remove('active');
            }
        });

        // Smooth scrolling for navigation
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const targetId = this.getAttribute('href');
                if (targetId === '#') return;
                
                const targetElement = document.querySelector(targetId);
                if (targetElement) {
                    targetElement.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
    }

    switchTab(e) {
        const tabId = e.target.dataset.tab;
        
        // Update active tab button
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        e.target.classList.add('active');

        // Show corresponding content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(`${tabId}-tab`).classList.add('active');
    }

    handleFiles(files) {
        const fileList = document.getElementById('fileList');
        if (!fileList) return;
        
        fileList.innerHTML = '';

        Array.from(files).forEach(file => {
            if (file.size > 256 * 1024 * 1024) {
                this.showNotification(`File ${file.name} exceeds 256MB limit`, 'error');
                return;
            }

            const fileItem = document.createElement('div');
            fileItem.className = 'file-item';
            fileItem.innerHTML = `
                <div class="file-info">
                    <i class="fas fa-file file-icon"></i>
                    <div>
                        <strong>${file.name}</strong>
                        <p>${(file.size / (1024 * 1024)).toFixed(2)} MB</p>
                    </div>
                </div>
                <button class="btn-secondary remove-file">
                    <i class="fas fa-times"></i>
                </button>
            `;

            // Remove file button
            fileItem.querySelector('.remove-file').addEventListener('click', () => {
                fileItem.remove();
            });

            fileList.appendChild(fileItem);
        });

        if (files.length > 0) {
            this.showNotification(`${files.length} file(s) added for scanning`, 'success');
        }
    }

    async scanFiles() {
        const files = document.getElementById('fileList')?.children;
        if (!files || files.length === 0) {
            this.showNotification('Please add files to scan', 'warning');
            return;
        }

        this.showNotification('Scanning files...', 'info');
        
        // Simulate scanning process
        await this.simulateScanDelay(2000);

        // Generate mock results
        Array.from(files).forEach((fileItem, index) => {
            const fileName = fileItem.querySelector('strong').textContent;
            const isMalicious = Math.random() > 0.7;
            const threat = isMalicious ? this.getRandomThreat() : null;
            
            this.addScanResult({
                type: 'file',
                name: fileName,
                status: isMalicious ? 'malicious' : 'safe',
                threat: threat,
                timestamp: new Date().toISOString()
            });
        });

        this.showNotification('File scan completed!', 'success');
        this.showResultsModal();
    }

    async scanURL() {
        const urlInput = document.getElementById('urlInput');
        if (!urlInput) return;
        
        const url = urlInput.value.trim();

        if (!url) {
            this.showNotification('Please enter a URL to scan', 'warning');
            return;
        }

        if (!this.isValidUrl(url)) {
            this.showNotification('Please enter a valid URL', 'error');
            return;
        }

        this.showNotification(`Scanning URL: ${url}`, 'info');
        
        // Simulate scanning process
        await this.simulateScanDelay(1500);

        const isMalicious = Math.random() > 0.8;
        const threat = isMalicious ? this.getRandomThreat() : null;

        this.addScanResult({
            type: 'url',
            name: url,
            status: isMalicious ? 'malicious' : 'safe',
            threat: threat,
            timestamp: new Date().toISOString()
        });

        this.addToScanHistory(url, isMalicious ? 'malicious' : 'safe');
        urlInput.value = '';
        
        this.showNotification('URL scan completed!', 'success');
        this.showResultsModal();
    }

    async scanHash() {
        const hashInput = document.getElementById('hashInput');
        const hashType = document.getElementById('hashType');
        
        if (!hashInput || !hashType) return;
        
        const hash = hashInput.value.trim();
        const hashTypeValue = hashType.value;

        if (!hash) {
            this.showNotification('Please enter a hash value', 'warning');
            return;
        }

        this.showNotification(`Checking ${hashTypeValue.toUpperCase()} hash...`, 'info');
        
        // Simulate scanning process
        await this.simulateScanDelay(1000);

        const isKnownThreat = Math.random() > 0.9;
        const threat = isKnownThreat ? this.getRandomThreat() : null;

        this.addScanResult({
            type: 'hash',
            name: `${hashTypeValue.toUpperCase()}: ${hash.substring(0, 16)}...`,
            status: isKnownThreat ? 'malicious' : 'safe',
            threat: threat,
            timestamp: new Date().toISOString()
        });

        this.showNotification('Hash check completed!', 'success');
        this.showResultsModal();
    }

    addScanResult(result) {
        const resultsGrid = document.getElementById('resultsGrid');
        const emptyResults = document.getElementById('emptyResults');
        
        if (!resultsGrid) return;
        
        if (emptyResults) {
            emptyResults.style.display = 'none';
        }

        // Create result card
        const resultCard = document.createElement('div');
        resultCard.className = 'result-card';
        
        const severityClass = {
            safe: 'safe',
            suspicious: 'suspicious',
            malicious: 'malicious'
        }[result.status];

        let threatInfo = '';
        if (result.threat) {
            threatInfo = `
                <div class="threat-info">
                    <p><strong>Threat:</strong> ${result.threat.name}</p>
                    <p><strong>Type:</strong> ${result.threat.type}</p>
                    <p><strong>Severity:</strong> ${result.threat.severity}</p>
                </div>
            `;
        }

        resultCard.innerHTML = `
            <div class="result-header">
                <div>
                    <h4>${result.name}</h4>
                    <p class="file-type">${result.type.toUpperCase()}</p>
                </div>
                <span class="result-status ${severityClass}">
                    ${result.status.toUpperCase()}
                </span>
            </div>
            ${threatInfo}
            <div class="threat-indicators">
                <div class="threat-indicator">
                    <i class="fas fa-shield-alt"></i>
                    <span>Security Score: ${Math.floor(Math.random() * 100)}/100</span>
                </div>
            </div>
            <div class="threat-meter">
                <div class="threat-meter-fill" style="width: ${
                    result.status === 'malicious' ? '90%' : 
                    result.status === 'suspicious' ? '50%' : '10%'
                }; background: ${
                    result.status === 'malicious' ? '#f72585' : 
                    result.status === 'suspicious' ? '#f8961e' : '#06d6a0'
                }"></div>
            </div>
            <div class="result-footer">
                <small>Scanned: ${new Date(result.timestamp).toLocaleTimeString()}</small>
            </div>
        `;

        resultsGrid.insertBefore(resultCard, resultsGrid.firstChild);
        this.scanHistory.push(result);

        // Update dashboard
        this.updateDashboard();
    }

    showResultsModal() {
        const modal = document.getElementById('resultsModal');
        const modalBody = document.getElementById('modalResults');
        
        if (!modal || !modalBody) return;
        
        const latestResult = this.scanHistory[this.scanHistory.length - 1];
        if (!latestResult) return;

        modalBody.innerHTML = `
            <div class="modal-result">
                <h3>Scan Complete</h3>
                <div class="result-summary">
                    <p><strong>Target:</strong> ${latestResult.name}</p>
                    <p><strong>Status:</strong> 
                        <span class="result-status ${latestResult.status}">
                            ${latestResult.status.toUpperCase()}
                        </span>
                    </p>
                    ${latestResult.threat ? `
                        <p><strong>Threat Detected:</strong> ${latestResult.threat.name}</p>
                        <p><strong>Description:</strong> ${latestResult.threat.description}</p>
                        <p><strong>Recommended Action:</strong> Quarantine and remove immediately</p>
                    ` : `
                        <p><strong>Result:</strong> No threats detected</p>
                        <p><strong>Recommendation:</strong> File appears to be safe</p>
                    `}
                </div>
                <div class="additional-info">
                    <h4><i class="fas fa-chart-bar"></i> Statistics</h4>
                    <p>Detection Rate: 99.9%</p>
                    <p>False Positive Rate: 0.01%</p>
                    <p>Scan Time: 1.2 seconds</p>
                </div>
            </div>
        `;

        modal.classList.add('active');
    }

    addToScanHistory(url, status) {
        const history = document.querySelector('.scan-history');
        if (!history) return;
        
        const historyItem = document.createElement('div');
        historyItem.className = 'history-item';
        historyItem.innerHTML = `
            <i class="fas fa-${status === 'malicious' ? 'times-circle' : 'check-circle'} ${status}"></i>
            <span class="url">${url.substring(0, 40)}${url.length > 40 ? '...' : ''}</span>
            <span class="time">${new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span>
        `;
        
        history.insertBefore(historyItem, history.firstChild);
        
        // Keep only last 5 items
        if (history.children.length > 5) {
            history.removeChild(history.lastChild);
        }
    }

    updateDashboard() {
        // Update threat types
        const threatTypes = document.getElementById('threatTypes');
        if (threatTypes) {
            const typeCounts = {};
            
            this.scanHistory.forEach(scan => {
                if (scan.threat) {
                    typeCounts[scan.threat.type] = (typeCounts[scan.threat.type] || 0) + 1;
                }
            });

            threatTypes.innerHTML = Object.entries(typeCounts).map(([type, count]) => `
                <div class="threat-type-item">
                    <span class="type-name">${type}</span>
                    <span class="type-count">${count}</span>
                </div>
            `).join('');
        }

        // Update activity log
        const activityLog = document.getElementById('activityLog');
        if (activityLog) {
            const recentScans = this.scanHistory.slice(-5).reverse();
            
            activityLog.innerHTML = recentScans.map(scan => `
                <div class="activity-item">
                    <i class="fas fa-${scan.type === 'file' ? 'file' : 'link'}"></i>
                    <div>
                        <p>${scan.name}</p>
                        <small>${new Date(scan.timestamp).toLocaleTimeString()}</small>
                    </div>
                    <span class="status-indicator ${scan.status}"></span>
                </div>
            `).join('');
        }
    }

    initializeCharts() {
        const ctx = document.getElementById('activityChart')?.getContext('2d');
        if (!ctx) return;
        
        this.chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                datasets: [{
                    label: 'Threats Detected',
                    data: [12, 19, 8, 15, 22, 18, 25],
                    borderColor: '#4361ee',
                    backgroundColor: 'rgba(67, 97, 238, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: '#6c757d'
                        }
                    },
                    x: {
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: '#6c757d'
                        }
                    }
                }
            }
        });
    }

    setupMockData() {
        // Add some mock scan history
        setTimeout(() => {
            this.addToScanHistory('https://example.com', 'safe');
            this.addToScanHistory('https://malicious-site.com', 'malicious');
            this.addToScanHistory('https://safe-download.com', 'safe');
        }, 1000);

        // Add mock activity items
        const mockActivities = [
            { type: 'file', name: 'setup.exe', status: 'malicious', time: '10:30 AM' },
            { type: 'url', name: 'https://trusted-site.com', status: 'safe', time: '09:15 AM' },
            { type: 'file', name: 'document.pdf', status: 'safe', time: '08:45 AM' }
        ];

        const activityLog = document.getElementById('activityLog');
        if (activityLog) {
            activityLog.innerHTML = mockActivities.map(activity => `
                <div class="activity-item">
                    <i class="fas fa-${activity.type === 'file' ? 'file' : 'link'}"></i>
                    <div>
                        <p>${activity.name}</p>
                        <small>${activity.time}</small>
                    </div>
                    <span class="status-indicator ${activity.status}"></span>
                </div>
            `).join('');
        }
    }

    initAuth() {
        // Initialize auth system
        const auth = new AuthSystem();
        
        // Setup user menu toggle
        const userAvatar = document.getElementById('userAvatar');
        const userDropdown = document.getElementById('userDropdown');
        const logoutBtn = document.getElementById('logoutBtn');
        
        if (userAvatar && userDropdown) {
            userAvatar.addEventListener('click', (e) => {
                e.stopPropagation();
                userDropdown.classList.toggle('active');
            });
            
            // Close dropdown when clicking outside
            document.addEventListener('click', (e) => {
                if (!userAvatar.contains(e.target) && !userDropdown.contains(e.target)) {
                    userDropdown.classList.remove('active');
                }
            });
        }
        
        if (logoutBtn) {
            logoutBtn.addEventListener('click', (e) => {
                e.preventDefault();
                auth.logout();
            });
        }
    }

    // Utility methods
    getRandomThreat() {
        const MOCK_THREATS = [
            { name: 'Trojan.Generic', severity: 'high', type: 'trojan', description: 'Generic trojan that steals information' },
            { name: 'Ransomware.WannaCry', severity: 'critical', type: 'ransomware', description: 'Encrypts files and demands ransom' },
            { name: 'Adware.PopUnder', severity: 'low', type: 'adware', description: 'Displays unwanted advertisements' },
            { name: 'Spyware.Keylogger', severity: 'medium', type: 'spyware', description: 'Records keystrokes and sensitive data' },
            { name: 'Worm.Mydoom', severity: 'high', type: 'worm', description: 'Spreads through email attachments' }
        ];
        return MOCK_THREATS[Math.floor(Math.random() * MOCK_THREATS.length)];
    }

    isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }

    async simulateScanDelay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    showNotification(message, type = 'info') {
        const toast = document.getElementById('notificationToast');
        if (!toast) return;
        
        const toastMessage = toast.querySelector('.toast-message');
        const toastIcon = toast.querySelector('i');
        
        // Set icon based on type
        const iconMap = {
            info: 'fas fa-info-circle',
            success: 'fas fa-check-circle',
            warning: 'fas fa-exclamation-triangle',
            error: 'fas fa-times-circle'
        };

        toastIcon.className = iconMap[type] || iconMap.info;
        toastMessage.textContent = message;
        
        // Show toast
        toast.classList.add('active');
        
        // Auto hide after 3 seconds
        setTimeout(() => {
            toast.classList.remove('active');
        }, 3000);
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.scanner = new CyberShieldScanner();
});