document.addEventListener('DOMContentLoaded', function() {
    // ==================== DEBUG LOGGING FUNCTIONS ====================
    const debugLogger = {
        colors: {
            info: '#4CAF50',
            warn: '#FFC107',
            error: '#F44336',
            debug: '#2196F3'
        },
        
        log: function(message, data, level = 'info') {
            if (!debugMode || !debugContent) return;
            
            try {
                const timestamp = new Date().toISOString();
                const color = this.colors[level] || this.colors.info;
                
                const entry = document.createElement('div');
                entry.className = `debug-entry ${level}`;
                entry.dataset.timestamp = timestamp;
                
                const header = document.createElement('div');
                header.className = 'debug-header';
                header.innerHTML = `
                    <span class="debug-timestamp">${this.formatTimestamp(timestamp)}</span>
                    <span class="debug-level" style="color: ${color}">${level.toUpperCase()}</span>
                `;
                
                const messageDiv = document.createElement('div');
                messageDiv.className = 'debug-message';
                messageDiv.textContent = message;
                
                entry.appendChild(header);
                entry.appendChild(messageDiv);
                
                if (data !== undefined) {
                    const dataElement = document.createElement('pre');
                    dataElement.className = 'debug-data';
                    
                    try {
                        dataElement.textContent = this.formatData(data);
                    } catch (e) {
                        dataElement.textContent = `[Data formatting error] ${e.message}`;
                        entry.classList.add('error');
                    }
                    
                    entry.appendChild(dataElement);
                }
                
                debugContent.appendChild(entry);
                debugContent.scrollTop = debugContent.scrollHeight;
                
                this.consoleLog(level, message, data);
                
            } catch (error) {
                console.error('Debug logging error:', error);
            }
        },
        
        formatTimestamp: function(timestamp) {
            const date = new Date(timestamp);
            return date.toLocaleString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false
            });
        },
        
        formatData: function(data) {
            if (typeof data === 'string') return data;
            if (data instanceof Error) {
                return `${data.name}: ${data.message}\n${data.stack || 'No stack trace'}`;
            }
            return JSON.stringify(data, this.safeStringifyReplacer(), 2);
        },
        
        safeStringifyReplacer: function() {
            const seen = new WeakSet();
            return (key, value) => {
                if (typeof value === 'object' && value !== null) {
                    if (seen.has(value)) return '[Circular]';
                    seen.add(value);
                }
                return value;
            };
        },
        
        consoleLog: function(level, message, data) {
            const method = {
                info: 'log',
                warn: 'warn',
                error: 'error',
                debug: 'debug'
            }[level] || 'log';
            
            const color = this.colors[level] || this.colors.info;
            const style = `color: ${color}; font-weight: bold`;
            
            console[method](`%c[${level.toUpperCase()}]`, style, message);
            if (data !== undefined) {
                console[method](data);
            }
        },
        
        clear: function() {
            if (debugContent) {
                debugContent.innerHTML = '';
            }
        }
    };

    // Simplified interface functions
    function logDebug(message, data, level = 'info') {
        debugLogger.log(message, data, level);
    }

    function logDebugInfo(message, data) {
        debugLogger.log(message, data, 'info');
    }

    function logDebugWarn(message, data) {
        debugLogger.log(message, data, 'warn');
    }

    function logDebugError(message, data) {
        debugLogger.log(message, data, 'error');
    }

    function logDebugVerbose(message, data) {
        debugLogger.log(message, data, 'debug');
    }

    function clearDebugLogs() {
        debugLogger.clear();
    }

    // Global variables
    let adminData = null;
    let socket = null;
    let currentView = 'dashboard';
    let currentLoanType = '';
    let currentCustomer = null;
    let debugMode = false;
    const API_BASE_URL = window.location.hostname === 'localhost' 
        ? 'http://localhost:3000' 
        : 'https://fonte-lenders.onrender.com';

    // DOM elements
    const loginContainer = document.getElementById('login-container');
    const adminContent = document.getElementById('admin-content');
    const loginButton = document.getElementById('login-button');
    const usernameInput = document.getElementById('username-input');
    const passwordInput = document.getElementById('password-input');
    const errorMessage = document.getElementById('error-message');
    const logoutButton = document.getElementById('logout-btn');
    const debugToggleButton = document.getElementById('debug-toggle-btn');
    const debugConsole = document.getElementById('debug-console');
    const debugContent = document.getElementById('debug-content');
    const refreshButton = document.getElementById('refresh-admin-btn');
    const loansSection = document.getElementById('loans-section');
    const loansGridContainer = document.getElementById('loans-grid-container');
    const loansTableContainer = document.getElementById('loans-table-container');
    const loansGrid = document.getElementById('loans-grid');
    const loansTableBody = document.getElementById('loans-table-body');
    const pendingPaymentsSection = document.getElementById('pending-payments-section');
    const pendingPaymentsTableBody = document.getElementById('pending-payments-table-body');
    const customerProfileSection = document.getElementById('customer-profile-section');
    const customerDetailsContainer = document.getElementById('customerDetails');
    const searchCustomerInput = document.getElementById('searchCustomer');
    const loanDetailsModal = document.getElementById('loanDetailsModal');
    const loanDetailsContent = document.getElementById('loanDetailsContent');
    const approvalTermsModal = document.getElementById('approvalTermsModal');
    const reportModal = document.getElementById('reportModal');
    const reportContent = document.getElementById('reportContent');
    const pendingPaymentsBtn = document.getElementById('pending-payments-btn');
    const hidePaymentsBtn = document.getElementById('hide-payments-btn');
    const bulkLimitFile = document.getElementById('bulkLimitFile');
    const processBulkBtn = document.getElementById('process-bulk-btn');
    const bulkUpdateResult = document.getElementById('bulkUpdateResult');

    // ==================== CORE FUNCTIONS ====================
    window.backToDashboard = function() {
        // Close all open modals
        document.querySelectorAll('.modal').forEach(modal => {
            modal.style.display = 'none';
        });

        // Close debug console
        debugMode = false;
        debugConsole.style.display = 'none';
        debugToggleButton.querySelector('.debug-btn-text').textContent = 'SHOW DEBUG';
        localStorage.setItem('debugMode', 'false');

        // Reset to dashboard view
        showDashboard();
        
        // Clear customer search
        searchCustomerInput.value = '';
        customerDetailsContainer.innerHTML = '';
        
        logDebugInfo('Navigated back to dashboard');
    };

window.showLoanDetails = async function(loanId) {
    try {
        // FIXED: Corrected endpoint from '/loans' to '/loan-applications'
        const response = await fetch(`${API_BASE_URL}/api/admin/loan-applications/${loanId}`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            }
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Failed to load loan details');
        }
        
        renderLoanDetails(data.loan);
        loanDetailsModal.style.display = 'flex';
        logDebugInfo('Loan details shown', data.loan);
        
    } catch (error) {
        console.error('Error loading loan details:', error);
        showNotification('Failed to load loan details', 'error');
        logDebugError('Loan details load failed', {
            error: error.message,
            loanId,
            endpoint: `${API_BASE_URL}/api/admin/loan-applications/${loanId}`
        });
    }
};

    async function fetchLoans(apiUrl, loanType) {
        try {
            const response = await fetch(apiUrl, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
                }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to load loans');
            }
            
            if (loanType === 'active') {
                renderActiveLoansGrid(data.applications);
            } else {
                renderLoansTable(data.applications);
            }
            
            logDebugInfo(`Loans data loaded: ${loanType}`, data);
            
        } catch (error) {
            console.error('Error loading loans:', error);
            showNotification('Failed to load loans', 'error');
            logDebugError('Error loading loans', error);
        }
    }

    async function searchCustomer() {
        const searchTerm = searchCustomerInput.value.trim();
        
        // Clear previous results and show loading state
        customerDetailsContainer.innerHTML = '<div class="loading-spinner"></div>';
        searchCustomerInput.disabled = true;
        
        if (!searchTerm) {
            showNotification('Please enter a search term', 'error');
            customerDetailsContainer.innerHTML = '';
            searchCustomerInput.disabled = false;
            return;
        }
        
        try {
            // Show loading indicator on search button
            const searchButton = document.getElementById('search-customer-btn');
            const originalButtonText = searchButton?.innerHTML || '';
            if (searchButton) {
                searchButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Searching...';
                searchButton.disabled = true;
            }
            
            const response = await fetch(`${API_BASE_URL}/api/admin/customers?search=${encodeURIComponent(searchTerm)}`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
                }
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || `Search failed with status ${response.status}`);
            }
            
            const data = await response.json();
            const customers = data.data || [];
            
            if (!customers || customers.length === 0) {
                customerDetailsContainer.innerHTML = `
                    <div class="no-results">
                        <i class="fas fa-search"></i>
                        <h4>No customers found</h4>
                        <p>Try searching by full name, phone number, or customer ID</p>
                        <p>Examples: "John Doe", "0712345678", "CUST-123"</p>
                    </div>
                `;
                showNotification('No matching customers found', 'info');
                return;
            }
            
            renderCustomerSearchResults(customers);
            showNotification(`Found ${customers.length} customer(s)`, 'success');
            logDebugInfo('Customer search results', { searchTerm, results: customers });
            
        } catch (error) {
            console.error('Search error:', error);
            customerDetailsContainer.innerHTML = `
                <div class="search-error">
                    <i class="fas fa-exclamation-triangle"></i>
                    <h4>Search Failed</h4>
                    <p>${error.message || 'An error occurred while searching'}</p>
                    <button class="retry-btn" onclick="searchCustomer()">
                        <i class="fas fa-sync-alt"></i> Try Again
                    </button>
                </div>
            `;
            
            showNotification(error.message || 'Search failed', 'error');
            logDebugError('Customer search failed', error);
        } finally {
            // Reset button state
            const searchButton = document.getElementById('search-customer-btn');
            if (searchButton) {
                searchButton.innerHTML = originalButtonText;
                searchButton.disabled = false;
            }
            searchCustomerInput.disabled = false;
        }
    }

// ==================== INITIALIZATION ====================
function initAdmin() {
    // Fix favicon 404 error
    const faviconLink = document.createElement('link');
    faviconLink.rel = 'icon';
    faviconLink.type = 'image/svg+xml';
    faviconLink.href = 'data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>👑</text></svg>';
    document.head.appendChild(faviconLink);
    
    // Event listeners
    loginButton.addEventListener('click', handleLogin);
    logoutButton.addEventListener('click', handleLogout);
    debugToggleButton.addEventListener('click', toggleDebugConsole);
    refreshButton.addEventListener('click', refreshAdminData);
    pendingPaymentsBtn.addEventListener('click', showPendingPayments);
    processBulkBtn.addEventListener('click', processBulkLimitUpdate);

    // Handle Enter key in login form
    usernameInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') handleLogin();
    });
    passwordInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') handleLogin();
    });
    searchCustomerInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') searchCustomer();
    });

    // Add event listener for search button
    const searchButton = document.getElementById('search-customer-btn');
    if (searchButton) {
        searchButton.addEventListener('click', searchCustomer);
    }

    // ====== FIX 1: PROPER CARD CLICK HANDLING ======
    document.getElementById('admin-grid').addEventListener('click', function(e) {
        const card = e.target.closest('.admin-card');
        if (!card) return;
        
        // Get loan type from card attribute
        const loanType = card.getAttribute('data-loan-type');
        
        // Only handle cards with loan-type attribute
        if (loanType) {
            showLoansSection(loanType);
        }
    });

    // ====== FIX 2: PREVENT BUTTON CLICK CONFLICTS ======
    document.querySelectorAll('.admin-card[data-loan-type] .luxury-btn').forEach(button => {
        button.addEventListener('click', function(e) {
            e.stopPropagation(); // Prevent triggering card click
            const card = this.closest('.admin-card');
            const loanType = card.getAttribute('data-loan-type');
            showLoansSection(loanType);
        });
    });

    // Modal close handlers
    document.querySelectorAll('.close-modal').forEach(btn => {
        btn.addEventListener('click', function() {
            const modalId = this.getAttribute('data-modal');
            document.getElementById(modalId).style.display = 'none';
        });
    });

    // Back to dashboard handlers
    document.querySelectorAll('.back-to-dashboard').forEach(button => {
        button.addEventListener('click', window.backToDashboard);
    });
    
    // Explicit handler for debug console back button
    const debugBackButton = document.getElementById('debug-back-btn');
    if (debugBackButton) {
        debugBackButton.addEventListener('click', window.backToDashboard);
    }

    // Handle back buttons reliably
    const hideLoansBtn = document.getElementById('hide-loans-btn');
    if (hideLoansBtn) hideLoansBtn.addEventListener('click', window.backToDashboard);
    
    if (hidePaymentsBtn) {
        hidePaymentsBtn.addEventListener('click', window.backToDashboard);
    }
    
    const backToDashboardBtn = document.getElementById('back-to-dashboard-btn');
    if (backToDashboardBtn) {
        backToDashboardBtn.onclick = null; // Remove existing onclick handler
        backToDashboardBtn.addEventListener('click', window.backToDashboard);
    }

    // Window click handler for modals
    window.addEventListener('click', function(event) {
        if (event.target.classList.contains('modal')) {
            event.target.style.display = 'none';
        }
    });

    // Check for existing token
    const token = localStorage.getItem('adminToken');
    if (token) {
        validateToken(token);
    }
    
    // Initialize debug mode
    initDebugMode();

    // FIXED: Loan card click handling in loans section
    document.addEventListener('click', function(e) {
        // Find closest loan card element
        const card = e.target.closest('.loan-card');
        
        if (card) {
            // Prevent opening if click was on a button
            if (e.target.tagName === 'BUTTON') return;
            
            // Get loan ID from data attribute
            const loanId = card.dataset.loanId;
            
            if (loanId) {
                // Add visual feedback
                card.style.transform = 'scale(0.98)';
                setTimeout(() => card.style.transform = '', 150);
                
                // Open loan details
                window.showLoanDetails(loanId);
            }
        }
    });
}

    // ==================== AUTHENTICATION FUNCTIONS ====================
    async function handleLogin() {
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();

        if (!username || !password) {
            showError('Please enter both username and password');
            return;
        }

        loginButton.disabled = true;
        loginButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> LOGGING IN...';

        try {
            const response = await fetch(`${API_BASE_URL}/api/admin/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || 'Login failed');
            }

            // Store token and admin data
            localStorage.setItem('adminToken', data.token);
            adminData = data.admin;
            
            // Update UI
            loginContainer.classList.add('hidden');
            adminContent.classList.remove('hidden');
            document.getElementById('admin-username').textContent = `Logged in as: ${adminData.username}`;
            
            // Initialize socket connection
            initSocketConnection(data.token);
            
            // Load initial data
            loadAdminData();
            
            logDebugInfo('Admin logged in', adminData);
            
        } catch (error) {
            console.error('Login error:', error);
            showError(error.message || 'Login failed. Please try again.');
            logDebugError('Login failed', error);
        } finally {
            loginButton.disabled = false;
            loginButton.textContent = 'LOGIN';
        }
    }

    async function validateToken(token) {
        try {
            const response = await fetch(`${API_BASE_URL}/api/admin/validate-token`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (response.status === 401) {
                // Token expired - attempt refresh if possible
                const refreshResponse = await fetch(`${API_BASE_URL}/api/admin/refresh-token`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    },
                    credentials: 'include' // Include cookies if using httpOnly refresh tokens
                });
                
                if (refreshResponse.ok) {
                    const { token: newToken, refreshToken } = await refreshResponse.json();
                    localStorage.setItem('adminToken', newToken);
                    // Store refresh token securely if not httpOnly
                    if (refreshToken) {
                        localStorage.setItem('adminRefreshToken', refreshToken);
                    }
                    return validateToken(newToken); // Retry with new token
                } else {
                    // Refresh failed - force logout
                    handleLogout();
                    throw new Error('Session expired. Please log in again.');
                }
            }

            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Token validation failed');
            }

            // Token is valid - update UI and initialize
            adminData = data.admin;
            loginContainer.classList.add('hidden');
            adminContent.classList.remove('hidden');
            document.getElementById('admin-username').textContent = `Logged in as: ${adminData.username}`;
            
            // Initialize socket connection with fresh token
            initSocketConnection(token);
            
            // Load admin data
            loadAdminData();
            
            logDebugInfo('Admin token validated', adminData);
            
            return true;
            
        } catch (error) {
            console.error('Token validation error:', error);
            handleLogout();
            showError(error.message || 'Session expired. Please log in again.');
            logDebugError('Token validation failed', error);
            return false;
        }
    }

    function handleLogout() {
        // Clear all tokens
        localStorage.removeItem('adminToken');
        localStorage.removeItem('adminRefreshToken');
        
        // Disconnect socket if exists
        if (socket) {
            socket.disconnect();
            logDebugInfo('Socket disconnected on logout');
        }
        
        // Reset UI
        adminContent.classList.add('hidden');
        loginContainer.classList.remove('hidden');
        usernameInput.value = '';
        passwordInput.value = '';
        errorMessage.classList.add('hidden');
        adminData = null;
        
        // Clear any sensitive data
        clearAdminData();
        
        logDebugInfo('Admin logged out');
    }

    function showError(message, isPersistent = false) {
        errorMessage.textContent = message;
        errorMessage.classList.remove('hidden');
        
        // Only auto-hide if not a persistent error
        if (!isPersistent) {
            setTimeout(() => {
                errorMessage.classList.add('hidden');
            }, 5000);
        }
        
        logDebugWarn('Error displayed', message);
    }

    function clearAdminData() {
        // Clear any admin-related data from memory
        // Implement this based on your application's needs
    }

    // ==================== SOCKET.IO FUNCTIONS ====================
    function initSocketConnection(token) {
        if (socket) {
            socket.disconnect();
            logDebugInfo('Existing socket disconnected');
        }

        socket = io(API_BASE_URL, {
            auth: {
                token: token
            }
        });

        socket.on('connect', () => {
            logDebug('Socket connected:', socket.id);
            socket.emit('joinAdminRoom');
        });

        socket.on('disconnect', () => {
            logDebug('Socket disconnected');
        });

        socket.on('connect_error', (err) => {
            logDebug('Socket connection error:', err.message);
            setTimeout(() => {
                socket.connect();
            }, 5000);
        });

        // Real-time updates
        socket.on('newPayment', (data) => {
            logDebug('New payment received:', data);
            showNotification(`New payment submitted by ${data.fullName}: KES ${data.amount}`, 'info');
            refreshPendingPayments();
        });

        socket.on('loanApproved', (data) => {
            logDebug('Loan approved:', data);
            showNotification(`Loan approved for ${data.customer.name}`, 'success');
            refreshAdminData();
        });

        socket.on('paymentApproved', (data) => {
            logDebug('Payment approved:', data);
            showNotification(`Payment of KES ${data.amount} approved`, 'success');
            refreshAdminData();
        });

        socket.on('paymentRejected', (data) => {
            logDebug('Payment rejected:', data);
            showNotification(`Payment rejected: ${data.reason}`, 'error');
            refreshPendingPayments();
        });

        socket.on('overdueUpdate', (data) => {
            logDebug('Overdue update:', data);
            showNotification(`Overdue update for loan ${data.loanId}: ${data.overdueDays} days`, 'warning');
            if (currentView === 'loans' && currentLoanType === 'active') {
                refreshLoansData();
            }
        });
    }

    // ==================== UI FUNCTIONS ====================
    function showDashboard() {
        currentView = 'dashboard';
        loansSection.classList.add('hidden');
        pendingPaymentsSection.classList.add('hidden');
        customerProfileSection.classList.add('hidden');
        document.getElementById('admin-grid').style.display = 'grid';
        logDebugInfo('Dashboard shown');
    }

    // ====== FIX 3: IMPROVE showLoansSection FUNCTION ======
    function showLoansSection(loanType) {
        try {
            // Null check for required elements
            if (!loansSection || !loansGridContainer || !loansTableContainer) {
                throw new Error('Required DOM elements not found for loans section');
            }

            currentView = 'loans';
            currentLoanType = loanType;
            
            // Hide other sections
            pendingPaymentsSection.classList.add('hidden');
            customerProfileSection.classList.add('hidden');
            document.getElementById('admin-grid').style.display = 'none';
            
            // Show loans section
            loansSection.classList.remove('hidden');
            document.getElementById('loans-section-title').textContent = `${loanType.charAt(0).toUpperCase() + loanType.slice(1)} Loans`;
            
            // Show appropriate view
            if (loanType === 'active') {
                loansGridContainer.style.display = 'block';
                loansTableContainer.style.display = 'none';
            } else {
                loansGridContainer.style.display = 'none';
                loansTableContainer.style.display = 'block';
            }
            
            // Build API URL with proper filtering
            let apiUrl = `${API_BASE_URL}/api/admin/loan-applications?`;
            const statusMap = {
                'pending': ['pending'],
                'active': ['active'],
                'defaulted': ['defaulted'],
                'completed': ['completed']
            };
            
            if (statusMap[loanType]) {
                apiUrl += statusMap[loanType].map(s => `status=${s}`).join('&');
            } else {
                apiUrl += `status=${loanType}`;
            }
            
            // Fetch loans
            fetchLoans(apiUrl, loanType);
            logDebugInfo(`Loans section shown: ${loanType}`, { apiUrl });
            
        } catch (error) {
            console.error('Error in showLoansSection:', error);
            showNotification('Failed to load loans section. Please try again.', 'error');
            logDebugError('Error in showLoansSection', error);
            
            // Fallback to dashboard if loan section fails
            showDashboard();
        }
    }

    function showPendingPayments() {
        currentView = 'pending-payments';
        loansSection.classList.add('hidden');
        customerProfileSection.classList.add('hidden');
        document.getElementById('admin-grid').style.display = 'none';
        pendingPaymentsSection.classList.remove('hidden');
        refreshPendingPayments();
        logDebugInfo('Pending payments section shown');
    }

    function showCustomerProfile(customer) {
        currentView = 'customer-profile';
        currentCustomer = customer;
        loansSection.classList.add('hidden');
        pendingPaymentsSection.classList.add('hidden');
        document.getElementById('admin-grid').style.display = 'none';
        customerProfileSection.classList.remove('hidden');
        
        renderCustomerProfile(customer);
        logDebugInfo('Customer profile shown', customer);
    }

    function backToCustomerSearch() {
        showDashboard();
        customerDetailsContainer.innerHTML = '';
        logDebugInfo('Back to customer search');
    }

    // ==================== DATA LOADING FUNCTIONS ====================
    async function loadAdminData() {
        try {
            // Load metrics
            const metricsResponse = await fetch(`${API_BASE_URL}/api/admin/metrics`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
                }
            });
            const metricsData = await metricsResponse.json();
            
            if (metricsData.success) {
                updateMetrics(metricsData.data);
            }
            
            // Load counts for cards
            updateCardCounts();
            
            logDebugInfo('Admin data loaded');
            
        } catch (error) {
            console.error('Error loading admin data:', error);
            showNotification('Failed to load dashboard data', 'error');
            logDebugError('Error loading admin data', error);
        }
    }

    async function refreshAdminData() {
        refreshButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> REFRESHING...';
        try {
            await loadAdminData();
            
            // Refresh current view if needed
            if (currentView === 'loans') {
                refreshLoansData();
            } else if (currentView === 'pending-payments') {
                refreshPendingPayments();
            } else if (currentView === 'customer-profile' && currentCustomer) {
                const updatedCustomer = await fetchCustomerDetails(currentCustomer._id);
                renderCustomerProfile(updatedCustomer);
            }
            
            showNotification('Data refreshed successfully', 'success');
            logDebugInfo('Admin data refreshed');
            
        } catch (error) {
            console.error('Refresh error:', error);
            showNotification('Failed to refresh data', 'error');
            logDebugError('Refresh failed', error);
        } finally {
            refreshButton.innerHTML = '<i class="fas fa-sync-alt"></i> REFRESH DATA';
        }
    }

    function updateMetrics(metrics) {
        document.getElementById('total-customers').textContent = metrics.totalCustomers;
        document.getElementById('total-loans').textContent = `KES ${metrics.activeLoans.toLocaleString()}`;
        document.getElementById('total-pending').textContent = metrics.pendingApplications;
        document.getElementById('total-overdue').textContent = metrics.overdueLoans;
    }

    async function updateCardCounts() {
        try {
            const [pendingLoans, activeLoans, overdueLoans, completedLoans, pendingPayments] = await Promise.all([
                fetchLoanCount('pending'),
                fetchLoanCount('active'),
                fetchLoanCount('defaulted'),
                fetchLoanCount('completed'),
                fetchPendingPaymentCount()
            ]);
            
            document.getElementById('pending-loans-count').textContent = `${pendingLoans} pending applications`;
            document.getElementById('active-loans-count').textContent = `${activeLoans} active loans`;
            document.getElementById('overdue-loans-count').textContent = `${overdueLoans} overdue loans`;
            document.getElementById('completed-loans-count').textContent = `${completedLoans} completed loans`;
            document.getElementById('pending-payments-count').textContent = `${pendingPayments} pending payments`;
            
        } catch (error) {
            console.error('Error updating card counts:', error);
            logDebugError('Error updating card counts', error);
        }
    }

    async function fetchLoanCount(status) {
        try {
            const response = await fetch(`${API_BASE_URL}/api/admin/loan-applications?status=${status}`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
                }
            });
            const data = await response.json();
            return data.pagination?.total || 0;
        } catch (error) {
            console.error(`Error fetching ${status} loan count:`, error);
            logDebugError(`Error fetching ${status} loan count`, error);
            return 0;
        }
    }

    async function fetchPendingPaymentCount() {
        try {
            const response = await fetch(`${API_BASE_URL}/api/admin/pending-payments`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
                }
            });
            const data = await response.json();
            return data.payments?.length || 0;
        } catch (error) {
            console.error('Error fetching pending payment count:', error);
            logDebugError('Error fetching pending payment count', error);
            return 0;
        }
    }

    // ==================== LOAN MANAGEMENT FUNCTIONS ====================
    async function refreshLoansData() {
        try {
            const response = await fetch(`${API_BASE_URL}/api/admin/loan-applications?status=${currentLoanType}`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
                }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to load loans');
            }
            
            if (currentLoanType === 'active') {
                renderActiveLoansGrid(data.applications);
            } else {
                renderLoansTable(data.applications);
            }
            
            logDebugInfo(`Loans data refreshed: ${currentLoanType}`, data);
            
        } catch (error) {
            console.error('Error loading loans:', error);
            showNotification('Failed to load loans', 'error');
            logDebugError('Error loading loans', error);
        }
    }

    function renderActiveLoansGrid(loans) {
        loansGrid.innerHTML = '';
        
        if (!loans || loans.length === 0) {
            loansGrid.innerHTML = '<p>No active loans found</p>';
            return;
        }
        
        loans.forEach(loan => {
            const loanCard = createLoanCard(loan);
            loansGrid.appendChild(loanCard);
        });
    }

    function createLoanCard(loan) {
        const now = new Date();
        const dueDate = new Date(loan.dueDate);
        const daysRemaining = Math.ceil((dueDate - now) / (1000 * 60 * 60 * 24));
        const isOverdue = daysRemaining < 0;
        const overdueDays = isOverdue ? Math.abs(daysRemaining) : 0;
        const penaltyDays = Math.min(overdueDays, 6);
        
        const amountPaid = loan.amountPaid || 0;
        const totalAmount = loan.totalAmount || (loan.amount + (loan.amount * (loan.interestRate || 15) / 100) + (loan.overdueFees || 0));
        const amountDue = totalAmount - amountPaid;
        const progress = Math.min(100, (amountPaid / totalAmount) * 100);
        
        const card = document.createElement('div');
        card.className = `loan-card ${isOverdue ? 'overdue' : ''}`;
        card.style.minHeight = '300px'; // Fixed minimum height
        card.style.display = 'flex';
        card.style.flexDirection = 'column';
        card.style.justifyContent = 'space-between';
        card.style.border = '1px solid #e0e0e0';
        card.style.borderRadius = '8px';
        card.style.padding = '15px';
        card.style.boxShadow = '0 2px 4px rgba(0,0,0,0.1)';
        card.style.transition = 'transform 0.2s ease, box-shadow 0.2s ease';
        card.dataset.loanId = loan._id; // Add loan ID to card
        
        card.innerHTML = `
            <div>
                <div class="loan-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <h4 style="margin: 0; font-size: 16px; font-weight: 600;">${loan.fullName}</h4>
                    <span class="status-${loan.status}" style="padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; text-transform: uppercase;">
                        ${loan.status.toUpperCase()}
                    </span>
                </div>
                <div class="loan-details" style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px;">
                    <div class="detail" style="display: flex; justify-content: space-between;">
                        <span style="color: #666;">Principal</span>
                        <span style="font-weight: 500;">KES ${loan.amount.toLocaleString()}</span>
                    </div>
                    <div class="detail" style="display: flex; justify-content: space-between;">
                        <span style="color: #666;">Total Due</span>
                        <span style="font-weight: 500;">KES ${totalAmount.toLocaleString()}</span>
                    </div>
                    <div class="detail" style="display: flex; justify-content: space-between;">
                        <span style="color: #666;">Amount Paid</span>
                        <span style="font-weight: 500;">KES ${amountPaid.toLocaleString()}</span>
                    </div>
                    <div class="detail" style="display: flex; justify-content: space-between;">
                        <span style="color: #666;">Amount Due</span>
                        <span style="font-weight: 500;">KES ${amountDue.toLocaleString()}</span>
                    </div>
                    <div class="detail" style="display: flex; justify-content: space-between;">
                        <span style="color: #666;">${isOverdue ? 'Days Overdue' : 'Days Remaining'}</span>
                        <span class="${isOverdue ? 'text-warning' : ''}" style="font-weight: 500;">
                            ${isOverdue ? overdueDays : daysRemaining}
                            ${isOverdue && overdueDays > 6 ? ' (penalty capped)' : ''}
                        </span>
                    </div>
                    <div class="detail" style="display: flex; justify-content: space-between;">
                        <span style="color: #666;">Due Date</span>
                        <span style="font-weight: 500;">${formatDate(loan.dueDate)}</span>
                    </div>
                </div>
                <div class="progress-container" style="margin-top: 15px; height: 10px; background: #f0f0f0; border-radius: 5px;">
                    <div class="progress-bar" style="height: 100%; width: ${progress}%; background: ${progress === 100 ? '#4CAF50' : '#FFD700'}; border-radius: 5px; transition: width 0.5s ease;"></div>
                </div>
            </div>
            <div class="loan-actions" style="margin-top: auto; display: flex; gap: 10px; padding-top: 15px;">
                <button class="luxury-btn" data-action="view" data-loan-id="${loan._id}" style="padding: 8px 15px; font-size: 14px; flex: 1;">View Details</button>
                ${loan.status === 'pending' ? `
                    <button class="luxury-btn" data-action="approve" data-loan-id="${loan._id}" style="padding: 8px 15px; font-size: 14px; background: #4CAF50; color: white; flex: 1;">Approve</button>
                    <button class="luxury-btn" data-action="reject" data-loan-id="${loan._id}" style="padding: 8px 15px; font-size: 14px; background: #f44336; color: white; flex: 1;">Reject</button>
                ` : ''}
                ${isOverdue ? `
                    <button class="luxury-btn" data-action="force-complete" data-loan-id="${loan._id}" style="padding: 8px 15px; font-size: 14px; background: #2196F3; color: white; flex: 1;">Mark Complete</button>
                ` : ''}
            </div>
        `;
        
        // Add hover effects
        card.addEventListener('mouseenter', () => {
            card.style.transform = 'translateY(-2px)';
            card.style.boxShadow = '0 4px 8px rgba(0,0,0,0.15)';
        });
        
        card.addEventListener('mouseleave', () => {
            card.style.transform = '';
            card.style.boxShadow = '0 2px 4px rgba(0,0,0,0.1)';
        });
        
        // ========== IMPROVED: Card click handling ========== //
        card.addEventListener('click', function(event) {
            // Ignore clicks on buttons or inside buttons
            if (event.target.closest('button')) return;
            
            // Add visual feedback
            card.style.transform = 'scale(0.98)';
            setTimeout(() => {
                card.style.transform = '';
            }, 150);
            
            // Open loan details
            window.showLoanDetails(loan._id);
        });
        
        // ========== FIXED: Button click handling ========== //
        card.querySelectorAll('button').forEach(btn => {
            btn.addEventListener('click', function(e) {
                // Prevent card click from firing
                e.stopPropagation();
                
                const action = this.getAttribute('data-action');
                const loanId = this.getAttribute('data-loan-id');
                
                switch (action) {
                    case 'view':
                        window.showLoanDetails(loanId);
                        break;
                    case 'approve':
                        showApprovalTermsModal(loanId);
                        break;
                    case 'reject':
                        showRejectionModal(loanId);
                        break;
                    case 'force-complete':
                        forceCompleteLoan(loanId);
                        break;
                }
            });
        });
        
        return card;
    }

    function renderLoansTable(loans) {
        loansTableBody.innerHTML = '';
        
        if (!loans || loans.length === 0) {
            loansTableBody.innerHTML = '<tr><td colspan="6">No loans found</td></tr>';
            return;
        }
        
        loans.forEach(loan => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${loan.fullName}</td>
                <td>KES ${loan.amount.toLocaleString()}</td>
                <td class="status-${loan.status}">${loan.status.toUpperCase()}</td>
                <td>${formatDate(loan.createdAt)}</td>
                <td>${loan.dueDate ? formatDate(loan.dueDate) : 'N/A'}</td>
                <td>
                    <button class="action-btn" data-action="view" data-loan-id="${loan._id}">View</button>
                    ${loan.status === 'pending' ? `
                        <button class="action-btn" data-action="approve" data-loan-id="${loan._id}" style="background: #4CAF50; color: white;">Approve</button>
                        <button class="action-btn" data-action="reject" data-loan-id="${loan._id}" style="background: #f44336; color: white;">Reject</button>
                    ` : ''}
                </td>
            `;
            
            // Add event listeners to buttons
            row.querySelectorAll('button').forEach(btn => {
                btn.addEventListener('click', function() {
                    const action = this.getAttribute('data-action');
                    const loanId = this.getAttribute('data-loan-id');
                    
                    switch (action) {
                        case 'view':
                            window.showLoanDetails(loanId);
                            break;
                        case 'approve':
                            showApprovalTermsModal(loanId);
                            break;
                        case 'reject':
                            showRejectionModal(loanId);
                            break;
                    }
                });
            });
            
            loansTableBody.appendChild(row);
        });
    }

function renderLoanDetails(loan) {
    const now = new Date();
    const dueDate = new Date(loan.dueDate);
    const daysRemaining = Math.ceil((dueDate - now) / (1000 * 60 * 60 * 24));
    const isOverdue = daysRemaining < 0;
    const overdueDays = isOverdue ? Math.abs(daysRemaining) : 0;
    const penaltyDays = Math.min(overdueDays, 6);
    
    const amountPaid = loan.amountPaid || 0;
    const totalAmount = loan.totalAmount || (loan.amount + (loan.amount * (loan.interestRate || 15) / 100) + (loan.overdueFees || 0));
    const amountDue = totalAmount - amountPaid;
    const progress = Math.min(100, (amountPaid / totalAmount) * 100);
    
    document.getElementById('loanDetailsTitle').textContent = `Loan Details - ${loan.fullName}`;
    
    loanDetailsContent.innerHTML = `
        <div class="loan-details">
            <div class="detail-row">
                <span><strong>Loan ID:</strong></span>
                <span>${loan._id}</span>
            </div>
            <div class="detail-row">
                <span><strong>Status:</strong></span>
                <span class="status-${loan.status}">${loan.status.toUpperCase()}</span>
            </div>
            <div class="detail-row">
                <span><strong>Customer:</strong></span>
                <span>${loan.fullName} (${loan.phoneNumber})</span>
            </div>
            <div class="detail-row">
                <span><strong>Principal Amount:</strong></span>
                <span>KES ${loan.amount.toLocaleString()}</span>
            </div>
            <div class="detail-row">
                <span><strong>Interest Rate:</strong></span>
                <span>${loan.interestRate || 15}%</span>
            </div>
            <div class="detail-row">
                <span><strong>Total Amount:</strong></span>
                <span>KES ${totalAmount.toLocaleString()}</span>
            </div>
            <div class="detail-row">
                <span><strong>Amount Paid:</strong></span>
                <span>KES ${amountPaid.toLocaleString()}</span>
            </div>
            <div class="detail-row">
                <span><strong>Amount Due:</strong></span>
                <span>KES ${amountDue.toLocaleString()}</span>
            </div>
            <div class="detail-row">
                <span><strong>${isOverdue ? 'Days Overdue' : 'Days Remaining'}:</strong></span>
                <span class="${isOverdue ? 'text-warning' : ''}">
                    ${isOverdue ? overdueDays : daysRemaining}
                    ${isOverdue && overdueDays > 6 ? ' (penalty capped at 6 days)' : ''}
                </span>
            </div>
            <div class="detail-row">
                <span><strong>Due Date:</strong></span>
                <span>${formatDate(loan.dueDate)}</span>
            </div>
            <div class="detail-row">
                <span><strong>Created:</strong></span>
                <span>${formatDate(loan.createdAt)}</span>
            </div>
            ${loan.approvedAt ? `
            <div class="detail-row">
                <span><strong>Approved:</strong></span>
                <span>${formatDate(loan.approvedAt)}</span>
            </div>
            ` : ''}
            ${loan.adminNotes ? `
            <div class="detail-row">
                <span><strong>Admin Notes:</strong></span>
                <span>${loan.adminNotes}</span>
            </div>
            ` : ''}
        </div>
        
        <div class="payment-history">
            <h4>Payment History</h4>
            ${loan.repaymentSchedule && loan.repaymentSchedule.length > 0 ? `
                <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
                    <thead>
                        <tr>
                            <th style="text-align: left; padding: 8px; border-bottom: 1px solid #ddd;">Due Date</th>
                            <th style="text-align: left; padding: 8px; border-bottom: 1px solid #ddd;">Amount</th>
                            <th style="text-align: left; padding: 8px; border-bottom: 1px solid #ddd;">Paid</th>
                            <th style="text-align: left; padding: 8px; border-bottom: 1px solid #ddd;">Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${loan.repaymentSchedule.map(payment => `
                            <tr>
                                <td style="padding: 8px; border-bottom: 1px solid #ddd;">${formatDate(payment.dueDate)}</td>
                                <td style="padding: 8px; border-bottom: 1px solid #ddd;">KES ${payment.amount.toLocaleString()}</td>
                                <td style="padding: 8px; border-bottom: 1px solid #ddd;">KES ${payment.paidAmount || 0}</td>
                                <td style="padding: 8px; border-bottom: 1px solid #ddd;" class="status-${payment.status}">${payment.status.toUpperCase()}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            ` : '<p>No payment history available</p>'}
        </div>
        
        <div class="loan-actions" style="margin-top: 20px; display: flex; gap: 10px;">
            <!-- FIXED: Corrected documents endpoint -->
            <button class="luxury-btn" 
                    onclick="window.location.href='/api/admin/loan-applications/${loan._id}/documents'" 
                    style="padding: 10px 15px;">
                View Documents
            </button>
            ${loan.status === 'pending' ? `
                <button class="luxury-btn" onclick="showApprovalTermsModal('${loan._id}')" style="padding: 10px 15px; background: #4CAF50;">
                    Approve Loan
                </button>
                <button class="luxury-btn" onclick="showRejectionModal('${loan._id}')" style="padding: 10px 15px; background: #f44336;">
                    Reject Loan
                </button>
            ` : ''}
            ${isOverdue ? `
                <button class="luxury-btn" onclick="forceCompleteLoan('${loan._id}')" style="padding: 10px 15px; background: #2196F3;">
                    Mark Complete
                </button>
            ` : ''}
            ${loan.status === 'active' || loan.status === 'defaulted' ? `
                <button class="luxury-btn" onclick="showRecordPaymentModal('${loan._id}')" style="padding: 10px 15px; background: #FFD700; color: #000;">
                    Record Payment
                </button>
            ` : ''}
        </div>
    `;
}

    function showApprovalTermsModal(loanId) {
        // Reset form and set default values
        document.getElementById('approvalTermsForm').reset();
        document.getElementById('interestRate').value = '15';
        document.getElementById('repaymentPeriod').value = '30';
        
        // Store loan ID on the confirm button
        const confirmBtn = document.getElementById('confirm-approval-btn');
        confirmBtn.setAttribute('data-loan-id', loanId);
        
        // Clear any previous error messages
        document.getElementById('approval-form-error').textContent = '';
        
        // Show modal with fade-in animation
        approvalTermsModal.style.display = 'flex';
        setTimeout(() => {
            approvalTermsModal.classList.add('show');
        }, 10);
        logDebugInfo('Approval terms modal shown', { loanId });
    }

    function showRejectionModal(loanId) {
        // Create a more user-friendly rejection modal instead of using prompt
        const modalContent = `
            <div class="modal-content">
                <h3>Reject Loan Application</h3>
                <textarea id="rejectionReason" placeholder="Enter rejection reason..." rows="4" required></textarea>
                <div class="modal-actions">
                    <button id="cancel-reject-btn" class="btn-secondary">Cancel</button>
                    <button id="confirm-reject-btn" class="btn-danger" data-loan-id="${loanId}">Confirm Rejection</button>
                </div>
            </div>
        `;
        
        // Create and show modal
        const modal = document.createElement('div');
        modal.className = 'custom-modal';
        modal.innerHTML = modalContent;
        document.body.appendChild(modal);
        
        // Add event listeners
        document.getElementById('cancel-reject-btn').addEventListener('click', () => {
            document.body.removeChild(modal);
        });
        
        document.getElementById('confirm-reject-btn').addEventListener('click', () => {
            const reason = document.getElementById('rejectionReason').value.trim();
            if (!reason) {
                alert('Please enter a rejection reason');
                return;
            }
            
            rejectLoan(loanId, reason);
            document.body.removeChild(modal);
        });
        logDebugInfo('Rejection modal shown', { loanId });
    }

    async function approveLoan(loanId, terms) {
        try {
            // Show loading state - with null check
            const confirmBtn = document.getElementById('confirm-approval-btn');
            if (confirmBtn) {
                const originalText = confirmBtn.innerHTML;
                confirmBtn.disabled = true;
                confirmBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
            }

            const response = await fetch(`${API_BASE_URL}/api/admin/loan-applications/${loanId}/approve`, {
                method: 'PATCH',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(terms)
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || 'Failed to approve loan');
            }

            showNotification('Loan approved successfully', 'success');
            approvalTermsModal.style.display = 'none';

            // Refresh data with visual feedback
            refreshLoansData();
            refreshAdminData();
            logDebugInfo('Loan approved', { loanId, terms });

        } catch (error) {
            console.error('Error approving loan:', error);
            showNotification(error.message || 'Failed to approve loan', 'error');
            logDebugError('Loan approval failed', error);

            // Show detailed error in form if it's a validation error
            if (error.name === 'ValidationError') {
                const errorElement = document.getElementById('approval-form-error');
                if (errorElement) {
                    errorElement.textContent = error.message;
                }
            }
        } finally {
            // Reset button state with null check
            const confirmBtn = document.getElementById('confirm-approval-btn');
            if (confirmBtn) {
                confirmBtn.disabled = false;
                confirmBtn.innerHTML = 'Confirm Approval';
            }
        }
    }

    async function rejectLoan(loanId, reason) {
        try {
            // Show loading state
            const rejectBtn = document.getElementById('confirm-reject-btn');
            if (rejectBtn) {
                const originalText = rejectBtn.innerHTML;
                rejectBtn.disabled = true;
                rejectBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
            }
            
            const response = await fetch(`${API_BASE_URL}/api/admin/loan-applications/${loanId}/reject`, {
                method: 'PATCH',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ reason })
            });

            // Check content type before parsing
            const contentType = response.headers.get('content-type');
            let data = {};
            
            if (contentType && contentType.includes('application/json')) {
                data = await response.json();
            } else {
                // Handle non-JSON responses (like HTML errors)
                const text = await response.text();
                throw new Error(text || 'Non-JSON response received');
            }

            if (!response.ok) {
                throw new Error(data.message || 'Failed to reject loan');
            }
            
            showNotification('Loan rejected successfully', 'success');
            
            // Refresh data with visual feedback
            refreshLoansData();
            refreshAdminData();
            logDebugInfo('Loan rejected', { loanId, reason });
            
        } catch (error) {
            console.error('Error rejecting loan:', error);
            showNotification(error.message || 'Failed to reject loan', 'error');
            logDebugError('Loan rejection failed', error);
        } finally {
            // Reset button state
            const rejectBtn = document.getElementById('confirm-reject-btn');
            if (rejectBtn) {
                rejectBtn.disabled = false;
                rejectBtn.innerHTML = 'Confirm Rejection';
            }
        }
    }

    // Enhanced approval form submission handler
    document.getElementById('approvalTermsForm')?.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const loanId = document.getElementById('confirm-approval-btn').getAttribute('data-loan-id');
        const interestRate = parseFloat(document.getElementById('interestRate').value);
        const repaymentPeriod = parseInt(document.getElementById('repaymentPeriod').value);
        const adminNotes = document.getElementById('adminNotes').value;
        
        // Clear previous errors
        document.getElementById('interestRate-error').textContent = '';
        document.getElementById('repaymentPeriod-error').textContent = '';
        
        // Validate inputs
        let isValid = true;
        
        if (isNaN(interestRate) || interestRate < 5 || interestRate > 30) {
            document.getElementById('interestRate-error').textContent = 'Please enter a valid interest rate (5-30%)';
            isValid = false;
        }
        
        if (isNaN(repaymentPeriod) || repaymentPeriod < 7 || repaymentPeriod > 90) {
            document.getElementById('repaymentPeriod-error').textContent = 'Please enter a valid repayment period (7-90 days)';
            isValid = false;
        }
        
        if (!isValid) return;
        
        approveLoan(loanId, {
            interestRate,
            repaymentPeriod,
            adminNotes
        });
    });

    // Modal close handler
    document.querySelector('.close-modal[data-modal="approvalTermsModal"]')?.addEventListener('click', function() {
        approvalTermsModal.classList.remove('show');
        setTimeout(() => {
            approvalTermsModal.style.display = 'none';
        }, 300);
    });

    async function forceCompleteLoan(loanId) {
        if (!confirm('Are you sure you want to mark this loan as complete? This cannot be undone.')) {
            return;
        }
        
        try {
            const response = await fetch(`${API_BASE_URL}/api/admin/loan-applications/${loanId}/force-complete`, {
                method: 'PATCH',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
                }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to complete loan');
            }
            
            showNotification('Loan marked as completed', 'success');
            refreshLoansData();
            refreshAdminData();
            logDebugInfo('Loan force completed', { loanId });
            
        } catch (error) {
            console.error('Error completing loan:', error);
            showNotification(error.message || 'Failed to complete loan', 'error');
            logDebugError('Loan completion failed', error);
        }
    }

    function showRecordPaymentModal(loanId) {
        const amount = prompt('Enter payment amount:');
        if (!amount || isNaN(amount) || parseFloat(amount) <= 0) {
            alert('Please enter a valid amount');
            return;
        }
        
        const reference = prompt('Enter payment reference (M-Pesa code or other reference):');
        if (!reference || reference.trim() === '') {
            alert('Please enter a valid reference');
            return;
        }
        
        recordPayment(loanId, parseFloat(amount), reference.trim());
    }

    async function recordPayment(loanId, amount, reference) {
        try {
            const response = await fetch(`${API_BASE_URL}/api/admin/loans/${loanId}/record-payment`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ amount, reference })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to record payment');
            }
            
            showNotification(`Payment of KES ${amount.toLocaleString()} recorded`, 'success');
            refreshLoansData();
            refreshAdminData();
            logDebugInfo('Payment recorded', { loanId, amount, reference });
            
        } catch (error) {
            console.error('Error recording payment:', error);
            showNotification(error.message || 'Failed to record payment', 'error');
            logDebugError('Payment recording failed', error);
        }
    }

    // ==================== PAYMENT MANAGEMENT FUNCTIONS ====================
    async function refreshPendingPayments() {
        try {
            const response = await fetch(`${API_BASE_URL}/api/admin/pending-payments`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
                }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to load pending payments');
            }
            
            renderPendingPayments(data.payments);
            logDebugInfo('Pending payments refreshed', data.payments);
            
        } catch (error) {
            console.error('Error loading pending payments:', error);
            showNotification('Failed to load pending payments', 'error');
            logDebugError('Pending payments load failed', error);
        }
    }

    function renderPendingPayments(payments) {
        pendingPaymentsTableBody.innerHTML = '';
        
        if (!payments || payments.length === 0) {
            pendingPaymentsTableBody.innerHTML = '<tr><td colspan="5">No pending payments found</td></tr>';
            return;
        }
        
        payments.forEach(payment => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${payment.userId?.fullName || 'N/A'}</td>
                <td>KES ${payment.amount.toLocaleString()}</td>
                <td>${payment.reference}</td>
                <td>${formatDate(payment.createdAt)}</td>
                <td>
                    <button class="action-btn" data-action="approve" data-payment-id="${payment._id}" style="background: #4CAF50; color: white;">Approve</button>
                    <button class="action-btn" data-action="reject" data-payment-id="${payment._id}" style="background: #f44336; color: white;">Reject</button>
                </td>
            `;
            
            // Add event listeners to buttons
            row.querySelectorAll('button').forEach(btn => {
                btn.addEventListener('click', function() {
                    const action = this.getAttribute('data-action');
                    const paymentId = this.getAttribute('data-payment-id');
                    
                    switch (action) {
                        case 'approve':
                            approvePayment(paymentId);
                            break;
                        case 'reject':
                            rejectPayment(paymentId);
                            break;
                    }
                });
            });
            
            pendingPaymentsTableBody.appendChild(row);
        });
    }

    async function approvePayment(paymentId) {
        try {
            const response = await fetch(`${API_BASE_URL}/api/admin/payments/${paymentId}/approve`, {
                method: 'PATCH',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
                }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to approve payment');
            }
            
            showNotification('Payment approved successfully', 'success');
            refreshPendingPayments();
            refreshAdminData();
            logDebugInfo('Payment approved', { paymentId });
            
        } catch (error) {
            console.error('Error approving payment:', error);
            showNotification(error.message || 'Failed to approve payment', 'error');
            logDebugError('Payment approval failed', error);
        }
    }

    async function rejectPayment(paymentId) {
        const reason = prompt('Enter rejection reason:');
        if (!reason || reason.trim() === '') {
            alert('Please enter a valid reason');
            return;
        }
        
        try {
            // Use the unified status endpoint with proper request body
            const response = await fetch(`${API_BASE_URL}/api/admin/payments/${paymentId}/status`, {
                method: 'PATCH',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ 
                    status: 'rejected',  // Required status field
                    reason             // Rejection reason
                })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to reject payment');
            }
            
            showNotification('Payment rejected successfully', 'success');
            refreshPendingPayments();
            logDebugInfo('Payment rejected', { paymentId, reason });
            
        } catch (error) {
            console.error('Error rejecting payment:', error);
            showNotification(error.message || 'Failed to reject payment', 'error');
            logDebugError('Payment rejection failed', error);
        }
    }

    // ==================== CUSTOMER MANAGEMENT FUNCTIONS ====================
    function renderCustomerSearchResults(customers) {
        customerDetailsContainer.innerHTML = '';
        
        customers.forEach(customer => {
            const availableCredit = customer.maxLoanLimit - customer.currentLoanBalance;
            const creditUtilization = customer.maxLoanLimit > 0 
                ? (customer.currentLoanBalance / customer.maxLoanLimit) * 100 
                : 0;
            
            const customerCard = document.createElement('div');
            customerCard.className = 'customer-card';
            customerCard.innerHTML = `
                <div class="customer-header">
                    <h4>${customer.fullName || 'Unknown Customer'}</h4>
                    <span class="status-badge status-${customer.verificationStatus || 'pending'}">
                        ${(customer.verificationStatus || 'pending').toUpperCase()}
                    </span>
                </div>
                
                <div class="customer-details-grid">
                    <div class="detail-item">
                        <span class="detail-label">Customer ID:</span>
                        <span class="detail-value">${customer.customerId || 'N/A'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Phone:</span>
                        <span class="detail-value">${customer.phoneNumber}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Email:</span>
                        <span class="detail-value">${customer.email || 'N/A'}</span>
                    </div>
                    
                    <div class="detail-item">
                        <span class="detail-label">Credit Limit:</span>
                        <span class="detail-value">KES ${customer.maxLoanLimit.toLocaleString()}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Current Balance:</span>
                        <span class="detail-value">KES ${customer.currentLoanBalance.toLocaleString()}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Available Credit:</span>
                        <span class="detail-value ${availableCredit <= 0 ? 'text-danger' : ''}">
                            KES ${availableCredit.toLocaleString()}
                        </span>
                    </div>
                    
                    <div class="detail-item full-width">
                        <div class="credit-utilization">
                            <span class="detail-label">Credit Utilization:</span>
                            <div class="utilization-bar-container">
                                <div class="utilization-bar" style="width: ${Math.min(creditUtilization, 100)}%"></div>
                                <span class="utilization-text">${Math.round(creditUtilization)}%</span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="limit-controls">
                    <div class="limit-input-group">
                        <input type="number" 
                               id="newLimit-${customer._id}" 
                               placeholder="New loan limit" 
                               min="0" 
                               value="${customer.maxLoanLimit}"
                               class="limit-input">
                        <button class="luxury-btn limit-update-btn" 
                                data-customer-id="${customer._id}">
                            <i class="fas fa-save"></i> Update Limit
                        </button>
                    </div>
                    <div class="limit-message" id="limitMessage-${customer._id}"></div>
                </div>
                
                <div class="customer-actions">
                    <button class="action-btn view-profile-btn" 
                            data-customer-id="${customer._id}">
                        <i class="fas fa-user-circle"></i> View Profile
                    </button>
                    ${customer.activeLoan ? `
                    <button class="action-btn view-loan-btn" 
                            data-loan-id="${customer.activeLoan._id}">
                        <i class="fas fa-file-invoice-dollar"></i> View Active Loan
                    </button>
                    ` : ''}
                </div>
            `;
            
            // Add event listeners to buttons
            customerCard.querySelector('.limit-update-btn').addEventListener('click', function() {
                const customerId = this.getAttribute('data-customer-id');
                updateCustomerLimit(customerId);
            });
            
            customerCard.querySelector('.view-profile-btn').addEventListener('click', function() {
                const customerId = this.getAttribute('data-customer-id');
                viewCustomerProfile(customerId);
            });
            
            if (customer.activeLoan) {
                customerCard.querySelector('.view-loan-btn').addEventListener('click', function() {
                    const loanId = this.getAttribute('data-loan-id');
                    window.showLoanDetails(loanId);
                });
            }
            
            customerDetailsContainer.appendChild(customerCard);
        });
    }

    async function fetchCustomerDetails(customerId) {
        try {
            const response = await fetch(`${API_BASE_URL}/api/admin/customers/${customerId}`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
                }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to fetch customer details');
            }
            
            return data.customer;
            
        } catch (error) {
            console.error('Error fetching customer details:', error);
            showNotification(error.message || 'Failed to fetch customer details', 'error');
            logDebugError('Customer details fetch failed', error);
            return null;
        }
    }

    function renderCustomerProfile(customer) {
        if (!customer) return;
        
        const availableCredit = customer.maxLoanLimit - customer.currentLoanBalance;
        const creditUtilization = customer.maxLoanLimit > 0 
            ? (customer.currentLoanBalance / customer.maxLoanLimit) * 100 
            : 0;
        
        customerProfileSection.innerHTML = `
            <div class="profile-header">
                <button class="back-btn" id="back-to-search-btn">
                    <i class="fas fa-arrow-left"></i> Back to Search
                </button>
                <h2>${customer.fullName}'s Profile</h2>
            </div>
            
            <div class="customer-profile-grid">
                <div class="profile-section">
                    <h3><i class="fas fa-user"></i> Personal Information</h3>
                    <div class="profile-field">
                        <span class="field-label">Full Name:</span>
                        <span class="field-value">${customer.fullName}</span>
                    </div>
                    <div class="profile-field">
                        <span class="field-label">Customer ID:</span>
                        <span class="field-value">${customer.customerId}</span>
                    </div>
                    <div class="profile-field">
                        <span class="field-label">Phone Number:</span>
                        <span class="field-value">${customer.phoneNumber}</span>
                    </div>
                    <div class="profile-field">
                        <span class="field-label">Email:</span>
                        <span class="field-value">${customer.email || 'N/A'}</span>
                    </div>
                    <div class="profile-field">
                        <span class="field-label">Verification Status:</span>
                        <span class="status-badge status-${customer.verificationStatus || 'pending'}">
                            ${(customer.verificationStatus || 'pending').toUpperCase()}
                        </span>
                    </div>
                    <div class="profile-field">
                        <span class="field-label">Member Since:</span>
                        <span class="field-value">${formatDate(customer.createdAt)}</span>
                    </div>
                </div>
                
                <div class="profile-section">
                    <h3><i class="fas fa-credit-card"></i> Loan Information</h3>
                    <div class="profile-field">
                        <span class="field-label">Maximum Loan Limit:</span>
                        <span class="field-value">KES ${customer.maxLoanLimit.toLocaleString()}</span>
                    </div>
                    <div class="profile-field">
                        <span class="field-label">Current Loan Balance:</span>
                        <span class="field-value">KES ${customer.currentLoanBalance.toLocaleString()}</span>
                    </div>
                    <div class="profile-field">
                        <span class="field-label">Available Credit:</span>
                        <span class="field-value ${availableCredit <= 0 ? 'text-danger' : ''}">
                            KES ${availableCredit.toLocaleString()}
                        </span>
                    </div>
                    
                    <div class="credit-utilization">
                        <span class="field-label">Credit Utilization:</span>
                        <div class="utilization-bar-container">
                            <div class="utilization-bar" style="width: ${Math.min(creditUtilization, 100)}%"></div>
                            <span class="utilization-text">${Math.round(creditUtilization)}%</span>
                        </div>
                    </div>
                    
                    <div class="limit-controls">
                        <h4>Update Loan Limit</h4>
                        <div class="limit-input-group">
                            <input type="number" 
                                   id="newCustomerLimit" 
                                   placeholder="New loan limit" 
                                   min="0" 
                                   value="${customer.maxLoanLimit}"
                                   class="limit-input">
                            <button class="luxury-btn limit-update-btn" 
                                    data-customer-id="${customer._id}">
                                <i class="fas fa-save"></i> Update Limit
                            </button>
                        </div>
                        <div class="limit-message" id="customerLimitMessage"></div>
                    </div>
                </div>
                
                ${customer.activeLoan ? `
                <div class="profile-section">
                    <h3><i class="fas fa-file-invoice"></i> Active Loan</h3>
                    <div class="profile-field">
                        <span class="field-label">Loan Amount:</span>
                        <span class="field-value">KES ${customer.activeLoan.amount.toLocaleString()}</span>
                    </div>
                    <div class="profile-field">
                        <span class="field-label">Amount Paid:</span>
                        <span class="field-value">KES ${customer.activeLoan.amountPaid.toLocaleString()}</span>
                    </div>
                    <div class="profile-field">
                        <span class="field-label">Status:</span>
                        <span class="status-badge status-${customer.activeLoan.status}">
                            ${customer.activeLoan.status.toUpperCase()}
                        </span>
                    </div>
                    <div class="profile-field">
                        <span class="field-label">Due Date:</span>
                        <span class="field-value">${formatDate(customer.activeLoan.dueDate)}</span>
                    </div>
                    <button class="luxury-btn view-loan-btn" 
                            data-loan-id="${customer.activeLoan._id}">
                        <i class="fas fa-file-invoice-dollar"></i> View Loan Details
                    </button>
                </div>
                ` : ''}
            </div>
            
            <div class="profile-actions">
                <button class="danger-btn" data-customer-id="${customer._id}">
                    <i class="fas fa-trash-alt"></i> Delete Customer
                </button>
            </div>
        `;
        
        // Add event listeners
        document.getElementById('back-to-search-btn').addEventListener('click', backToCustomerSearch);
        document.querySelector('.limit-update-btn').addEventListener('click', function() {
            const customerId = this.getAttribute('data-customer-id');
            updateCustomerLimit(customerId, true);
        });
        document.querySelector('.danger-btn').addEventListener('click', function() {
            const customerId = this.getAttribute('data-customer-id');
            deleteCustomer(customerId);
        });
        
        if (customer.activeLoan) {
            document.querySelector('.view-loan-btn').addEventListener('click', function() {
                const loanId = this.getAttribute('data-loan-id');
                window.showLoanDetails(loanId);
            });
        }
    }

    async function updateCustomerLimit(customerId, isProfileView = false) {
        const limitInput = isProfileView 
            ? document.getElementById('newCustomerLimit')
            : document.getElementById(`newLimit-${customerId}`);
            
        const messageElement = isProfileView
            ? document.getElementById('customerLimitMessage')
            : document.getElementById(`limitMessage-${customerId}`);
            
        const newLimit = parseFloat(limitInput.value);
        
        if (isNaN(newLimit) || newLimit < 0) {
            messageElement.textContent = 'Please enter a valid limit amount';
            messageElement.className = 'limit-message error';
            return;
        }
        
        try {
            const response = await fetch(`${API_BASE_URL}/api/admin/customers/${customerId}/limit`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ newLimit })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to update limit');
            }
            
            messageElement.textContent = 'Loan limit updated successfully!';
            messageElement.className = 'limit-message success';
            
            // Refresh data
            if (isProfileView && currentCustomer) {
                const updatedCustomer = await fetchCustomerDetails(currentCustomer._id);
                renderCustomerProfile(updatedCustomer);
            } else {
                searchCustomer();
            }
            
            showNotification('Loan limit updated successfully', 'success');
            logDebugInfo('Customer limit updated', { customerId, newLimit });
            
        } catch (error) {
            console.error('Error updating limit:', error);
            messageElement.textContent = error.message || 'Failed to update limit';
            messageElement.className = 'limit-message error';
            logDebugError('Customer limit update failed', error);
        }
    }

    async function deleteCustomer(customerId) {
        if (!confirm('Are you sure you want to delete this customer? This action cannot be undone.')) {
            return;
        }
        
        try {
            const response = await fetch(`${API_BASE_URL}/api/admin/customers/${customerId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
                }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to delete customer');
            }
            
            showNotification('Customer deleted successfully', 'success');
            backToCustomerSearch();
            logDebugInfo('Customer deleted', { customerId });
            
        } catch (error) {
            console.error('Error deleting customer:', error);
            showNotification(error.message || 'Failed to delete customer', 'error');
            logDebugError('Customer deletion failed', error);
        }
    }

    function viewCustomerProfile(customerId) {
        fetchCustomerDetails(customerId).then(customer => {
            if (customer) {
                showCustomerProfile(customer);
            }
        });
    }

    // ==================== BULK OPERATIONS ====================
    async function processBulkLimitUpdate() {
        const file = bulkLimitFile.files[0];
        if (!file) {
            alert('Please select a CSV file first');
            return;
        }
        
        processBulkBtn.disabled = true;
        processBulkBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> PROCESSING...';
        bulkUpdateResult.innerHTML = '';
        
        try {
            const formData = new FormData();
            formData.append('file', file);
            
            const response = await fetch(`${API_BASE_URL}/api/admin/bulk-limit-update`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
                },
                body: formData
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to process bulk update');
            }
            
            bulkUpdateResult.innerHTML = `
                <div style="color: #4CAF50;">
                    <i class="fas fa-check-circle"></i> Bulk update processed successfully
                </div>
                <div style="margin-top: 10px;">
                    <strong>Updated:</strong> ${data.updatedCount} customers
                </div>
                ${data.errors.length > 0 ? `
                <div style="margin-top: 10px;">
                    <strong>Errors:</strong> ${data.errors.length}
                    <ul style="margin-top: 5px; color: #f44336;">
                        ${data.errors.map(error => `<li>${error}</li>`).join('')}
                    </ul>
                </div>
                ` : ''}
            `;
            
            showNotification('Bulk update processed successfully', 'success');
            logDebugInfo('Bulk limit update processed', data);
            
        } catch (error) {
            console.error('Bulk update error:', error);
            bulkUpdateResult.innerHTML = `
                <div style="color: #f44336;">
                    <i class="fas fa-times-circle"></i> ${error.message || 'Failed to process bulk update'}
                </div>
            `;
            logDebugError('Bulk limit update failed', error);
        } finally {
            processBulkBtn.disabled = false;
            processBulkBtn.textContent = 'PROCESS BULK UPDATE';
            bulkLimitFile.value = '';
        }
    }

    // ==================== REPORT GENERATION ====================
    async function generateReport() {
        const reportType = document.getElementById('reportType').value;
        let startDate, endDate;
        
        if (reportType === 'custom') {
            startDate = document.getElementById('startDate').value;
            endDate = document.getElementById('endDate').value;
            
            if (!startDate || !endDate) {
                alert('Please select both start and end dates');
                return;
            }
        }
        
        try {
            let url = `${API_BASE_URL}/api/admin/reports/${reportType}`;
            if (reportType === 'custom') {
                url += `?startDate=${startDate}&endDate=${endDate}`;
            }
            
            const response = await fetch(url, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
                }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to generate report');
            }
            
            renderReport(data.data);
            reportModal.style.display = 'flex';
            logDebugInfo('Report generated', { reportType, startDate, endDate });
            
        } catch (error) {
            console.error('Report generation error:', error);
            showNotification(error.message || 'Failed to generate report', 'error');
            logDebugError('Report generation failed', error);
        }
    }

    function renderReport(reportData) {
        document.getElementById('reportModalTitle').textContent = reportData.title;
        
        reportContent.innerHTML = `
            <div style="margin-bottom: 20px;">
                <p><strong>Date Range:</strong> ${reportData.startDate} to ${reportData.endDate}</p>
            </div>
            
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-bottom: 20px;">
                <div style="background: #f5f5f5; padding: 15px; border-radius: 5px;">
                    <h4 style="margin-top: 0; color: #333;">Total Loans</h4>
                    <p style="font-size: 24px; font-weight: bold; color: #2c3e50;">${reportData.totalLoans}</p>
                </div>
                <div style="background: #f5f5f5; padding: 15px; border-radius: 5px;">
                    <h4 style="margin-top: 0; color: #333;">Repayments Received</h4>
                    <p style="font-size: 24px; font-weight: bold; color: #2c3e50;">KES ${reportData.repaymentsReceived.toLocaleString()}</p>
                </div>
                <div style="background: #f5f5f5; padding: 15px; border-radius: 5px;">
                    <h4 style="margin-top: 0; color: #333;">Default Rate</h4>
                    <p style="font-size: 24px; font-weight: bold; color: #2c3e50;">${reportData.defaultRate}%</p>
                </div>
            </div>
            
            <h3 style="margin-top: 30px;">Daily Activity</h3>
            <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
                <thead>
                    <tr style="background: #f5f5f5;">
                        <th style="padding: 10px; text-align: left; border-bottom: 1px solid #ddd;">Date</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 1px solid #ddd;">New Loans</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 1px solid #ddd;">Repayments</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 1px solid #ddd;">Defaults</th>
                    </tr>
                </thead>
                <tbody>
                    ${reportData.dailyActivity.map(day => `
                        <tr>
                            <td style="padding: 10px; border-bottom: 1px solid #ddd;">${day.date}</td>
                            <td style="padding: 10px; border-bottom: 1px solid #ddd;">${day.newLoans}</td>
                            <td style="padding: 10px; border-bottom: 1px solid #ddd;">KES ${day.repayments.toLocaleString()}</td>
                            <td style="padding: 10px; border-bottom: 1px solid #ddd;">${day.defaults}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }

    // ==================== UTILITY FUNCTIONS ====================
    function formatDate(dateString, includeTime = false) {
        if (!dateString) return 'N/A';
        
        try {
            const date = new Date(dateString);
            const options = {
                day: '2-digit',
                month: '2-digit',
                year: 'numeric'
            };
            
            if (includeTime) {
                options.hour = '2-digit';
                options.minute = '2-digit';
                options.hour12 = true;
            }
            
            return date.toLocaleDateString('en-GB', options);
        } catch (e) {
            console.error('Date formatting error:', e);
            return 'Invalid Date';
        }
    }

    function showNotification(message, type = 'info', duration = 5000) {
        // Remove existing notifications of the same type
        const existingNotifications = document.querySelectorAll(`.notification.${type}`);
        existingNotifications.forEach(notification => {
            notification.remove();
        });

        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.setAttribute('aria-live', 'polite');
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${getNotificationIcon(type)}"></i>
                <span>${message}</span>
                <button class="notification-close" aria-label="Close notification">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;

        document.body.appendChild(notification);

        // Add close button functionality
        notification.querySelector('.notification-close').addEventListener('click', () => {
            dismissNotification(notification);
        });

        // Auto-dismiss after duration
        const timeoutId = setTimeout(() => {
            dismissNotification(notification);
        }, duration);

        // Store timeout ID for potential clearing
        notification.dataset.timeoutId = timeoutId;
        logDebugInfo('Notification shown', { message, type, duration });
    }

    function dismissNotification(notification) {
        if (notification.dataset.timeoutId) {
            clearTimeout(notification.dataset.timeoutId);
        }
        notification.style.opacity = '0';
        setTimeout(() => notification.remove(), 300);
    }

    function getNotificationIcon(type) {
        const icons = {
            success: 'check-circle',
            error: 'times-circle',
            warning: 'exclamation-circle',
            info: 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    function toggleDebugConsole() {
        debugMode = !debugMode;
        debugConsole.style.display = debugMode ? 'block' : 'none';
        debugToggleButton.querySelector('.debug-btn-text').textContent = debugMode ? 'HIDE DEBUG' : 'SHOW DEBUG';
        
        // Save debug state to localStorage
        localStorage.setItem('debugMode', debugMode);
        
        // Dispatch event for other components to react
        document.dispatchEvent(new CustomEvent('debugModeChanged', { detail: debugMode }));
        logDebugInfo('Debug console toggled', { debugMode });
    }
    
    function initDebugMode() {
        const savedDebugMode = localStorage.getItem('debugMode');
        if (savedDebugMode !== null) {
            debugMode = savedDebugMode === 'true';
            debugConsole.style.display = debugMode ? 'block' : 'none';
            debugToggleButton.querySelector('.debug-btn-text').textContent = 
                debugMode ? 'HIDE DEBUG' : 'SHOW DEBUG';
        }
    }

    // ==================== GLOBAL FUNCTION EXPORTS ====================
    window.showApprovalTermsModal = showApprovalTermsModal;
    window.showRejectionModal = showRejectionModal;
    window.forceCompleteLoan = forceCompleteLoan;
    window.showRecordPaymentModal = showRecordPaymentModal;
    window.updateCustomerLimit = updateCustomerLimit;
    window.viewCustomerProfile = viewCustomerProfile;
    window.backToCustomerSearch = backToCustomerSearch;
    window.searchCustomer = searchCustomer;

    // Report type change handler
    document.getElementById('reportType').addEventListener('change', function() {
        const customDateRange = document.getElementById('customDateRange');
        customDateRange.style.display = this.value === 'custom' ? 'block' : 'none';
    });

    // Generate report button handler
    document.getElementById('generate-report-btn').addEventListener('click', generateReport);

    // Export report button handler
    document.getElementById('export-report-btn').addEventListener('click', function() {
        // In a real implementation, this would generate a CSV file
        alert('Export to CSV functionality would be implemented here');
    });

    // Initialize custom date range visibility
    document.getElementById('customDateRange').style.display = 'none';

    // Initialize admin panel
    initAdmin();
});