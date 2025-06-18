// ==================== GLOBAL VARIABLES ====================
const API_BASE_URL = window.location.hostname === 'localhost'
  ? 'http://localhost:3000'
  : 'https://fonte-lenders.onrender.com';

// Date formatting utility
function formatDate(dateString) {
  if (!dateString) return 'N/A';
  const date = new Date(dateString);
  return date.toLocaleDateString('en-GB', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric'
  });
}

// ==================== SOCKET.IO CONNECTION ====================
// Initialize Socket.IO connection with enhanced configuration
const socket = io(API_BASE_URL, {
  auth: {
    token: localStorage.getItem('adminToken')
  },
  reconnection: true,
  reconnectionAttempts: 5,
  reconnectionDelay: 1000,
  autoConnect: true // This ensures it tries to connect immediately
});

// Add error handlers
socket.on('connect_error', (err) => {
  debugLog(`Socket connection error: ${err.message}`);
  showNotification('Connection error. Attempting to reconnect...', 'warning');
});

socket.on('disconnect', (reason) => {
  debugLog(`Socket disconnected: ${reason}`);
  if (reason === 'io server disconnect') {
    // Auto-reconnect if server drops connection
    socket.connect();
    showNotification('Reconnecting to server...', 'info');
  }
});

// Global variables
let currentAdmin = null;
let currentLoanId = null;
let currentCustomerId = null; // Track currently viewed customer

// ==================== SOCKET EVENT LISTENERS ====================
// Listen for loan updates
socket.on('loanUpdate', (data) => {
    debugLog(`Received loanUpdate: ${JSON.stringify(data)}`);
    
    // Refresh all relevant sections
    if (currentCustomerId === data.userId) {
        loadCustomerProfile(currentCustomerId);
    }
    
    showLoans('pending');
    showLoans('active');
    showPendingPayments();
    
    // Show notification
    showNotification(`Loan ${data.loanId} ${data.status} by ${data.adminName}`, 'info');
});

// Listen for payment updates
socket.on('paymentUpdate', (data) => {
    debugLog(`Received paymentUpdate: ${JSON.stringify(data)}`);
    
    // Refresh all relevant sections
    if (currentCustomerId === data.userId) {
        loadCustomerProfile(currentCustomerId);
    }
    
    showPendingPayments();
    
    if (currentLoanId === data.loanId) {
        showLoanDetails(data.loanId);
    }
    
    // Show notification
    showNotification(`Payment ${data.status} for loan ${data.loanId}`, 'info');
});

// Listen for limit updates
socket.on('limitUpdate', (data) => {
    debugLog(`Received limitUpdate: ${JSON.stringify(data)}`);
    showNotification(`Loan limit updated for customer`, 'info');
    
    // Refresh customer view if we're looking at it
    if (currentCustomerId === data.customerId) {
        loadCustomerProfile(data.customerId);
    }
});

// Listen for loan approval events
socket.on('loanApproved', (data) => {
    debugLog(`Received loanApproved event: ${JSON.stringify(data)}`);
    
    // Refresh customer profile if viewing the customer
    if (currentCustomerId === data.userId) {
        loadCustomerProfile(currentCustomerId);
        debugLog(`Refreshed customer profile for ${currentCustomerId}`);
    }
    
    // Refresh loan lists
    const currentStatus = document.getElementById('loans-section-title')?.textContent || '';
    if (currentStatus.includes('Pending') || currentStatus.includes('Active')) {
        showLoans('pending');
        debugLog('Refreshed loans list after approval');
    }
});

// Listen for payment approved events
socket.on('paymentApproved', (data) => {
    debugLog(`Received paymentApproved: ${JSON.stringify(data)}`);
    showNotification(`Payment of KES ${data.amount} approved for ${data.customerName}`, 'success');
    
    if (currentCustomerId === data.userId) {
        loadCustomerProfile(data.userId);
    }
    
    if (currentLoanId === data.loanId) {
        showLoanDetails(data.loanId);
    }
});

// Listen for payment rejected events
socket.on('paymentRejected', (data) => {
    debugLog(`Received paymentRejected: ${JSON.stringify(data)}`);
    showNotification(`Payment rejected by ${data.adminName}`, 'warning');
});

// Listen for admin notifications
socket.on('adminNotification', (data) => {
    debugLog(`Received admin notification: ${JSON.stringify(data)}`);
    showNotification(data.message, data.type || 'info');
});

// Listen for reconnection events
socket.on('reconnect', (attemptNumber) => {
    debugLog(`Socket reconnected after ${attemptNumber} attempts`);
    showNotification('Connection restored', 'success');
    
    // Re-authenticate after reconnection
    if (currentAdmin) {
        socket.emit('authenticate', { token: localStorage.getItem('adminToken') });
    }
});

// Listen for reconnect failed events
socket.on('reconnect_failed', () => {
    debugLog('Socket reconnection failed');
    showNotification('Failed to reconnect to server. Please refresh the page.', 'error');
});

// ==================== API CLIENT (UTILITY FUNCTION) ====================
async function apiClient(endpoint, method = 'GET', body = null) {
    const token = localStorage.getItem("adminToken");
    if (!token) {
        debugLog('No token found - logging out');
        logout();
        throw new Error('Authentication required');
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000); // 15s timeout

    try {
        debugLog(`API request: ${method} ${endpoint}`);
        const response = await fetch(`${API_BASE_URL}${endpoint}`, {
            method,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: body ? JSON.stringify(body) : null,
            signal: controller.signal
        });

        clearTimeout(timeoutId);
        
        // Handle 401 Unauthorized responses
        if (response.status === 401) {
            debugLog('Token expired - attempting refresh');
            try {
                // Call refresh token endpoint
                const refreshResponse = await fetch(`${API_BASE_URL}/api/admin/refresh-token`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        refreshToken: localStorage.getItem('adminRefreshToken') 
                    })
                });

                if (refreshResponse.ok) {
                    const { token: newToken, refreshToken } = await refreshResponse.json();
                    localStorage.setItem('adminToken', newToken);
                    localStorage.setItem('adminRefreshToken', refreshToken);
                    
                    // Retry original request with new token
                    return apiClient(endpoint, method, body);
                } else {
                    throw new Error('Failed to refresh token');
                }
            } catch (refreshError) {
                debugLog(`Token refresh failed: ${refreshError.message}`);
                logout();
                throw new Error('Session expired. Please login again.');
            }
        }
        
        // Handle 204 No Content responses
        if (response.status === 204) {
            return { success: true };
        }
        
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const text = await response.text();
            debugLog(`Non-JSON response: ${text}`);
            throw new Error('Invalid server response');
        }

        const data = await response.json();
        debugLog(`API response: ${response.status} ${JSON.stringify(data)}`);
        
        if (!response.ok) {
            throw new Error(data.message || `Request failed with status ${response.status}`);
        }
        
        return data;
    } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            debugLog(`API timeout: ${endpoint}`);
            throw new Error('Request timed out');
        }
        debugLog(`API error: ${error.message}`);
        throw error;
    }
}

// ==================== DEBUG LOGGER ====================
function debugLog(message) {
    const consoleDiv = document.getElementById('debug-console');
    if (consoleDiv) {
        const entry = document.createElement('div');
        entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        consoleDiv.appendChild(entry);
        consoleDiv.scrollTop = consoleDiv.scrollHeight;
    }
    console.log(message);
}

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', async () => {
    debugLog('DOMContentLoaded - Initializing admin portal');
    await checkAuthStatus();
    setupEventListeners();
    
    // Add admin to admin room if authenticated
    if (currentAdmin) {
        socket.emit('joinAdminRoom');
        debugLog('Joined admin room');
    }
    
    // Listen for loan updates
    socket.on('loanUpdate', (data) => {
        debugLog(`Received loanUpdate: ${JSON.stringify(data)}`);
        
        // Refresh all relevant sections
        if (currentCustomerId === data.userId) {
            loadCustomerProfile(currentCustomerId);
        }
        
        showLoans('pending');
        showLoans('active');
        showPendingPayments();
        
        // Show notification
        showNotification(`Loan ${data.loanId} ${data.status} by ${data.adminName}`, 'info');
    });

    // Add new socket listeners
    socket.on('paymentUpdate', (data) => {
        debugLog(`Received paymentUpdate: ${JSON.stringify(data)}`);
        
        // Refresh all relevant sections
        if (currentCustomerId === data.userId) {
            loadCustomerProfile(currentCustomerId);
        }
        
        showPendingPayments();
        
        if (currentLoanId === data.loanId) {
            showLoanDetails(data.loanId);
        }
        
        // Show notification
        showNotification(`Payment ${data.status} for loan ${data.loanId}`, 'info');
    });
    
    socket.on('limitUpdate', (data) => {
        debugLog(`Received limitUpdate: ${JSON.stringify(data)}`);
        showNotification(`Loan limit updated for customer`, 'info');
        
        // Refresh customer view if we're looking at it
        if (currentCustomerId === data.customerId) {
            loadCustomerProfile(data.customerId);
        }
    });
    
    // Listen for loan approval events
    socket.on('loanApproved', (data) => {
        debugLog(`Received loanApproved event: ${JSON.stringify(data)}`);
        
        // Refresh customer profile if viewing the customer
        if (currentCustomerId === data.userId) {
            loadCustomerProfile(currentCustomerId);
            debugLog(`Refreshed customer profile for ${currentCustomerId}`);
        }
        
        // Refresh loan lists
        const currentStatus = document.getElementById('loans-section-title')?.textContent || '';
        if (currentStatus.includes('Pending') || currentStatus.includes('Active')) {
            showLoans('pending');
            debugLog('Refreshed loans list after approval');
        }
    });
    
    // Handle socket errors
    socket.on('connect_error', (error) => {
        debugLog(`Socket connection error: ${error.message}`);
        showNotification('Connection lost. Trying to reconnect...', 'error');
    });
    
    socket.on('reconnect', () => {
        debugLog('Socket reconnected');
        showNotification('Connection restored', 'success');
    });
    
    const loginButton = document.getElementById('login-button');
    if (loginButton) {
        loginButton.addEventListener('click', checkPassword);
        debugLog('Login button event listener added');
    }
});

// ==================== CHECK PASSWORD FUNCTION ====================
async function checkPassword() {
    const username = document.getElementById('username-input').value.trim();
    const password = document.getElementById('password-input').value.trim();
    
    if (!username || !password) {
        showError('Please enter both username and password');
        debugLog('Login attempt with missing credentials');
        return;
    }
    
    debugLog(`Login attempt with username: ${username}`);
    const success = await adminLogin(username, password);
    
    if (success) {
        debugLog('Login successful');
        // Join admin room after login
        socket.emit('joinAdminRoom');
        debugLog('Joined admin room');
    } else {
        debugLog('Login failed');
    }
}

// ==================== ADMIN LOGIN FUNCTION ====================
async function adminLogin(username, password) {
    try {
        showLoading('login');

        const response = await fetch(`${API_BASE_URL}/api/admin/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        debugLog(`Response Status: ${response.status}`);

        if (!response.headers.get('content-type')?.includes('application/json')) {
            const text = await response.text();
            debugLog(`Non-JSON response: ${text}`);
            showError('Invalid server response');
            return false;
        }

        const data = await response.json();
        debugLog(`Login response data: ${JSON.stringify(data)}`);

        if (response.ok && data.success) {
            localStorage.setItem("adminToken", data.token);
            localStorage.setItem("adminId", data.admin._id || data.admin.id);
            currentAdmin = data.admin;
            showAdminContent();
            return true;
        } else {
            showError(data.message || `Invalid credentials (status: ${response.status})`);
            return false;
        }
    } catch (error) {
        debugLog(`Login error: ${error.message}`);
        showError(`Network error: ${error.message}`);
        return false;
    } finally {
        hideLoading('login');
    }
}

// ==================== AUTHENTICATION FUNCTIONS ====================
async function checkAuthStatus() {
    const token = localStorage.getItem("adminToken");

    if (!token) {
        showLoginContent();
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/admin/validate-token`, {
            headers: { Authorization: `Bearer ${token}` }
        });

        if (response.ok) {
            const data = await response.json();
            if (data.success && data.admin) {
                currentAdmin = data.admin;
                localStorage.setItem("adminId", data.admin._id || data.admin.id);
                showAdminContent();
                loadAdminData();
                return;
            }
        }
        logout();
    } catch (error) {
        debugLog(`Auth check failed: ${error.message}`);
        logout();
    }
}

// ==================== DASHBOARD FUNCTIONS ====================
async function loadAdminData() {
    try {
        showLoading('dashboard');
        debugLog('Loading admin dashboard data...');
        
        // Optimized: Single API call for all dashboard data
        const response = await apiClient('/api/admin/metrics');
        const metrics = response.data;
        
        debugLog('Dashboard data loaded successfully');
        updateDashboardMetrics(metrics);
        document.getElementById('admin-username').textContent = `Logged in as: ${currentAdmin.username}`;
        
        // Update loan counts from metrics
        document.getElementById('pending-loans-count').textContent = `${metrics.pendingApplications || 0} pending`;
        document.getElementById('active-loans-count').textContent = `${metrics.activeLoans || 0} active`;
        document.getElementById('overdue-loans-count').textContent = `${metrics.overdueLoans || 0} overdue`;
        document.getElementById('completed-loans-count').textContent = `${metrics.completedLoans || 0} completed`;
        document.getElementById('pending-payments-count').textContent = `${metrics.pendingPaymentsCount || 0} pending`;
    } catch (error) {
        debugLog(`Failed to load dashboard data: ${error.message}`);
        showError('Failed to load dashboard data', 'dashboard');
    } finally {
        hideLoading('dashboard');
    }
}

function updateDashboardMetrics(metrics) {
    document.getElementById('total-customers').textContent = metrics?.totalCustomers || 0;
    document.getElementById('total-loans').textContent = `KES ${(metrics?.totalLoanAmount || 0).toLocaleString()}`;
    document.getElementById('total-pending').textContent = metrics?.pendingApplications || 0;
    document.getElementById('total-overdue').textContent = metrics?.overdueLoans || 0;
}

// ==================== CUSTOMER MANAGEMENT ====================
async function searchCustomer() {
    const query = document.getElementById('searchCustomer').value.trim();
    const customerDetails = document.getElementById('customerDetails');
    
    if (!query) {
        showError('Please enter search criteria', 'customer');
        return;
    }
    
    try {
        // Show loading state
        customerDetails.innerHTML = '<div class="spinner"></div>';
        debugLog(`Searching customers: ${query}`);
        
        const response = await apiClient(`/api/admin/customers?search=${encodeURIComponent(query)}`);
        
        // FIX: Access response.customers directly
        if (!response.success) {
            throw new Error(response.message || 'Search failed');
        }
        
        if (!response.customers || !Array.isArray(response.customers)) {
            throw new Error('Invalid response structure from server');
        }
        
        displayCustomerResults(response.customers);
    } catch (error) {
        debugLog(`Customer search failed: ${error.message}`);
        customerDetails.innerHTML = `<p class="error">Search failed: ${error.message}</p>`;
    }
}

// Enhanced customer display with limit controls
function displayCustomerResults(customers) {
    const container = document.getElementById('customerDetails');
    
    if (!customers.length) {
        container.innerHTML = '<p>No customers found.</p>';
        return;
    }
    
    container.innerHTML = customers.map(customer => {
        // Calculate available credit safely
        const maxLimit = customer.maxLoanLimit || 0;
        const currentBalance = customer.currentLoanBalance || 0;
        const availableCredit = Math.max(maxLimit - currentBalance, 0);
        
        return `
        <div class="customer-card">
            <div class="customer-header">
                <h4>${customer.fullName || 'Unknown'}</h4>
                <span class="customer-id">ID: ${customer.customerId || 'N/A'}</span>
            </div>
            
            <div class="customer-details">
                <div class="detail-row">
                    <span>Phone:</span>
                    <span>${customer.phoneNumber || 'N/A'}</span>
                </div>
                <div class="detail-row">
                    <span>Verification:</span>
                    <span class="status-${customer.verificationStatus}">
                        ${customer.verificationStatus.toUpperCase()}
                    </span>
                </div>
                <div class="detail-row">
                    <span>Current Limit:</span>
                    <span>KES ${maxLimit.toLocaleString()}</span>
                </div>
                <div class="detail-row">
                    <span>Current Balance:</span>
                    <span>KES ${currentBalance.toLocaleString()}</span>
                </div>
                <div class="detail-row">
                    <span>Available Credit:</span>
                    <span>KES ${availableCredit.toLocaleString()}</span>
                </div>
                
                <div class="limit-controls">
                    <label for="limit-${customer._id}">Set New Loan Limit:</label>
                    <div class="limit-input-group">
                        <input type="number" 
                            id="limit-${customer._id}" 
                            value="${maxLimit}"
                            min="0"
                            step="100">
                        <button class="action-btn" onclick="updateCustomerLimit('${customer._id}')">
                            UPDATE LIMIT
                        </button>
                    </div>
                    <div id="limit-message-${customer._id}" class="limit-message"></div>
                </div>
                
                <button class="luxury-btn" onclick="viewCustomerProfile('${customer._id}')" style="margin-top: 15px;">
                    View Full Profile
                </button>
            </div>
        </div>
        `;
    }).join('');
}

async function updateCustomerLimit(customerId, context = 'search') {
    let input, messageDiv;
    
    if (context === 'profile') {
        input = document.getElementById('customer-limit-input');
        messageDiv = document.getElementById('profile-limit-message');
    } else {
        input = document.getElementById(`limit-${customerId}`);
        messageDiv = document.getElementById(`limit-message-${customerId}`);
    }
    
    const newLimit = parseFloat(input.value);

    if (isNaN(newLimit) || newLimit < 0) {
        showError('Please enter a valid positive number', messageDiv);
        return;
    }

    try {
        debugLog(`Updating limit for customer ${customerId} to ${newLimit}`);
        const response = await apiClient(
            `/api/admin/customers/${customerId}/limit`,
            'PUT',
            { newLimit }
        );

        showSuccess('Limit updated successfully', messageDiv);
        input.value = response.newLimit;
        
        // Refresh profile view if we're in profile context
        if (context === 'profile') {
            loadCustomerProfile(customerId);
        }
        
        // Emit socket event for limit update
        socket.emit('limitUpdated', {
            userId: customerId,
            newLimit: newLimit
        });
    } catch (error) {
        debugLog(`Limit update error: ${error.message}`);
        showError(error.message, messageDiv);
    }
}

function viewCustomerProfile(customerId) {
    // Show profile section and hide other sections
    document.getElementById('admin-grid').classList.add('hidden');
    document.getElementById('loans-section').classList.add('hidden');
    document.getElementById('pending-payments-section').classList.add('hidden');
    
    const profileSection = document.getElementById('customer-profile-section');
    profileSection.classList.remove('hidden');
    
    // Track current customer
    currentCustomerId = customerId;
    profileSection.dataset.customerId = customerId;
    
    // Show loading state
    profileSection.innerHTML = '<div class="spinner"></div>';
    
    // Fetch and display customer profile
    loadCustomerProfile(customerId);
}

async function loadCustomerProfile(customerId) {
    try {
        // Update current customer
        currentCustomerId = customerId;
        
        const response = await apiClient(`/api/admin/customers/${customerId}`);
        
        if (!response.data || !response.data.customer) {
            throw new Error('Invalid customer data received');
        }
        
        renderCustomerProfile(response.data.customer);
    } catch (error) {
        console.error('Profile load error:', error);
        const profileSection = document.getElementById('customer-profile-section');
        profileSection.innerHTML = `<p class="error">Error: ${error.message}</p>`;
    }
}

function renderCustomerProfile(customer) {
    const profileSection = document.getElementById('customer-profile-section');
    
    // Safely handle currentLoanBalance (default to 0 if undefined)
    const currentBalance = customer.currentLoanBalance || 0;
    const availableCredit = customer.maxLoanLimit - currentBalance;
    
    profileSection.innerHTML = `
    <div class="profile-header">
        <button class="back-btn" onclick="backToDashboard()">
            <i class="fas fa-arrow-left"></i> Back
        </button>
        <h3>Customer Profile: ${customer.fullName}</h3>
    </div>
    
    <div class="customer-profile-grid">
        <div class="profile-section">
            <h4>Personal Information</h4>
            <div class="profile-field">
                <strong>Customer ID:</strong> ${customer.customerId}
            </div>
            <div class="profile-field">
                <strong>Full Name:</strong> ${customer.fullName}
            </div>
            <div class="profile-field">
                <strong>Phone:</strong> ${customer.phoneNumber}
            </div>
            <div class="profile-field">
                <strong>Email:</strong> ${customer.email || 'N/A'}
            </div>
            <div class="profile-field">
                <strong>Joined:</strong> ${new Date(customer.createdAt).toLocaleDateString()}
            </div>
            <div class="profile-field">
                <strong>Last Login:</strong> ${customer.lastLogin ? new Date(customer.lastLogin).toLocaleString() : 'Never'}
            </div>
        </div>
        
        <div class="profile-section">
            <h4>Loan Information</h4>
            <div class="profile-field">
                <strong>Credit Score:</strong> ${customer.creditScore}
            </div>
            <div class="profile-field">
                <strong>Loan Limit:</strong> KES ${customer.maxLoanLimit.toLocaleString()}
            </div>
            <div class="profile-field">
                <strong>Current Balance:</strong> KES ${currentBalance.toLocaleString()}
            </div>
            <div class="profile-field">
                <strong>Available Credit:</strong> KES ${availableCredit.toLocaleString()}
            </div>
            <div class="profile-field">
                <strong>Verification Status:</strong> 
                <span class="status-${customer.verificationStatus}">
                    ${customer.verificationStatus.toUpperCase()}
                </span>
            </div>
            
            <div class="limit-controls" style="margin-top: 20px;">
                <label for="customer-limit-input">Update Loan Limit:</label>
                <div class="limit-input-group">
                    <input type="number" 
                        id="customer-limit-input" 
                        value="${customer.maxLoanLimit}"
                        min="0"
                        step="100">
                    <button class="action-btn" onclick="updateCustomerLimit('${customer._id}', 'profile')">
                        UPDATE LIMIT
                    </button>
                </div>
                <div id="profile-limit-message" class="limit-message"></div>
            </div>
        </div>
        
        <div class="profile-section">
            <h4>Payment Preferences</h4>
            <div class="profile-field">
                <strong>Payment Mode:</strong> ${customer.paymentPreferences?.mode || 'Not set'}
            </div>
            <div class="profile-field">
                <strong>Paybill Number:</strong> ${customer.paymentPreferences?.paybill || 'Not set'}
            </div>
            <div class="profile-field">
                <strong>Account Number:</strong> ${customer.paymentPreferences?.account || 'Not set'}
            </div>
        </div>
        
        <div class="profile-section" style="grid-column: 1 / -1;">
            <h4>Loan History</h4>
            <div id="customer-loans-container">
                <div class="spinner"></div>
            </div>
        </div>
    </div>`;
    
    // Load customer's loan history
    loadCustomerLoans(customer._id);
}

async function loadCustomerLoans(customerId) {
    try {
        const response = await apiClient(`/api/admin/customers/${customerId}/loans`);
        
        if (!response.data || !response.data.loans) {
            throw new Error('Invalid loan data received');
        }
        
        renderCustomerLoans(response.data.loans);
    } catch (error) {
        console.error('Loan history error:', error);
        const container = document.getElementById('customer-loans-container');
        container.innerHTML = `<p class="error">Error loading loan history: ${error.message}</p>`;
    }
}

function renderCustomerLoans(loans) {
    const container = document.getElementById('customer-loans-container');
    
    if (!loans.length) {
        container.innerHTML = '<p>No loan history found.</p>';
        return;
    }
    
    container.innerHTML = `
    <table class="loan-table">
        <thead>
            <tr>
                <th>Loan ID</th>
                <th>Amount</th>
                <th>Status</th>
                <th>Date</th>
                <th>Due Date</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            ${loans.map(loan => `
            <tr>
                <td>${loan.loanId?.substring(0, 8) || loan._id.substring(0,8)}</td>
                <td>KES ${loan.amount?.toLocaleString() || '0'}</td>
                <td class="status-${loan.status.toLowerCase()}">${loan.status}</td>
                <td>${new Date(loan.createdAt).toLocaleDateString()}</td>
                <td>${loan.dueDate ? new Date(loan.dueDate).toLocaleDateString() : 'N/A'}</td>
                <td>
                    <button class="action-btn" onclick="viewLoanDetails('${loan._id}')">
                        View
                    </button>
                    ${loan.status === 'completed' ? `
                      <button class="action-btn" onclick="downloadLoanDocuments('${loan._id}')">
                        Documents
                      </button>
                    ` : ''}
                </td>
            </tr>
            `).join('')}
        </tbody>
    </table>`;
}

function backToDashboard() {
    // Hide all sections
    document.getElementById('loans-section').classList.add('hidden');
    document.getElementById('pending-payments-section').classList.add('hidden');
    document.getElementById('customer-profile-section').classList.add('hidden');
    
    // Clear current customer
    currentCustomerId = null;
    
    // Show main dashboard
    document.getElementById('admin-grid').classList.remove('hidden');
}

// ==================== BULK LIMIT UPDATE ====================
async function processBulkLimits() {
    const fileInput = document.getElementById('bulkLimitFile');
    const resultDiv = document.getElementById('bulkUpdateResult');
    
    if (!fileInput.files.length) {
        showError('Please select a CSV file', resultDiv);
        return;
    }

    try {
        showLoading(resultDiv);
        debugLog('Processing bulk limits...');
        const file = fileInput.files[0];
        const csvData = await readCSVFile(file);
        
        if (!csvData.length) {
            throw new Error('CSV file is empty or invalid');
        }

        const response = await apiClient(
            '/api/admin/customers/bulk-limit',
            'PUT',
            { updates: csvData }
        );

        if (response.success) {
            showSuccess(`Successfully updated ${response.data.updatedCount} customer limits`, resultDiv);
            
            // Notify users of limit updates
            if (response.data.updatedCount > 0) {
                response.data.updatedCustomers.forEach(customer => {
                    socket.emit('limitUpdated', {
                        userId: customer._id,
                        newLimit: customer.maxLoanLimit
                    });
                });
                debugLog(`Emitted limitUpdated for ${response.data.updatedCount} customers`);
            }
        } else {
            showError('Bulk update failed: ' + (response.error || 'Unknown error'), resultDiv);
        }
    } catch (error) {
        debugLog(`Bulk update failed: ${error.message}`);
        showError('Bulk update failed: ' + error.message, resultDiv);
    }
}

function readCSVFile(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        
        reader.onload = (event) => {
            try {
                const content = event.target.result;
                const lines = content.split('\n').filter(line => line.trim() !== '');
                
                if (lines.length < 2) {
                    reject(new Error('CSV must contain at least one data row'));
                    return;
                }
                
                const headers = lines[0].split(',').map(h => h.trim().toLowerCase());
                const data = [];
                
                for (let i = 1; i < lines.length; i++) {
                    const values = lines[i].split(',');
                    if (values.length !== headers.length) continue;
                    
                    const entry = {};
                    for (let j = 0; j < headers.length; j++) {
                        entry[headers[j]] = values[j].trim();
                    }
                    data.push(entry);
                }
                
                resolve(data);
            } catch (error) {
                reject(error);
            }
        };
        
        reader.onerror = () => {
            reject(new Error('Error reading file'));
        };
        
        reader.readAsText(file);
    });
}

// ==================== LOAN MANAGEMENT ====================
async function showLoans(status, page = 1) {
    try {
        showLoading('loans');
        debugLog(`Loading ${status} loans, page ${page}`);
        
        let queryParams = `status=${status}&page=${page}&limit=20`;
        
        // Special handling for active loans to ensure they're not filtered prematurely
        if (status === 'active') {
            queryParams += '&activeOnly=true';
        }
        
        const response = await apiClient(
            `/api/admin/loan-applications?${queryParams}`
        );
        
        // For active loans, display in card layout
        if (status === 'active') {
            displayActiveLoans(response.applications || []);
        } else {
            displayLoans(response.applications || [], status, response.totalPages, page);
        }
    } catch (error) {
        debugLog(`Failed to load ${status} loans: ${error.message}`);
        
        // Show error in UI
        const gridContainer = document.getElementById('loans-grid-container');
        const tableContainer = document.getElementById('loans-table-container');
        
        if (gridContainer) {
            gridContainer.innerHTML = `<p class="error">Error loading loans: ${error.message}</p>`;
        }
        
        if (tableContainer) {
            tableContainer.innerHTML = `<p class="error">Error loading loans: ${error.message}</p>`;
        }
        
        showError(`Failed to load ${status} loans: ${error.message}`, 'loans');
    } finally {
        hideLoading('loans');
    }
}

// Display active loans in card layout
function displayActiveLoans(loans) {
    // Hide table container, show grid container
    document.getElementById('loans-table-container').style.display = 'none';
    const gridContainer = document.getElementById('loans-grid-container');
    const grid = document.getElementById('loans-grid');
    
    if (!gridContainer || !grid) {
        debugLog('Error: Loans grid elements not found');
        return;
    }
    
    gridContainer.style.display = 'block';
    document.getElementById('loans-section-title').textContent = 'Active Loans';
    
    if (!loans.length) {
        grid.innerHTML = '<p>No active loans found</p>';
        return;
    }
    
    grid.innerHTML = loans.map(loan => createLoanCard(loan)).join('');
    
    document.getElementById('admin-grid').classList.add('hidden');
    document.getElementById('loans-section').classList.remove('hidden');
}

function createLoanCard(loan) {
    const dueDate = new Date(loan.dueDate);
    const now = new Date();
    const daysLeft = Math.ceil((dueDate - now) / (1000 * 60 * 60 * 24));
    
    // Calculate balance
    const balance = (loan.totalAmount || 0) - (loan.amountPaid || 0);
    
    return `
        <div class="loan-card">
            <div class="loan-header">
                <h4>${loan.fullName || 'Unknown'}</h4>
                <span class="loan-id">#${loan.loanId?.substring(0, 8) || loan._id.substring(0,8)}</span>
            </div>
            <div class="loan-details">
                <div class="detail">
                    <span>Principal:</span>
                    <span>KES ${loan.principal?.toLocaleString() || loan.amount?.toLocaleString() || '0'}</span>
                </div>
                <div class="detail">
                    <span>Total Due:</span>
                    <span>KES ${loan.totalAmount?.toLocaleString() || '0'}</span>
                </div>
                <div class="detail">
                    <span>Paid:</span>
                    <span>KES ${loan.amountPaid?.toLocaleString() || '0'}</span>
                </div>
                <div class="detail">
                    <span>Balance:</span>
                    <span>KES ${balance.toLocaleString()}</span>
                </div>
                <div class="detail">
                    <span>Days Left:</span>
                    <span class="days-remaining ${daysLeft < 7 ? 'text-warning' : ''}">
                        ${daysLeft}
                    </span>
                </div>
            </div>
            <button class="action-btn" onclick="showLoanDetails('${loan._id}')">
                View Details
            </button>
        </div>
    `;
}

// Display other loan statuses in table
function displayLoans(loans, status, totalPages = 1, currentPage = 1) {
    // Hide grid container, show table container
    document.getElementById('loans-grid-container').style.display = 'none';
    const tableContainer = document.getElementById('loans-table-container');
    const tableBody = document.getElementById('loans-table-body');
    
    if (!tableContainer || !tableBody) {
        debugLog('Error: Loans table elements not found');
        return;
    }
    
    tableContainer.style.display = 'block';
    
    const titleMap = {
        pending: 'Pending Loan Applications',
        active: 'Active Loans',
        overdue: 'Overdue Loans',
        completed: 'Completed Loans'
    };
    
    document.getElementById('loans-section-title').textContent = titleMap[status] || 'Loan Applications';
    
    tableBody.innerHTML = loans.length ? loans.map(loan => `
        <tr>
            <td>${loan.fullName || 'Unknown'}</td>
            <td>KES ${loan.amount?.toLocaleString() || '0'}</td>
            <td class="status-${loan.status.toLowerCase()}">${loan.status?.toUpperCase()}</td>
            <td>${formatDate(loan.createdAt)}</td>
            <td class="${isOverdue(loan) ? 'status-overdue' : ''}">
                ${loan.dueDate ? formatDate(loan.dueDate) : 'N/A'}
            </td>
            <td>
                ${loan.status === 'pending' ? `
                    <button class="action-btn" onclick="showApprovalTerms('${loan._id}')">APPROVE</button>
                    <button class="action-btn" onclick="processLoan('${loan._id}', 'reject')">REJECT</button>
                ` : ''}
                <button class="action-btn" onclick="showLoanDetails('${loan._id}')">DETAILS</button>
                ${loan.status === 'completed' ? `
                    <button class="action-btn" onclick="downloadLoanDocuments('${loan._id}')">DOCUMENTS</button>
                ` : ''}
            </td>
        </tr>
    `).join('') : '<tr><td colspan="6">No loans found</td></tr>';
    
    // Add pagination controls
    if (totalPages > 1) {
        const pagination = document.createElement('div');
        pagination.className = 'pagination';
        pagination.style.marginTop = '20px';
        
        for (let i = 1; i <= totalPages; i++) {
            const pageBtn = document.createElement('button');
            pageBtn.textContent = i;
            pageBtn.className = i === currentPage ? 'active' : '';
            pageBtn.addEventListener('click', () => showLoans(status, i));
            pagination.appendChild(pageBtn);
        }
        
        // Remove existing pagination
        const existingPagination = tableContainer.querySelector('.pagination');
        if (existingPagination) existingPagination.remove();
        
        tableContainer.appendChild(pagination);
    }
    
    document.getElementById('admin-grid').classList.add('hidden');
    document.getElementById('loans-section').classList.remove('hidden');
}

function hideLoans() {
    document.getElementById('loans-section').classList.add('hidden');
    document.getElementById('admin-grid').classList.remove('hidden');
}

// ==================== UPDATED LOAN DETAILS ====================
async function showLoanDetails(loanId) {
  currentLoanId = loanId;
  const modal = document.getElementById('loanDetailsModal');
  
  try {
    showLoading('loanDetailsModal');
    const response = await apiClient(`/api/admin/loan-applications/${loanId}`);
    const loan = response.data || response.loan;
    
    // FIX: Properly handle repayment history
    const repaymentRows = (loan.repaymentSchedule || []).map(payment => `
      <tr>
        <td>${formatDate(payment.dueDate)}</td>
        <td>KES ${payment.amount?.toLocaleString() || '0'}</td>
        <td>KES ${payment.paidAmount?.toLocaleString() || '0'}</td>
        <td class="status-${payment.status}">${payment.status?.toUpperCase() || 'PENDING'}</td>
        <td>${payment.paidAt ? formatDate(payment.paidAt) : 'N/A'}</td>
      </tr>
    `).join('') || '<tr><td colspan="5">No repayment history</td></tr>';
    
    document.getElementById('loanDetailsContent').innerHTML = `
      <div class="loan-details-modal-content">
        <div class="loan-header">
          <h3>Loan Details</h3>
          <button class="close-modal" onclick="closeModal('loanDetailsModal')">
            <i class="fas fa-times"></i>
          </button>
        </div>
        
        <div class="loan-info-grid">
          <div class="loan-info-section">
            <h4>Basic Information</h4>
            <div class="info-field">
              <strong>Loan ID:</strong> ${loan.loanId?.substring(0, 8) || loan._id.substring(0,8)}
            </div>
            <div class="info-field">
              <strong>Customer:</strong> 
              <span class="customer-link" onclick="showCustomerProfile('${loan.userId?._id || ''}')">
                ${loan.fullName || 'Unknown'}
              </span>
            </div>
            <div class="info-field">
              <strong>Principal:</strong> KES ${loan.principal?.toLocaleString() || loan.amount?.toLocaleString() || '0'}
            </div>
            <div class="info-field">
              <strong>Total Amount:</strong> KES ${loan.totalAmount?.toLocaleString() || '0'}
            </div>
          </div>
          
          <div class="loan-info-section">
            <h4>Status & Dates</h4>
            <div class="info-field">
              <strong>Status:</strong> 
              <span class="status-${loan.status.toLowerCase()}">${loan.status.toUpperCase()}</span>
            </div>
            <div class="info-field">
              <strong>Created:</strong> ${formatDate(loan.createdAt)}
            </div>
            <div class="info-field">
              <strong>Due Date:</strong> ${loan.dueDate ? formatDate(loan.dueDate) : 'N/A'}
            </div>
            <div class="info-field">
              <strong>Completed:</strong> ${loan.completedAt ? formatDate(loan.completedAt) : 'N/A'}
            </div>
          </div>
        </div>
        
        <div class="payment-summary">
          <div class="summary-card">
            <h5>Amount Paid</h5>
            <p>KES ${loan.amountPaid?.toLocaleString() || '0'}</p>
          </div>
          <div class="summary-card">
            <h5>Balance</h5>
            <p>KES ${(loan.totalAmount - loan.amountPaid)?.toLocaleString() || '0'}</p>
          </div>
          <div class="summary-card">
            <h5>Days Remaining</h5>
            <p>${calculateDaysRemaining(loan.dueDate)}</p>
          </div>
        </div>
        
        <h4>Repayment Schedule</h4>
        <table class="repayment-table">
          <thead>
            <tr>
              <th>Due Date</th>
              <th>Scheduled Amount</th>
              <th>Paid Amount</th>
              <th>Status</th>
              <th>Paid At</th>
            </tr>
          </thead>
          <tbody>
            ${repaymentRows}
          </tbody>
        </table>
        
        ${loan.status === 'active' && loan.amountPaid < loan.totalAmount ? `
          <div class="force-payment-section" style="margin-top: 30px;">
            <h4>Force Payment</h4>
            <div class="form-group">
              <label for="force-payment-amount">Amount</label>
              <input type="number" id="force-payment-amount" 
                     min="1" max="${loan.totalAmount - loan.amountPaid}" 
                     step="100" value="${loan.totalAmount - loan.amountPaid}">
            </div>
            <button class="luxury-btn" id="force-payment-btn" 
                    style="background: var(--green);">
              RECORD PAYMENT
            </button>
          </div>
        ` : ''}
        
        ${loan.status === 'active' ? `
          <div class="loan-actions" style="margin-top: 20px;">
            <button class="action-btn danger" onclick="forceCompleteLoan('${loan._id}')">
              MARK AS COMPLETED
            </button>
          </div>
        ` : ''}
      </div>
    `;
    
    // Add event listener for force payment button
    const forcePaymentBtn = document.getElementById('force-payment-btn');
    if (forcePaymentBtn) {
      forcePaymentBtn.addEventListener('click', () => {
        const amount = parseFloat(document.getElementById('force-payment-amount').value);
        if (amount > 0) {
          recordManualPayment(loanId, amount);
        }
      });
    }
    
    modal.style.display = 'block';
  } catch (error) {
    debugLog(`Loan details error: ${error.message}`);
    showError('Failed to load loan details: ' + error.message);
  } finally {
    hideLoading('loanDetailsModal');
  }
}

function calculateDaysRemaining(dueDate) {
  if (!dueDate) return 'N/A';
  const due = new Date(dueDate);
  const now = new Date();
  const diff = due - now;
  return Math.ceil(diff / (1000 * 60 * 60 * 24));
}

// ==================== FORCE COMPLETE LOAN FUNCTION ====================
async function forceCompleteLoan(loanId) {
  try {
    debugLog(`Forcing completion of loan: ${loanId}`);
    const response = await apiClient(
      `/api/admin/loan-applications/${loanId}/force-complete`,
      'PATCH'
    );
    
    if (response.success) {
      showNotification('Loan marked as completed!', 'success');
      
      // Notify user
      if (response.data?.userId) {
        socket.emit('loanStatusUpdate', {
          userId: response.data.userId,
          loanId: loanId,
          newStatus: 'completed'
        });
        debugLog(`Emitted loanStatusUpdate to user ${response.data.userId}`);
      }
      
      // Refresh views
      showLoans('active');
      showPendingPayments();
      closeModal('loanDetailsModal');
    }
  } catch (error) {
    debugLog(`Failed to force complete loan: ${error.message}`);
    showError('Failed to mark loan as completed: ' + error.message);
  }
}

function showApprovalTerms(loanId) {
    currentLoanId = loanId;
    document.getElementById('approvalTermsModal').style.display = 'block';
    debugLog(`Showing approval terms for loan: ${loanId}`);
}

async function confirmLoanApproval() {
    const interestRate = parseFloat(document.getElementById('interestRate').value);
    const repaymentPeriod = parseInt(document.getElementById('repaymentPeriod').value);
    const adminNotes = document.getElementById('adminNotes').value;

    try {
        showLoading('approvalTermsModal');
        debugLog(`Approving loan ${currentLoanId} with terms: ${interestRate}%, ${repaymentPeriod} days`);
        
        const response = await apiClient(
            `/api/admin/loan-applications/${currentLoanId}/approve`,
            'PATCH',
            { interestRate, repaymentPeriod, adminNotes }
        );

        // Corrected loan amount calculations
        const principal = response.data.loan.amount;
        const interestAmount = principal * (interestRate / 100);
        const totalAmount = principal + interestAmount;
        
        showSuccess('Loan approved successfully!');
        closeModal('approvalTermsModal');
        showLoans('pending');
        
        // Emit socket event with corrected values
        socket.emit('loanApproved', {
            loanId: currentLoanId,
            adminName: currentAdmin.username,
            principal: principal,
            interestRate: interestRate,
            totalAmount: totalAmount,
            dueDate: response.data.loan.dueDate,
            userId: response.data.customer._id
        });
    } catch (error) {
        debugLog(`Loan approval failed: ${error.message}`);
        showError(error.message || 'Failed to approve loan. Please try again.', 'approvalTermsModal');
    } finally {
        hideLoading('approvalTermsModal');
    }
}

async function processLoan(loanId, action) {
    if (action === 'reject') {
        const reason = prompt('Rejection reason:');
        if (!reason) return;

        try {
            showLoading('loans');
            debugLog(`Rejecting loan ${loanId}: ${reason}`);
            await apiClient(`/api/admin/loan-applications/${loanId}/reject`, 'PATCH', { reason });
            
            // Notify all admins
            socket.emit('loanUpdate', {
                loanId,
                status: 'rejected',
                adminName: currentAdmin.username,
                timestamp: new Date().toISOString()
            });
            
            showSuccess('Loan rejected successfully');
            showLoans('pending');
        } catch (error) {
            debugLog(`Loan rejection failed: ${error.message}`);
            showError(error.message || 'Failed to reject loan');
        } finally {
            hideLoading('loans');
        }
    }
}

// ==================== PAYMENT MANAGEMENT ====================
async function showPendingPayments(page = 1) {
    try {
        showLoading('pending-payments');
        debugLog(`Loading pending payments, page ${page}`);
        const response = await apiClient(`/api/admin/pending-payments?page=${page}&limit=20`);
        displayPendingPayments(response.payments || [], response.totalPages, page);
    } catch (error) {
        debugLog(`Failed to load pending payments: ${error.message}`);
        showError(`Failed to load pending payments: ${error.message}`, 'pending-payments');
    } finally {
        hideLoading('pending-payments');
    }
}

function displayPendingPayments(payments, totalPages = 1, currentPage = 1) {
    const tableBody = document.getElementById('pending-payments-table-body');
    const title = `Pending Payments (${payments.length})`;
    
    document.getElementById('pending-payments-section-title').textContent = title;
    
    tableBody.innerHTML = payments.length ? payments.map(payment => `
        <tr>
            <td>
                <div class="customer-link" onclick="viewCustomerProfile('${payment.userId._id}')">
                    <i class="fas fa-user"></i> ${payment.userId.fullName || 'Unknown'}
                </div>
            </td>
            <td>KES ${payment.amount?.toLocaleString() || '0'}</td>
            <td>${payment.reference}</td>
            <td>${formatDate(payment.createdAt)}</td>
            <td>
                <button class="action-btn" onclick="approvePayment('${payment._id}')">APPROVE</button>
                <button class="action-btn" onclick="rejectPayment('${payment._id}')">REJECT</button>
            </td>
        </tr>
    `).join('') : '<tr><td colspan="5">No pending payments</tr>';
    
    // Add pagination controls
    if (totalPages > 1) {
        const pagination = document.createElement('div');
        pagination.className = 'pagination';
        pagination.style.marginTop = '20px';
        
        for (let i = 1; i <= totalPages; i++) {
            const pageBtn = document.createElement('button');
            pageBtn.textContent = i;
            pageBtn.className = i === currentPage ? 'active' : '';
            pageBtn.addEventListener('click', () => showPendingPayments(i));
            pagination.appendChild(pageBtn);
        }
        
        // Remove existing pagination
        const existingPagination = tableBody.parentNode.querySelector('.pagination');
        if (existingPagination) existingPagination.remove();
        
        tableBody.parentNode.appendChild(pagination);
    }
    
    document.getElementById('admin-grid').classList.add('hidden');
    document.getElementById('pending-payments-section').classList.remove('hidden');
}

async function approvePayment(paymentId) {
    try {
        const response = await apiClient(
            `/api/admin/payments/${paymentId}/approve`,
            'PATCH'
        );
        
        if (response.success) {
            showNotification(`Payment approved for ${response.customerName}!`, 'success');
            
            // Emit socket event
            socket.emit('paymentApproved', {
                paymentId,
                adminName: currentAdmin.username,
                userId: response.data.userId,
                loanId: response.data.loanId,
                amount: response.data.amount,
                newBalance: response.data.customer.newBalance
            });
            
            // Refresh pending payments list
            showPendingPayments();
            
            // Update dashboard metrics
            loadAdminData();
            
            // If we're viewing the customer's profile, refresh it
            if (currentCustomerId === response.data.userId) {
                loadCustomerProfile(response.data.userId);
            }
            
            // If we're viewing the loan details, refresh them
            if (currentLoanId === response.data.loanId) {
                showLoanDetails(response.data.loanId);
            }
        }
    } catch (error) {
        showError(`Failed to approve payment: ${error.message}`);
    }
}

async function rejectPayment(paymentId) {
    const reason = prompt('Reason for rejection:');
    if (!reason) return;

    try {
        const response = await apiClient(`/api/admin/payments/${paymentId}/reject`, 'PATCH', { reason });
        if (response.success) {
            showNotification('Payment rejected!', 'success');
            
            // Emit socket event
            socket.emit('paymentRejected', {
                paymentId,
                adminName: currentAdmin.username
            });
            
            // Refresh pending payments list
            showPendingPayments();
            // Update dashboard metrics
            loadAdminData();
        }
    } catch (error) {
        showError(`Failed to reject payment: ${error.message}`);
    }
}

function hidePendingPayments() {
    document.getElementById('pending-payments-section').classList.add('hidden');
    document.getElementById('admin-grid').classList.remove('hidden');
}

// ==================== REPORTING ====================
async function generateReport() {
    const reportType = document.getElementById('reportType').value;
    const startDate = document.getElementById('startDate').value;
    const endDate = document.getElementById('endDate').value;
    
    if (!reportType) {
        showError('Please select a report type', 'reportModal');
        return;
    }
    
    let warningElement = null;
    const timeoutId = setTimeout(() => {
        warningElement = showLongOperationWarning();
    }, 10000);

    try {
        showLoading('reportModal');
        debugLog(`Generating report: ${reportType}`);
        let endpoint = `/api/admin/reports/${reportType}`;
        
        // Proper date formatting
        if (reportType === 'custom' && startDate && endDate) {
            const formattedStart = new Date(startDate).toISOString().split('T')[0];
            const formattedEnd = new Date(endDate).toISOString().split('T')[0];
            endpoint += `?start=${formattedStart}&end=${formattedEnd}`;
        }
        
        const response = await apiClient(endpoint);
        displayReport(response.data);
    } catch (error) {
        debugLog(`Report generation failed: ${error.message}`);
        showError('Failed to generate report: ' + error.message, 'reportModal');
    } finally {
        clearTimeout(timeoutId);
        if (warningElement) {
            warningElement.remove();
        }
        hideLoading('reportModal');
    }
}

function displayReport(reportData) {
    const reportContent = document.getElementById('reportContent');
    reportContent.innerHTML = `
        <div class="report-summary">
            <h4>${reportData.title || 'Loan Activity Report'}</h4>
            ${reportData.startDate ? `<p>Period: ${reportData.startDate} to ${reportData.endDate}</p>` : ''}
            <p>Generated: ${new Date().toLocaleDateString()}</p>
            
            ${reportData.totalLoans ? `<p>Total Loans: KES ${reportData.totalLoans.toLocaleString()}</p>` : ''}
            ${reportData.newCustomers ? `<p>New Customers: ${reportData.newCustomers}</p>` : ''}
            ${reportData.repaymentsReceived ? `<p>Repayments Received: KES ${reportData.repaymentsReceived.toLocaleString()}</p>` : ''}
            ${reportData.defaultRate ? `<p>Default Rate: ${reportData.defaultRate}%</p>` : ''}
        </div>
        
        ${reportData.dailyActivity?.length > 0 ? `
          <h4>Loan Activity</h4>
          <table class="loan-table">
              <thead>
                  <tr>
                      <th>Date</th>
                      <th>New Loans</th>
                      <th>Repayments</th>
                      <th>Defaults</th>
                  </tr>
              </thead>
              <tbody>
                  ${reportData.dailyActivity.map(day => `
                      <tr>
                          <td>${day.date}</td>
                          <td>${day.newLoans || '0'}</td>
                          <td>KES ${day.repayments?.toLocaleString() || '0'}</td>
                          <td>${day.defaults || '0'}</td>
                      </tr>
                  `).join('')}
              </tbody>
          </table>
        ` : '<p>No activity data available</p>'}
        
        <div class="report-actions">
            <button class="luxury-btn" onclick="exportReport()">
                <i class="fas fa-download"></i> Export to CSV
            </button>
        </div>
    `;
    
    document.getElementById('reportModal').style.display = 'block';
}

function exportReport() {
    alert('Report exported successfully! This would download a CSV file in a real implementation.');
}

// ==================== UTILITY FUNCTIONS ====================
async function apiClient(endpoint, method = 'GET', body = null) {
    const token = localStorage.getItem("adminToken");
    if (!token) {
        debugLog('No token found - logging out');
        logout();
        throw new Error('Authentication required');
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000); // 15s timeout

    try {
        debugLog(`API request: ${method} ${endpoint}`);
        const response = await fetch(`${API_BASE_URL}${endpoint}`, {
            method,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: body ? JSON.stringify(body) : null,
            signal: controller.signal
        });

        clearTimeout(timeoutId);
        
        // Handle 204 No Content responses
        if (response.status === 204) {
            return { success: true };
        }
        
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const text = await response.text();
            debugLog(`Non-JSON response: ${text}`);
            throw new Error('Invalid server response');
        }

        const data = await response.json();
        debugLog(`API response: ${response.status} ${JSON.stringify(data)}`);
        
        if (!response.ok) {
            if (response.status === 401) {
                debugLog('Token expired - logging out');
                logout();
                throw new Error('Session expired. Please login again.');
            }
            throw new Error(data.message || `Request failed with status ${response.status}`);
        }
        
        return data;
    } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            debugLog(`API timeout: ${endpoint}`);
            throw new Error('Request timed out');
        }
        debugLog(`API error: ${error.message}`);
        throw error;
    }
}

function showLoading(context) {
    const element = document.getElementById(context);
    if (element) {
        element.innerHTML = '<div class="spinner"></div>';
        element.classList.remove('hidden');
        
        // Add timeout warning after 8 seconds
        setTimeout(() => {
            if (element.querySelector('.spinner')) {
                const warning = document.createElement('div');
                warning.className = 'loading-warning';
                warning.textContent = 'Loading is taking longer than expected...';
                warning.style.color = '#FFA500';
                warning.style.marginTop = '10px';
                element.appendChild(warning);
            }
        }, 8000);
    }
}

function hideLoading(context) {
    const element = document.getElementById(context);
    if (element) {
        element.innerHTML = '';
        // Remove any existing warnings
        const warning = element.querySelector('.loading-warning');
        if (warning) warning.remove();
    }
}

function showError(message, element) {
    if (element instanceof HTMLElement) {
        element.innerHTML = `<span style="color: var(--red)">${message}</span>`;
    } else {
        const container = document.getElementById(element || 'error-message');
        if (container) {
            container.textContent = message;
            container.style.display = 'block';
        }
    }
    debugLog(`Error shown: ${message}`);
}

function showSuccess(message, element) {
    if (element instanceof HTMLElement) {
        element.innerHTML = `<span style="color: var(--green)">✓ ${message}</span>`;
        setTimeout(() => element.innerHTML = '', 3000);
    } else {
        const container = document.getElementById(element || 'success-message');
        if (container) {
            container.textContent = message;
            container.style.display = 'block';
            setTimeout(() => container.style.display = 'none', 3000);
        }
    }
    debugLog(`Success shown: ${message}`);
}

function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
            <span>${message}</span>
        </div>
    `;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.opacity = '0';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
    debugLog(`Notification shown: ${message}`);
}

function isOverdue(loan) {
    return loan.status === 'active' && new Date(loan.dueDate) < new Date();
}

function showLongOperationWarning() {
    const warning = document.createElement('div');
    warning.className = 'operation-warning';
    warning.innerHTML = `
        <div class="warning-content">
            <p>⏳ This operation may take several seconds...</p>
            <div class="spinner"></div>
        </div>
    `;
    document.body.appendChild(warning);
    return warning;
}

// ==================== EVENT HANDLERS ====================
function setupEventListeners() {
    debugLog('Setting up event listeners');
    
    // Authentication
    document.getElementById("username-input")?.addEventListener("keypress", e => {
        if (e.key === 'Enter') checkPassword();
    });
    
    document.getElementById("password-input")?.addEventListener("keypress", e => {
        if (e.key === 'Enter') checkPassword();
    });

    // Customer management
    document.getElementById("searchCustomer")?.addEventListener("keypress", e => {
        if (e.key === 'Enter') searchCustomer();
    });

    // Reporting
    document.getElementById("reportType")?.addEventListener("change", () => {
        const customDateRange = document.getElementById("customDateRange");
        if (customDateRange) {
            customDateRange.style.display = 
                document.getElementById("reportType").value === 'custom' ? 'block' : 'none';
        }
    });

    // Bulk operations
    document.getElementById("bulkLimitFile")?.addEventListener("change", function() {
        const bulkUpdateResult = document.getElementById("bulkUpdateResult");
        if (bulkUpdateResult) {
            bulkUpdateResult.textContent = "";
        }
    });
    
    // Modals
    document.querySelectorAll('.close-modal').forEach(btn => {
        btn.addEventListener('click', () => {
            const modal = btn.closest('.modal');
            if (modal) {
                modal.style.display = 'none';
            }
        });
    });
    
    // Loan approval modal
    document.getElementById("approvalTermsModal")?.addEventListener("click", function(e) {
        if (e.target === this) closeModal('approvalTermsModal');
    });
    
    // Report modal
    document.getElementById("reportModal")?.addEventListener("click", function(e) {
        if (e.target === this) closeModal('reportModal');
    });
    
    // Loan details modal
    document.getElementById("loanDetailsModal")?.addEventListener("click", function(e) {
        if (e.target === this) closeModal('loanDetailsModal');
    });
    
    // Report generation button
    document.getElementById("generateReportBtn")?.addEventListener("click", generateReport);
    
    // Loan navigation buttons
    document.querySelectorAll('.admin-card .luxury-btn[data-loan-type]').forEach(btn => {
        btn.addEventListener('click', () => {
            const loanType = btn.getAttribute('data-loan-type');
            showLoans(loanType);
        });
    });
    
    // Pending payments button
    document.getElementById('pending-payments-btn')?.addEventListener('click', () => {
        showPendingPayments();
    });
    
    // Back buttons
    document.getElementById('hide-loans-btn')?.addEventListener('click', hideLoans);
    document.getElementById('hide-payments-btn')?.addEventListener('click', hidePendingPayments);
    
    // Logout button
    document.getElementById('logout-btn')?.addEventListener('click', logout);
    
    // Debug toggle
    document.getElementById('debug-toggle-btn')?.addEventListener('click', enableDebugConsole);
    
    // Bulk process button
    document.getElementById('process-bulk-btn')?.addEventListener('click', processBulkLimits);
    
    // Loan approval
    document.getElementById('confirm-approval-btn')?.addEventListener('click', confirmLoanApproval);
    
    // Refresh button
    document.getElementById('refresh-admin-btn')?.addEventListener('click', refreshAdminPortal);
}

// ==================== UI STATE MANAGEMENT ====================
function showLoginContent() {
    const loginContainer = document.getElementById("login-container");
    const adminContent = document.getElementById("admin-content");
    
    if (loginContainer) loginContainer.classList.remove("hidden");
    if (adminContent) adminContent.classList.add("hidden");
    debugLog('Showing login content');
}

function showAdminContent() {
    debugLog('Showing admin content');
    
    const loginContainer = document.getElementById("login-container");
    const adminContent = document.getElementById("admin-content");
    
    if (loginContainer) {
        loginContainer.classList.add("hidden");
        debugLog('Hid login container');
    } else {
        debugLog('Login container not found');
    }
    
    if (adminContent) {
        adminContent.classList.remove("hidden");
        debugLog('Showed admin content');
        loadAdminData();
    } else {
        debugLog('Admin content container not found');
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.style.display = 'none';
    debugLog(`Closed modal: ${modalId}`);
}

function logout() {
    debugLog('Logging out...');
    localStorage.removeItem("adminToken");
    localStorage.removeItem("adminId");
    currentAdmin = null;
    currentCustomerId = null;
    
    // Cleanup socket listeners and disconnect
    if (socket) {
        socket.off('loanUpdate');
        socket.off('paymentUpdate');
        socket.off('limitUpdate');
        socket.off('loanApproved');
        socket.off('connect_error');
        socket.off('reconnect');
        socket.disconnect();
        debugLog('Socket disconnected and listeners removed');
    }
    
    showLoginContent();
}

function enableDebugConsole() {
    const consoleDiv = document.getElementById('debug-console');
    if (consoleDiv) {
        consoleDiv.style.display = consoleDiv.style.display === 'block' ? 'none' : 'block';
        consoleDiv.scrollTop = consoleDiv.scrollHeight;
        debugLog('Debug console toggled');
    }
}

// ==================== UPDATED REFRESH FUNCTION ====================
async function refreshAdminPortal() {
  // Get refresh button reference FIRST (outside try/catch)
  const refreshBtn = document.getElementById('refresh-admin-btn');
  
  // Store original text BEFORE try block
  const originalText = refreshBtn.innerHTML;
  
  // Initialize timeout handler
  let timeout;
  
  try {
    debugLog('Refreshing admin portal...');
    showNotification('Refreshing data...', 'info');
    
    // Disable and show spinner
    refreshBtn.innerHTML = '<i class="fas fa-sync fa-spin"></i> Refreshing...';
    refreshBtn.disabled = true;
    
    // Set timeout for slow operation warning
    timeout = setTimeout(() => {
      if (refreshBtn.innerHTML.includes('fa-spin')) {
        showNotification('Refresh is taking longer than expected...', 'warning');
        debugLog('Refresh operation taking longer than 5 seconds');
      }
    }, 5000);
    
    // Refresh dashboard metrics
    await loadAdminData();
    
    // Refresh current view without changing UI state
    const currentView = getCurrentView();
    
    switch(currentView) {
      case 'loans':
        const loanStatus = document.getElementById('loans-section-title').textContent.toLowerCase();
        if (loanStatus.includes('pending')) await showLoans('pending');
        else if (loanStatus.includes('active')) await showLoans('active');
        else if (loanStatus.includes('overdue')) await showLoans('overdue');
        else if (loanStatus.includes('completed')) await showLoans('completed');
        break;
        
      case 'payments':
        await showPendingPayments();
        break;
        
      case 'customer':
        const query = document.getElementById('searchCustomer').value;
        if (query) await searchCustomer();
        break;
        
      case 'customer-profile':
        const customerId = document.getElementById('customer-profile-section')?.dataset?.customerId;
        if (customerId) await loadCustomerProfile(customerId);
        break;
    }
    
    showNotification('Portal data refreshed', 'success');
  } catch (error) {
    debugLog(`Refresh failed: ${error.message}`);
    console.error('CRITICAL REFRESH ERROR:', error);
    showNotification('Critical error during refresh!', 'error');
  } finally {
    // Always clear timeout and restore button state
    clearTimeout(timeout);
    
    if (refreshBtn) {
      refreshBtn.innerHTML = originalText;
      refreshBtn.disabled = false;
    }
  }
}

// ==================== DOCUMENT DOWNLOAD ====================
function downloadLoanDocuments(loanId) {
  // Placeholder implementation - would call backend in real app
  debugLog(`Downloading documents for loan: ${loanId}`);
  showNotification('Preparing documents for download...', 'info');
  
  // Simulate delay
  setTimeout(() => {
    showNotification('Documents ready for download!', 'success');
    // In real implementation: window.location = `/api/loans/${loanId}/documents`;
  }, 2000);
}

// ==================== MANUAL PAYMENT RECORDING ====================
async function recordManualPayment(loanId, amount) {
  try {
    const reference = `MANUAL-${Date.now()}`;
    const response = await apiClient(
      `/api/admin/loans/${loanId}/record-payment`,
      'POST',
      { amount, reference }
    );

    if (response.success) {
      showNotification(`Manual payment of KES ${amount} recorded!`, 'success');
      showLoanDetails(loanId); // Refresh the view
      
      // Refresh related views
      showPendingPayments();
      if (currentCustomerId) loadCustomerProfile(currentCustomerId);
    }
  } catch (error) {
    showError(`Failed to record payment: ${error.message}`);
  }
}