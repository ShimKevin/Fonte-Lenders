// ==================== GLOBAL VARIABLES ====================
const API_BASE_URL = window.location.hostname === 'localhost'
  ? 'http://localhost:3000'
  : 'https://fonte-lenders.onrender.com';

// State management variable - NEWLY ADDED
let currentView = 'dashboard';

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
  reconnectionAttempts: 10, // Increased from 5
  reconnectionDelay: 1000,
  reconnectionDelayMax: 10000,
  randomizationFactor: 0.5, // Adds some randomness to reconnection delays
  timeout: 20000, // Increased connection timeout
  autoConnect: true,
  transports: ['websocket', 'polling'], // Fallback transport
  upgrade: true,
  rememberUpgrade: true,
  withCredentials: true
});

// Socket.IO connection handlers
socket.on('connect', () => {
  debugLog('Socket connected successfully');
  showNotification('Connected to real-time service', 'success');
  
  // Re-authenticate on reconnect
  const token = localStorage.getItem('adminToken');
  if (token) {
    socket.emit('authenticate', { token });
    debugLog('Sent authentication token after reconnect');
  }
  
  // Join admin room if authenticated
  if (currentAdmin) {
    socket.emit('joinAdminRoom');
    debugLog('Joined admin room');
  }
});

socket.on('connect_error', (err) => {
  debugLog(`Socket connection error: ${err.message}`);
  showNotification('Connection error. Attempting to reconnect...', 'warning');
  
  // Exponential backoff reconnection with jitter
  const baseDelay = Math.min(socket.reconnectionAttempts * 1000, 10000);
  const jitter = baseDelay * 0.2 * Math.random();
  const delay = Math.min(baseDelay + jitter, 15000);
  
  setTimeout(() => {
    if (socket.disconnected) {
      debugLog(`Attempting reconnection (attempt ${socket.reconnectionAttempts + 1}) after ${delay}ms`);
      socket.connect();
    }
  }, delay);
});

socket.on('disconnect', (reason) => {
  debugLog(`Socket disconnected: ${reason}`);
  
  if (reason === 'io server disconnect') {
    // Server-initiated disconnect (likely auth failure)
    showNotification('Server disconnected. Please refresh the page.', 'error');
  } else {
    // Network issues or voluntary disconnect
    showNotification('Connection lost. Reconnecting...', 'warning');
    
    // Auto-reconnect with increasing delay
    const delay = Math.min(socket.reconnectionAttempts * 1500, 15000);
    setTimeout(() => {
      if (socket.disconnected) {
        debugLog(`Attempting reconnect after ${delay}ms`);
        socket.connect();
      }
    }, delay);
  }
});

socket.on('reconnect_attempt', (attempt) => {
  debugLog(`Reconnection attempt ${attempt}`);
  // Switch transport method if needed
  if (attempt % 2 === 0) {
    socket.io.opts.transports = ['polling', 'websocket'];
  }
});

socket.on('reconnect_failed', () => {
  debugLog('Reconnection failed after maximum attempts');
  showNotification('Failed to establish connection. Please check your network and refresh the page.', 'error');
});

// Authentication handlers
socket.on('authenticated', () => {
  debugLog('Socket authentication successful');
});

socket.on('unauthorized', (err) => {
  debugLog(`Socket auth failed: ${err.message}`);
  showNotification('Session expired. Please login again.', 'error');
  logout();
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

// Add socket listener for overdue loan updates
socket.on('overdueUpdate', (data) => {
  debugLog(`Received overdueUpdate: ${JSON.stringify(data)}`);
  
  if (currentCustomerId === data.userId) {
    debugLog(`Overdue update for customer ${data.userId}`);
    loadCustomerProfile(currentCustomerId);
  }
  
  // Refresh loan views if needed
  if (currentLoanId === data.loanId) {
    showLoanDetails(data.loanId);
  }
  
  showNotification(`Overdue fees updated for loan ${data.loanId}`, 'warning');
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
    setupModalCloseHandlers();
    
    // Add admin to admin room if authenticated
    if (currentAdmin) {
        socket.emit('joinAdminRoom');
        debugLog('Joined admin room');
        loadAdminData();
    }
});

function setupModalCloseHandlers() {
  document.querySelectorAll('.close-modal').forEach(btn => {
    btn.addEventListener('click', function() {
      const modal = this.closest('.modal');
      if (modal) {
        modal.style.display = 'none';
      }
    });
  });
  
  // Close when clicking outside modal content
  document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', function(e) {
      if (e.target === this) {
        this.style.display = 'none';
      }
    });
  });
}

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
            localStorage.setItem("adminRefreshToken", data.refreshToken);
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

// ==================== IMPROVED BACK TO DASHBOARD FUNCTION ====================
function backToDashboard() {
    // Update state - NEWLY ADDED
    currentView = 'dashboard';
    
    // Hide all sections
    document.getElementById('loans-section')?.classList.add('hidden');
    document.getElementById('pending-payments-section')?.classList.add('hidden');
    document.getElementById('customer-profile-section')?.classList.add('hidden');
    
    // Show main dashboard
    document.getElementById('admin-grid')?.classList.remove('hidden');
    
    // Reset current views
    currentCustomerId = null;
    currentLoanId = null;
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
async function showLoans(status = 'pending', page = 1) {
    // Update state - NEWLY ADDED
    currentView = 'loans';
    
    try {
        showLoading('loans');
        debugLog(`Loading ${status} loans, page ${page}`);
        
        // Modified status handling to explicitly exclude rejected loans for active/defaulted view
        const statusParam = typeof status === 'string' ? 
            (status === 'active' ? 'active,defaulted' : status) : 
            'pending';
        
        // Add rejected=false parameter for active/defaulted loans
        const additionalParams = status === 'active' ? '&rejected=false' : '';
        
        const response = await apiClient(
            `/api/admin/loan-applications?status=${encodeURIComponent(statusParam)}${additionalParams}&page=${page}&limit=20`
        );
        
        // Filter out any rejected loans that might have slipped through (client-side safeguard)
        const filteredApplications = status === 'active' 
            ? (response.applications || []).filter(app => app.status !== 'rejected')
            : response.applications || [];
        
        if (status === 'active') {
            displayActiveLoans(filteredApplications);
        } else {
            displayLoans(filteredApplications, status, response.totalPages, page);
        }
    } catch (error) {
        debugLog(`Failed to load ${status} loans: ${error.message}`);
        
        // Enhanced error display with retry button
        const errorHtml = `
            <div class="error-container">
                <i class="fas fa-exclamation-triangle"></i>
                <div>
                    <p>Failed to load ${status} loans</p>
                    <p class="error-detail">${error.message}</p>
                    <button onclick="showLoans('${status}', ${page})" class="retry-btn">
                        <i class="fas fa-sync-alt"></i> Try Again
                    </button>
                </div>
            </div>
        `;
        
        const gridContainer = document.getElementById('loans-grid-container');
        const tableContainer = document.getElementById('loans-table-container');
        
        if (gridContainer) gridContainer.innerHTML = errorHtml;
        if (tableContainer) tableContainer.innerHTML = errorHtml;
        
        showNotification(`Failed to load ${status} loans`, 'error');
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
    if (!loan?.dueDate) return ''; // Null check
    
    // STANDARDIZED CALCULATION
    const daysRemaining = calculateDaysRemaining(loan.dueDate);
    const isOverdue = daysRemaining < 0;
    
    // Calculate balance
    const balance = (loan.totalAmount || 0) - (loan.amountPaid || 0);
    
    return `
        <div class="loan-card" data-loan-id="${loan._id}">
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
                    <span>Status:</span>
                    <span class="${isOverdue ? 'text-danger' : daysRemaining < 7 ? 'text-warning' : ''}">
                        ${isOverdue ? 
                            `${Math.abs(daysRemaining)} days overdue` : 
                            `${daysRemaining} day${daysRemaining !== 1 ? 's' : ''} remaining`}
                    </span>
                </div>
            </div>
            <button class="action-btn" onclick="showLoanDetails('${loan._id}')">
                View Details
            </button>
            ${isOverdue ? '<div class="overdue-badge">OVERDUE</div>' : ''}
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
    
    tableBody.innerHTML = loans.length ? loans.map(loan => {
        const isOverdue = loan.status === 'defaulted' && new Date(loan.dueDate) < new Date();
        const overdueInfo = isOverdue ? `
          <div class="overdue-details">
            <span>Days Overdue: ${loan.overdueDays || 0}</span>
            <span>Fees: KES ${loan.overdueFees?.toLocaleString() || '0'}</span>
            <span>Total Due: KES ${loan.totalAmount?.toLocaleString() || '0'}</span>
          </div>
        ` : '';
        
        return `
          <tr>
            <td>${loan.fullName || 'Unknown'}</td>
            <td>KES ${loan.amount?.toLocaleString() || '0'}</td>
            <td class="status-${loan.status.toLowerCase()}">
              ${loan.status?.toUpperCase()}
              ${isOverdue ? '<br><small>(OVERDUE)</small>' : ''}
            </td>
            <td>${formatDate(loan.createdAt)}</td>
            <td class="${isOverdue ? 'status-overdue' : ''}">
              ${loan.dueDate ? formatDate(loan.dueDate) : 'N/A'}
            </td>
            <td>
              ${overdueInfo}
              ${loan.status === 'pending' ? `
                <button class="action-btn" onclick="showApprovalTerms('${loan._id}')">APPROVE</button>
                <button class="action-btn" onclick="processLoan('${loan._id}', 'reject')">REJECT</button>
              ` : ''}
              <button class="action-btn" onclick="showLoanDetails('${loan._id}')">DETAILS</button>
            </td>
          </tr>
        `;
    }).join('') : '<tr><td colspan="6">No loans found</td></tr>';
    
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
    
    // Safe numeric values with validation
    const safePrincipal = isNaN(loan.principal) ? 0 : Number(loan.principal);
    const safeAmount = isNaN(loan.amount) ? 0 : Number(loan.amount);
    const safeInterestAmount = isNaN(loan.interestAmount) ? 0 : Number(loan.interestAmount);
    const safeOverdueFees = isNaN(loan.overdueFees) ? 0 : Number(loan.overdueFees);
    const safeAmountPaid = isNaN(loan.amountPaid) ? 0 : Number(loan.amountPaid);
    const safeTotalAmount = safePrincipal + safeInterestAmount + safeOverdueFees;
    const safeBalance = Math.max(0, safeTotalAmount - safeAmountPaid);

    // Safe repayment history
    const repaymentRows = (loan.repaymentSchedule || []).map(payment => {
      const safePaymentAmount = isNaN(payment.amount) ? 0 : Number(payment.amount);
      const safePaidAmount = isNaN(payment.paidAmount) ? 0 : Number(payment.paidAmount);
      const safeStatus = payment.status || 'pending';
      
      return `
        <tr>
          <td>${formatDate(payment.dueDate)}</td>
          <td>KES ${safePaymentAmount.toLocaleString()}</td>
          <td>KES ${safePaidAmount.toLocaleString()}</td>
          <td class="status-${safeStatus}">${safeStatus.toUpperCase()}</td>
          <td>${payment.paidAt ? formatDate(payment.paidAt) : 'N/A'}</td>
        </tr>
      `;
    }).join('') || '<tr><td colspan="5">No repayment history</td></tr>';

    // Calculate days remaining safely
    const daysRemaining = loan.dueDate ? calculateDaysRemaining(loan.dueDate) : 'N/A';
    const dailyPenalty = safePrincipal * 0.06;
    const maxPaymentAmount = Math.max(0, safeBalance);

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
              <strong>Principal:</strong> KES ${safePrincipal.toLocaleString()}
            </div>
            <div class="info-field">
              <strong>Total Amount:</strong> KES ${safeTotalAmount.toLocaleString()}
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
        
        ${loan.status === 'defaulted' ? `
          <div class="overdue-summary">
            <h4>Overdue Details</h4>
            <div class="detail-row">
              <span>Days Overdue:</span>
              <span>${loan.overdueDays || 0}</span>
            </div>
            <div class="detail-row">
              <span>Daily Penalty:</span>
              <span>6% of principal (KES ${dailyPenalty.toLocaleString()}/day)</span>
            </div>
            <div class="detail-row">
              <span>Total Penalty:</span>
              <span>KES ${safeOverdueFees.toLocaleString()}</span>
            </div>
            <div class="detail-row">
              <span>Updated Total:</span>
              <span>KES ${safeTotalAmount.toLocaleString()}</span>
            </div>
            <div class="detail-row">
              <span>Last Calculated:</span>
              <span>${loan.lastOverdueCalculation ? formatDate(loan.lastOverdueCalculation) : 'N/A'}</span>
            </div>
          </div>
        ` : ''}
        
        <div class="payment-summary">
          <div class="summary-card">
            <h5>Amount Paid</h5>
            <p>KES ${safeAmountPaid.toLocaleString()}</p>
          </div>
          <div class="summary-card">
            <h5>Balance</h5>
            <p>KES ${safeBalance.toLocaleString()}</p>
          </div>
          <div class="summary-card">
            <h5>Days Remaining</h5>
            <p>${daysRemaining}</p>
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
        
        ${loan.status === 'active' && safeBalance > 0 ? `
          <div class="force-payment-section" style="margin-top: 30px;">
            <h4>Force Payment</h4>
            <div class="form-group">
              <label for="force-payment-amount">Amount</label>
              <input type="number" id="force-payment-amount" 
                     min="1" max="${maxPaymentAmount}" 
                     step="100" value="${maxPaymentAmount}">
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
        const amountInput = document.getElementById('force-payment-amount');
        const amount = parseFloat(amountInput.value);
        if (!isNaN(amount) && amount > 0 && amount <= maxPaymentAmount) {
          recordManualPayment(loanId, amount);
        } else {
          showError(`Please enter a valid amount between 1 and ${maxPaymentAmount}`);
          amountInput.focus();
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
  try {
    const due = new Date(dueDate);
    const now = new Date();
    const diff = due - now;
    const days = Math.ceil(diff / (1000 * 60 * 60 * 24));
    return days > 0 ? days : 'Overdue';
  } catch (error) {
    debugLog(`Date calculation error: ${error.message}`);
    return 'N/A';
  }
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

/**
 * Displays pending payments with pagination
 * @param {number} page - Current page number
 */
async function showPendingPayments(page = 1) {
    // Update state - NEWLY ADDED
    currentView = 'payments';
    
    try {
        debugLog('Showing pending payments...');
        
        // Verify all required DOM elements exist
        const section = document.getElementById('pending-payments-section');
        const tableBody = document.getElementById('pending-payments-table-body');
        const titleElement = document.getElementById('pending-payments-section-title');
        
        if (!section || !tableBody || !titleElement) {
            throw new Error('Required DOM elements for payments not found');
        }

        showLoading('pending-payments');
        const response = await apiClient(`/api/admin/pending-payments?page=${page}&limit=20`);
        
        if (!response?.success) {
            throw new Error(response?.message || 'Invalid server response');
        }

        // Clear previous content
        tableBody.innerHTML = '';
        
        // Update title with count
        titleElement.textContent = `Pending Payments (${response.payments?.length || 0})`;
        
        // Handle empty response
        if (!response.payments || response.payments.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="5" class="no-payments">No pending payments found</td></tr>';
        } else {
            // Render payment rows
            tableBody.innerHTML = renderPaymentRows(response.payments);
            
            // Add pagination if needed
            if (response.totalPages > 1) {
                renderPaginationControls(tableBody, response.totalPages, page);
            }
        }
        
        // Show the section
        document.getElementById('admin-grid').classList.add('hidden');
        section.classList.remove('hidden');
        
    } catch (error) {
        debugLog(`Payment display error: ${error.message}`);
        showError(`Failed to load payments: ${error.message}`);
        
        // Ensure we don't leave the UI in a broken state
        if (tableBody) {
            tableBody.innerHTML = '<tr><td colspan="5" class="error-message">Error loading payments</td></tr>';
        }
    } finally {
        hideLoading('pending-payments');
    }
}
/**
 * Renders pending payments table
 * @param {Array} payments - Array of payment objects
 * @param {number} totalPages - Total number of pages
 * @param {number} currentPage - Current page number
 */
function displayPendingPayments(payments, totalPages = 1, currentPage = 1) {
    try {
        debugLog('Attempting to display payments...');
        
        const tableBody = document.getElementById('pending-payments-table-body');
        const titleElement = document.getElementById('pending-payments-section-title');
        const sectionElement = document.getElementById('pending-payments-section');
        
        if (!tableBody || !titleElement || !sectionElement) {
            const missingElements = [];
            if (!tableBody) missingElements.push('tableBody');
            if (!titleElement) missingElements.push('titleElement');
            if (!sectionElement) missingElements.push('sectionElement');
            
            debugLog(`Missing DOM elements: ${missingElements.join(', ')}`);
            throw new Error(`Required DOM elements not found: ${missingElements.join(', ')}`);
        }
        
        debugLog(`Rendering ${payments.length} payments`);
        const title = `Pending Payments (${payments.length})`;
        titleElement.textContent = title;
        
        tableBody.innerHTML = payments.length ? payments.map(payment => {
            const customerName = payment.userId?.fullName || 'Unknown';
            const customerId = payment.userId?._id || '';
            const amount = payment.amount ? `KES ${payment.amount.toLocaleString()}` : 'KES 0';
            const reference = payment.reference || 'N/A';
            const date = payment.createdAt ? formatDate(payment.createdAt) : 'N/A';
            
            return `
                <tr data-payment-id="${payment._id}">
                    <td>
                        <div class="customer-link" onclick="viewCustomerProfile('${customerId}')">
                            <i class="fas fa-user"></i> ${customerName}
                        </div>
                    </td>
                    <td>${amount}</td>
                    <td>${reference}</td>
                    <td>${date}</td>
                    <td>
                        <button class="action-btn approve-btn" onclick="approvePayment('${payment._id}')">
                            APPROVE
                        </button>
                        <button class="action-btn reject-btn" onclick="rejectPayment('${payment._id}')">
                            REJECT
                        </button>
                    </td>
                </tr>
            `;
        }).join('') : '<tr><td colspan="5">No pending payments</td></tr>';
        
        if (totalPages > 1) {
            renderPaginationControls(tableBody, totalPages, currentPage);
        }
        
        document.getElementById('admin-grid').classList.add('hidden');
        sectionElement.classList.remove('hidden');
        debugLog('Payments displayed successfully');
    } catch (error) {
        debugLog(`Error displaying payments: ${error.message}`);
        showError(`Failed to display payments: ${error.message}`);
    }
}
/**
 * Renders pagination controls
 */
function renderPaymentRows(payments) {
    if (!payments || !Array.isArray(payments)) return '';
    
    return payments.map(payment => {
        const customerId = payment.userId?._id || '';
        const customerName = payment.userId?.fullName || 'Unknown Customer';
        const amount = payment.amount ? `KES ${payment.amount.toLocaleString()}` : 'KES 0';
        const reference = payment.reference || 'N/A';
        const date = payment.createdAt ? formatDate(payment.createdAt) : 'N/A';
        
        return `
            <tr data-payment-id="${payment._id}">
                <td>
                    <div class="customer-link" onclick="viewCustomerProfile('${customerId}')">
                        <i class="fas fa-user"></i> ${customerName}
                    </div>
                </td>
                <td>${amount}</td>
                <td>${reference}</td>
                <td>${date}</td>
                <td>
                    <button class="action-btn approve-btn" onclick="approvePayment('${payment._id}')">
                        APPROVE
                    </button>
                    <button class="action-btn reject-btn" onclick="rejectPayment('${payment._id}')">
                        REJECT
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}
/**
 * Handles payment approval with enhanced transaction handling
 * @param {string} paymentId - ID of payment to approve
 */
async function approvePayment(paymentId) {
    if (!confirm('Are you sure you want to approve this payment?\n\nThis action cannot be undone.')) return;
    
    const row = document.querySelector(`tr[data-payment-id="${paymentId}"]`);
    const approveBtn = document.getElementById(`approve-btn-${paymentId}`);
    const tableBody = document.getElementById('pending-payments-table-body');
    
    // Optimistic UI update
    if (row) {
        row.classList.add('processing');
        row.querySelectorAll('button').forEach(btn => btn.disabled = true);
    }
    toggleButtonLoading(approveBtn, true);
    updatePendingCount(-1);

    try {
        const response = await apiClient(
            `/api/admin/payments/${paymentId}/status`,
            'PATCH',
            { status: 'approved' },
            { timeout: 30000 } // 30 second timeout
        );
        
        showNotification('Payment approved successfully!', 'success');
        
        // Complete UI update
        if (row) {
            row.remove();
            // Add visual feedback for successful approval
            const successRow = document.createElement('tr');
            successRow.className = 'success-feedback';
            successRow.innerHTML = `
                <td colspan="5">
                    <i class="fas fa-check-circle"></i> 
                    Payment approved successfully
                </td>
            `;
            tableBody.prepend(successRow);
            setTimeout(() => successRow.remove(), 3000);
        }

        // Handle successful response
        if (response.data && response.data.isFullyPaid) {
            debugLog(`Loan ${response.data.loanId} fully paid`);
            showNotification('Loan fully paid!', 'success');
        }
        
    } catch (error) {
        console.error('Approval failed:', error);
        
        // Handle transaction errors specifically
        if (error.code === 251 || error.code === 'NoSuchTransaction') {
            showNotification('Transaction error. Please try approving again.', 'error', 5000);
        } 
        // Handle timeout errors
        else if (error.name === 'AbortError' || error.code === 'ECONNABORTED') {
            showNotification('Request timed out. Please check your connection and try again.', 'error', 5000);
        }
        // Handle other specific errors
        else if (error.code === 'INVALID_PAYMENT_STATUS') {
            showNotification(`Payment cannot be approved: ${error.message}`, 'error');
        } else if (error.code === 'PAYMENT_NOT_FOUND') {
            showNotification('Payment not found. It may have been processed by another admin.', 'error');
        } else if (error.response?.status === 503) {
            showNotification('Service temporarily unavailable. Please try again later.', 'error', 5000);
        } else {
            showNotification(`Failed to approve payment: ${error.message || 'Please try again'}`, 'error');
        }
        
        // Revert UI if error occurs
        if (row) {
            row.classList.remove('processing');
            row.querySelectorAll('button').forEach(btn => btn.disabled = false);
            tableBody.appendChild(row);
        }
        updatePendingCount(1);
    } finally {
        toggleButtonLoading(approveBtn, false);
    }
}

/**
 * Handles payment approval with token refresh capability
 * @param {string} paymentId - ID of payment to approve
 */
async function confirmLoanApproval() {
    const interestRate = parseFloat(document.getElementById('interestRate').value);
    const repaymentPeriod = parseInt(document.getElementById('repaymentPeriod').value);
    const adminNotes = document.getElementById('adminNotes').value;

    if (!currentLoanId || isNaN(interestRate) || isNaN(repaymentPeriod)) {
        showError('Please fill all required fields with valid values');
        return;
    }

    try {
        showLoading('approvalTermsModal');
        debugLog(`Approving loan ${currentLoanId} with terms: ${interestRate}%, ${repaymentPeriod} days`);
        
        const response = await apiClient(
            `/api/admin/loan-applications/${currentLoanId}/approve`,
            'PATCH',
            { interestRate, repaymentPeriod, adminNotes }
        );

        if (response.success) {
            showSuccess('Loan approved successfully!');
            closeModal('approvalTermsModal');
            
            // Refresh the loans view
            showLoans('pending');
            
            // Emit socket event
            socket.emit('loanApproved', {
                loanId: currentLoanId,
                adminName: currentAdmin.username,
                userId: response.data?.userId,
                interestRate,
                repaymentPeriod
            });
        } else {
            throw new Error(response.message || 'Failed to approve loan');
        }
    } catch (error) {
        debugLog(`Loan approval failed: ${error.message}`);
        showError(error.message || 'Failed to approve loan. Please try again.', 'approvalTermsModal');
    } finally {
        hideLoading('approvalTermsModal');
    }
}

/**
 * Attempts to approve payment with error handling
 */
async function attemptPaymentApproval(paymentId) {
    try {
        const response = await apiClient(
            `/api/admin/payments/${paymentId}/status`,
            'PATCH',
            { status: 'approved' },
            { timeout: 30000 }
        );
        return response;
    } catch (error) {
        if (error.response?.data?.code === 'TokenExpiredError') {
            return { error: 'TokenExpired', message: error.message };
        }
        throw error;
    }
}

/**
 * Handles payment rejection with token refresh capability
 * @param {string} paymentId - ID of payment to reject
 */
async function rejectPayment(paymentId) {
    let reason;
    while (true) {
        reason = prompt('Please enter the rejection reason (min 5 characters, max 500 characters):');
        if (reason === null) return; // User cancelled
        
        if (!reason || reason.trim().length < 5) {
            showNotification('Reason must be at least 5 characters', 'error');
            continue;
        }
        if (reason.length > 500) {
            showNotification('Reason cannot exceed 500 characters', 'error');
            continue;
        }
        break;
    }

    const row = document.querySelector(`tr[data-payment-id="${paymentId}"]`);
    const rejectBtn = document.getElementById(`reject-btn-${paymentId}`);
    const tableBody = document.getElementById('pending-payments-table-body');
    
    // Optimistic UI update
    if (row) {
        row.classList.add('processing');
        row.querySelectorAll('button').forEach(btn => btn.disabled = true);
    }
    toggleButtonLoading(rejectBtn, true);
    updatePendingCount(-1);

    try {
        // First attempt
        let response = await attemptPaymentRejection(paymentId, reason);
        
        // If token expired, refresh and try again
        if (response?.error === 'TokenExpired') {
            await refreshAdminToken();
            response = await attemptPaymentRejection(paymentId, reason);
        }

        if (response.error) {
            throw new Error(response.message || 'Payment rejection failed');
        }

        showNotification('Payment rejected successfully', 'warning');
        
        // Complete UI update
        if (row) {
            row.remove();
            // Add visual feedback for successful rejection
            const feedbackRow = document.createElement('tr');
            feedbackRow.className = 'warning-feedback';
            feedbackRow.innerHTML = `
                <td colspan="5">
                    <i class="fas fa-exclamation-circle"></i> 
                    Payment rejected: ${reason.substring(0, 50)}${reason.length > 50 ? '...' : ''}
                </td>
            `;
            tableBody.prepend(feedbackRow);
            setTimeout(() => feedbackRow.remove(), 5000);
        }
        
    } catch (error) {
        console.error('Rejection failed:', error);
        handlePaymentError(error, row);
    } finally {
        toggleButtonLoading(rejectBtn, false);
    }
}

/**
 * Attempts to reject payment with error handling
 */
async function attemptPaymentRejection(paymentId, reason) {
    try {
        const response = await apiClient(
            `/api/admin/payments/${paymentId}/status`,
            'PATCH',
            { status: 'rejected', reason },
            { timeout: 30000 }
        );
        return response;
    } catch (error) {
        if (error.response?.data?.code === 'TokenExpiredError') {
            return { error: 'TokenExpired', message: error.message };
        }
        throw error;
    }
}

/**
 * Handles payment operation errors consistently
 */
function handlePaymentError(error, row) {
    // Handle token expiration
    if (error.response?.data?.code === 'TokenExpiredError' || error.message.includes('jwt expired')) {
        showNotification('Session expired. Please refresh the page and log in again.', 'error', 5000);
    }
    // Handle transaction errors
    else if (error.code === 251 || error.code === 'NoSuchTransaction') {
        showNotification('Transaction error. Please try the operation again.', 'error', 5000);
    }
    // Handle timeout errors
    else if (error.name === 'AbortError' || error.code === 'ECONNABORTED') {
        showNotification('Request timed out. Please check your connection and try again.', 'error', 5000);
    }
    // Handle other specific errors
    else if (error.code === 'INVALID_PAYMENT_STATUS') {
        showNotification(`Payment cannot be processed: ${error.message}`, 'error');
    } else if (error.code === 'PAYMENT_NOT_FOUND') {
        showNotification('Payment not found. It may have been processed by another admin.', 'error');
    } else if (error.response?.status === 503) {
        showNotification('Service temporarily unavailable. Please try again later.', 'error', 5000);
    } else {
        showNotification(`Operation failed: ${error.message || 'Please try again'}`, 'error');
    }
    
    // Revert UI if error occurs
    if (row) {
        const tableBody = document.getElementById('pending-payments-table-body');
        row.classList.remove('processing');
        row.querySelectorAll('button').forEach(btn => btn.disabled = false);
        tableBody.appendChild(row);
    }
    updatePendingCount(1);
}

/**
 * Refreshes admin token silently
 */
async function refreshAdminToken() {
    try {
        const response = await apiClient('/api/admin/refresh-token', 'POST');
        if (response.token) {
            localStorage.setItem('adminToken', response.token);
            return true;
        }
    } catch (error) {
        console.error('Token refresh failed:', error);
        // Force logout if refresh fails
        localStorage.removeItem('adminToken');
        window.location.href = '/admin/login';
    }
    return false;
}

/**
 * Toggles button loading state
 */
function toggleButtonLoading(button, isLoading) {
    if (button) {
        button.disabled = isLoading;
        button.querySelector('.btn-text').classList.toggle('hidden', isLoading);
        const spinner = button.querySelector('.btn-spinner');
        spinner.classList.toggle('hidden', !isLoading);
        
        const row = button.closest('tr');
        if (row) {
            row.classList.toggle('processing', isLoading);
        }
    }
}

/**
 * Updates the pending payments count
 */
function updatePendingCount(change) {
    const title = document.getElementById('pending-payments-section-title');
    if (title) {
        const match = title.textContent.match(/\((\d+)\)/);
        const currentCount = match ? parseInt(match[1]) : 0;
        const newCount = Math.max(0, currentCount + change);
        
        title.style.transition = 'color 0.3s ease';
        title.style.color = change < 0 ? '#4CAF50' : '#F44336';
        setTimeout(() => {
            title.style.color = '';
        }, 300);
        
        title.textContent = title.textContent.replace(/\(\d+\)/, `(${newCount})`);
    }
}

/**
 * Returns to admin dashboard
 */
function backToDashboard() {
    // Get references to all relevant sections
    const adminGrid = document.getElementById('admin-grid');
    const loansSection = document.getElementById('loans-section');
    const paymentsSection = document.getElementById('pending-payments-section');
    const profileSection = document.getElementById('customer-profile-section');
    
    // Apply fade-out animation to visible sections
    if (!loansSection.classList.contains('hidden')) {
        fadeOutSection(loansSection);
    }
    if (!paymentsSection.classList.contains('hidden')) {
        fadeOutSection(paymentsSection);
    }
    if (!profileSection.classList.contains('hidden')) {
        fadeOutSection(profileSection);
    }
    
    // Show main dashboard with fade-in
    adminGrid.classList.remove('hidden');
    fadeInSection(adminGrid);
    
    // Clear current customer/loan
    currentCustomerId = null;
    currentLoanId = null;
}

// Helper functions for smooth transitions
function fadeOutSection(section) {
    section.style.opacity = '1';
    section.style.transition = 'opacity 0.3s ease';
    
    setTimeout(() => {
        section.style.opacity = '0';
        setTimeout(() => {
            section.classList.add('hidden');
        }, 300);
    }, 0);
}

function fadeInSection(section) {
    section.style.opacity = '0';
    setTimeout(() => {
        section.style.opacity = '1';
    }, 10);
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

// ==================== IMPROVED BACK TO DASHBOARD FUNCTION ====================
function backToDashboard() {
    // Update state - NEWLY ADDED
    currentView = 'dashboard';
    
    // Hide all sections
    document.getElementById('loans-section')?.classList.add('hidden');
    document.getElementById('pending-payments-section')?.classList.add('hidden');
    document.getElementById('customer-profile-section')?.classList.add('hidden');
    
    // Show main dashboard
    document.getElementById('admin-grid')?.classList.remove('hidden');
    
    // Reset current views
    currentCustomerId = null;
    currentLoanId = null;
}

// ==================== UPDATED EVENT LISTENERS ====================
function setupEventListeners() {
    debugLog('Setting up event listeners');
    
    // Verify critical DOM elements first
    verifyCriticalElements();
    
    // Authentication
    document.getElementById("login-button")?.addEventListener("click", checkPassword);
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
    
    // Loan navigation buttons - UPDATED WITH CLONE NODE TO PREVENT DUPLICATES
    document.querySelectorAll('.luxury-btn[data-loan-type]').forEach(btn => {
        btn.replaceWith(btn.cloneNode(true));
    });
    document.querySelectorAll('.luxury-btn[data-loan-type]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const loanType = btn.getAttribute('data-loan-type');
            currentView = 'loans'; // NEWLY ADDED
            showLoans(loanType);
        });
    });
    
    // Pending payments button (with enhanced verification)
    document.getElementById('pending-payments-btn')?.addEventListener('click', () => {
        if (verifyPaymentElements()) {
            currentView = 'payments'; // NEWLY ADDED
            showPendingPayments();
        } else {
            showError('Payment system components not loaded');
        }
    });
    
    // Back buttons - UPDATED WITH PREVENT DEFAULT
    document.getElementById('hide-loans-btn')?.addEventListener('click', (e) => {
        e.preventDefault();
        debugLog('Hide Loans button clicked');
        backToDashboard();
    });
       
    // Logout button
    document.getElementById('logout-btn')?.addEventListener('click', (e) => {
        e.preventDefault();
        logout();
    });
    
    // Debug toggle
    document.getElementById('debug-toggle-btn')?.addEventListener('click', (e) => {
        e.preventDefault();
        toggleDebugConsole();
    });

    // Bulk process button
    document.getElementById('process-bulk-btn')?.addEventListener('click', processBulkLimits);
    
    // Loan approval
    document.getElementById('confirm-approval-btn')?.addEventListener('click', confirmLoanApproval);
    
    // Refresh button
    document.getElementById('refresh-admin-btn')?.addEventListener('click', async (e) => {
        e.preventDefault();
        await refreshAdminPortal();
    });
}

// ==================== DOM VERIFICATION ====================
function verifyCriticalElements() {
    debugLog('Verifying critical DOM elements');
    const checkElements = [
        'pending-payments-table-body',
        'pending-payments-section-title',
        'pending-payments-section',
        'admin-grid',
        'login-button',
        'logout-btn'
    ];
    
    checkElements.forEach(id => {
        const el = document.getElementById(id);
        debugLog(`${id} exists: ${!!el}`);
        if (!el) {
            console.error(`Missing element: #${id}`);
            showError(`System error: Missing component #${id}`);
        }
    });
}

function verifyPaymentElements() {
    const requiredElements = [
        'pending-payments-table-body',
        'pending-payments-section-title',
        'pending-payments-section'
    ];
    
    return requiredElements.every(id => {
        const exists = !!document.getElementById(id);
        if (!exists) debugLog(`Payment element missing: #${id}`);
        return exists;
    });
}

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', () => {
    debugLog('DOM fully loaded');
    
    // Verify all elements before setup
    verifyCriticalElements();
    
    // Setup event listeners
    setupEventListeners();
    
    // Load data if already on admin page
    if (document.getElementById('admin-content')?.classList.contains('hidden') === false) {
        loadAdminData();
    }
});

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
  
  try {
    // Clear all auth-related data (more specific than localStorage.clear())
    localStorage.removeItem("adminToken");
    localStorage.removeItem("adminRefreshToken");
    localStorage.removeItem("adminId");
    
    // Clear any other admin-related storage if needed
    const adminKeys = Object.keys(localStorage).filter(key => key.startsWith('admin_'));
    adminKeys.forEach(key => localStorage.removeItem(key));
    
    // Disconnect socket with better error handling
    if (socket?.connected) {
      try {
        socket.disconnect();
        debugLog('Socket disconnected');
      } catch (socketError) {
        debugLog('Socket disconnect error:', socketError);
      }
    }
    
    // Reset state
    currentAdmin = currentCustomerId = currentLoanId = null;
    
    // Main redirect attempt with enhanced URL handling
    const redirectUrl = new URL('/admin.html', window.location.origin);
    redirectUrl.searchParams.set('logout', 'true');
    redirectUrl.searchParams.set('t', Date.now()); // Cache busting
    
    // Primary redirect with fallback mechanism
    let redirectSuccess = false;
    try {
      window.location.assign(redirectUrl.href);
      redirectSuccess = true;
    } catch (e) {
      debugLog(`Primary redirect failed: ${e.message}`);
    }
    
    // Fallback sequence with timing
    const fallbackPaths = [
      '/admin.html',
      '/admin',
      '/',
    ];
    
    const fallbackAttempt = (index = 0) => {
      if (index >= fallbackPaths.length || redirectSuccess) return;
      
      try {
        window.location.href = fallbackPaths[index];
        redirectSuccess = true;
      } catch (e) {
        debugLog(`Fallback ${index} failed: ${e.message}`);
        setTimeout(() => fallbackAttempt(index + 1), 300 * (index + 1));
      }
    };
    
    if (!redirectSuccess) {
      setTimeout(() => fallbackAttempt(), 500);
    }
    
  } catch (error) {
    console.error('Logout failed:', error);
    // Ultimate fallback
    setTimeout(() => {
      window.location.href = '/';
    }, 1000);
  }
}

// ==================== DEBUG CONSOLE ====================
/**
 * Toggles the visibility of the debug console
 * @param {Event} [event] - Optional click event
 */
function toggleDebugConsole(event) {
  if (event) {
    event.preventDefault();
    event.stopPropagation();
  }

  const debugConsole = document.getElementById('debug-console');
  const debugToggleBtn = document.getElementById('debug-toggle-btn');
  
  if (!debugConsole || !debugToggleBtn) {
    console.warn('Debug console elements not found');
    return;
  }

  const isVisible = debugConsole.style.display === 'block';
  debugConsole.style.display = isVisible ? 'none' : 'block';
  
  // Update button text and icon
  debugToggleBtn.innerHTML = isVisible 
    ? '<i class="fas fa-bug"></i> SHOW DEBUG' 
    : '<i class="fas fa-times"></i> HIDE DEBUG';

  debugLog(`Debug console ${isVisible ? 'hidden' : 'shown'}`);
  
  // Scroll to bottom when shown
  if (!isVisible) {
    setTimeout(() => {
      debugConsole.scrollTop = debugConsole.scrollHeight;
    }, 100);
  }

  // Save state in localStorage
  localStorage.setItem('debugConsoleVisible', !isVisible);
}

// Initialize debug console state from localStorage
function initDebugConsole() {
  const debugConsole = document.getElementById('debug-console');
  const debugToggleBtn = document.getElementById('debug-toggle-btn');
  
  if (!debugConsole || !debugToggleBtn) return;

  const savedState = localStorage.getItem('debugConsoleVisible') === 'true';
  debugConsole.style.display = savedState ? 'block' : 'none';
  
  // Set initial button state
  debugToggleBtn.innerHTML = savedState 
    ? '<i class="fas fa-times"></i> HIDE DEBUG' 
    : '<i class="fas fa-bug"></i> SHOW DEBUG';
}

// Set up event listener
document.addEventListener('DOMContentLoaded', () => {
  // Initialize debug console state
  initDebugConsole();
  
  // Set up toggle button
  document.getElementById('debug-toggle-btn')?.addEventListener('click', toggleDebugConsole);
  
  // Optional: Add keyboard shortcut (Ctrl+Shift+D)
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.shiftKey && e.key === 'D') {
      toggleDebugConsole();
    }
  });
});

// ==================== DEBUG UTILITY ====================
async function verifyLoanDays(loanId) {
    try {
        const response = await apiClient(`/api/verify-days-calculation/${loanId}`);
        const loanCardElement = document.querySelector(`.loan-card[data-loan-id="${loanId}"]`);
        const clientDays = loanCardElement?.querySelector('.days-remaining')?.textContent;
        
        console.log('Verification Report:', {
            serverCalculation: response.serverCalculation,
            clientDisplay: clientDays,
            timeDiscrepancy: response.serverTime - new Date()
        });
    } catch (error) {
        console.error('Verification failed:', error);
    }
}

// Call this when you need to debug a specific loan
// verifyLoanDays('your-loan-id-here');

// ==================== IMPROVED REFRESH FUNCTION ====================
async function refreshAdminPortal() {
    const refreshBtn = document.getElementById('refresh-admin-btn');
    if (!refreshBtn) {
        debugLog('Refresh button not found');
        return;
    }

    // Store original state
    const originalHTML = refreshBtn.innerHTML;
    const originalDisabled = refreshBtn.disabled;
    
    try {
        // Update UI to show loading state
        refreshBtn.innerHTML = '<i class="fas fa-sync fa-spin"></i> Refreshing...';
        refreshBtn.disabled = true;
        debugLog('Refresh initiated');
        showNotification('Refreshing data...', 'info');

        // Set timeout for slow operation warning
        const timeout = setTimeout(() => {
            if (refreshBtn.innerHTML.includes('fa-spin')) {
                showNotification('Refresh is taking longer than expected...', 'warning');
                debugLog('Refresh operation taking longer than expected');
            }
        }, 5000);

        // Refresh based on current view - IMPROVED
        switch(currentView) {
            case 'dashboard':
                await loadAdminData();
                break;
            case 'loans':
                const loanStatus = document.getElementById('loans-section-title')?.textContent?.toLowerCase() || '';
                if (loanStatus.includes('pending')) await showLoans('pending');
                else if (loanStatus.includes('active')) await showLoans('active');
                else if (loanStatus.includes('overdue')) await showLoans('overdue');
                else if (loanStatus.includes('completed')) await showLoans('completed');
                break;
            case 'payments':
                await showPendingPayments();
                break;
            case 'customer':
                const query = document.getElementById('searchCustomer')?.value;
                if (query) await searchCustomer();
                break;
            case 'customer-profile':
                const customerId = document.getElementById('customer-profile-section')?.dataset?.customerId;
                if (customerId) await loadCustomerProfile(customerId);
                break;
            default:
                await loadAdminData();
        }

        // Clean up
        clearTimeout(timeout);
        showNotification('Portal data refreshed', 'success');
        debugLog('Refresh completed successfully');
    } catch (error) {
        console.error('Refresh failed:', error);
        debugLog(`Refresh failed: ${error.message}`);
        showNotification(`Refresh failed: ${error.message}`, 'error');
        
        // Additional error recovery if needed
        if (error.message.includes('authentication')) {
            debugLog('Authentication error detected during refresh');
            setTimeout(logout, 2000);
        }
    } finally {
        // Restore button state
        if (refreshBtn) {
            refreshBtn.innerHTML = originalHTML;
            refreshBtn.disabled = originalDisabled;
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

// Helper function to determine current view
function getCurrentView() {
    if (!document.getElementById('admin-content').classList.contains('hidden')) {
        if (!document.getElementById('loans-section').classList.contains('hidden')) return 'loans';
        if (!document.getElementById('pending-payments-section').classList.contains('hidden')) return 'payments';
        if (!document.getElementById('customer-profile-section').classList.contains('hidden')) return 'customer-profile';
        return 'dashboard';
    }
    return 'login';
}