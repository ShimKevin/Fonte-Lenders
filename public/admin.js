// ==================== GLOBAL VARIABLES ====================
const API_BASE_URL = window.location.hostname === 'localhost'
  ? 'http://localhost:3000'
  : 'https://fonte-lenders.onrender.com';

// State management variable
let currentView = 'dashboard';
let currentAdmin = null;
let currentLoanId = null;
let currentCustomerId = null;

// Performance tracking
const performanceMetrics = {
    apiCalls: 0,
    apiCallDuration: 0,
    socketEvents: 0
};

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
const socket = io(API_BASE_URL, {
  auth: {
    token: localStorage.getItem('adminToken')
  },
  reconnection: true,
  reconnectionAttempts: 10,
  reconnectionDelay: 2000,
  reconnectionDelayMax: 30000,
  randomizationFactor: 0.5,
  timeout: 30000,
  autoConnect: true,
  transports: ['websocket', 'polling'],
  upgrade: true,
  rememberUpgrade: true,
  withCredentials: true
});

// Socket.IO connection handlers
socket.on('connect', () => {
  debugLog('Socket connected successfully');
  showNotification('Connected to real-time service', 'success');
  
  const token = localStorage.getItem('adminToken');
  if (token) {
    socket.emit('authenticate', { token });
    debugLog('Sent authentication token after reconnect');
  }
  
  if (currentAdmin) {
    socket.emit('joinAdminRoom');
    debugLog('Joined admin room');
  }
});

socket.on('connect_error', (err) => {
  debugLog(`Socket connection error: ${err.message}`);
  showNotification('Connection error. Attempting to reconnect...', 'warning');
  
  const delay = Math.min(socket.reconnectionAttempts * 3000, 45000);
  setTimeout(() => {
    if (socket.disconnected) {
      debugLog(`Attempting reconnection after ${delay}ms`);
      socket.connect();
    }
  }, delay);
});

socket.on('disconnect', (reason) => {
  debugLog(`Socket disconnected: ${reason}`);
  
  if (reason === 'io server disconnect') {
    showNotification('Server disconnected. Please refresh the page.', 'error');
  } else {
    showNotification('Connection lost. Reconnecting...', 'warning');
    
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
  if (attempt % 2 === 0) {
    socket.io.opts.transports = ['polling', 'websocket'];
  }
});

socket.on('reconnect_failed', () => {
  debugLog('Reconnection failed after maximum attempts');
  showNotification('Failed to establish connection. Please check your network and refresh the page.', 'error');
});

socket.on('authenticated', () => {
  debugLog('Socket authentication successful');
});

socket.on('unauthorized', (err) => {
  debugLog(`Socket auth failed: ${err.message}`);
  showNotification('Session expired. Please login again.', 'error');
  logout();
});

// Socket event validation
function validateSocketMessage(message) {
  if (!message.eventId || !message.timestamp) return false;
  if (Date.now() - new Date(message.timestamp) > 60000) return false;
  if (message.adminId && !isValidAdmin(message.adminId)) return false;
  return true;
}

function isValidAdmin(adminId) {
  return adminId === currentAdmin?._id;
}

// Socket event listeners with validation
socket.on('loanUpdate', (data) => {
  if (!validateSocketMessage(data)) {
    debugLog('Invalid loanUpdate message received');
    return;
  }
  
  debugLog(`Received loanUpdate: ${JSON.stringify(data)}`);
  
  if (currentCustomerId === data.userId) {
    loadCustomerProfile(currentCustomerId);
  }
  
  showLoans('pending');
  showLoans('active');
  showPendingPayments();
  
  showNotification(`Loan ${data.loanId} ${data.status} by ${data.adminName}`, 'info');
});

socket.on('paymentUpdate', (data) => {
  if (!validateSocketMessage(data)) {
    debugLog('Invalid paymentUpdate message received');
    return;
  }
  
  debugLog(`Received paymentUpdate: ${JSON.stringify(data)}`);
  
  if (currentCustomerId === data.userId) {
    loadCustomerProfile(currentCustomerId);
  }
  
  showPendingPayments();
  
  if (currentLoanId === data.loanId) {
    showLoanDetails(data.loanId);
  }
  
  showNotification(`Payment ${data.status} for loan ${data.loanId}`, 'info');
});

socket.on('limitUpdate', (data) => {
  if (!validateSocketMessage(data)) {
    debugLog('Invalid limitUpdate message received');
    return;
  }
  
  debugLog(`Received limitUpdate: ${JSON.stringify(data)}`);
  showNotification(`Loan limit updated for customer`, 'info');
  
  if (currentCustomerId === data.customerId) {
    loadCustomerProfile(data.customerId);
  }
});

socket.on('loanApproved', (data) => {
  if (!validateSocketMessage(data)) {
    debugLog('Invalid loanApproved message received');
    return;
  }
  
  debugLog(`Received loanApproved event: ${JSON.stringify(data)}`);
  
  if (currentCustomerId === data.userId) {
    loadCustomerProfile(currentCustomerId);
    debugLog(`Refreshed customer profile for ${currentCustomerId}`);
  }
  
  const currentStatus = document.getElementById('loans-section-title')?.textContent || '';
  if (currentStatus.includes('Pending') || currentStatus.includes('Active')) {
    showLoans('pending');
    debugLog('Refreshed loans list after approval');
  }
});

socket.on('paymentApproved', (data) => {
  if (!validateSocketMessage(data)) {
    debugLog('Invalid paymentApproved message received');
    return;
  }
  
  debugLog(`Received paymentApproved: ${JSON.stringify(data)}`);
  showNotification(`Payment of KES ${data.amount} approved for ${data.customerName}`, 'success');
  
  if (currentCustomerId === data.userId) {
    loadCustomerProfile(data.userId);
  }
  
  if (currentLoanId === data.loanId) {
    showLoanDetails(data.loanId);
  }
});

socket.on('paymentRejected', (data) => {
  if (!validateSocketMessage(data)) {
    debugLog('Invalid paymentRejected message received');
    return;
  }
  
  debugLog(`Received paymentRejected: ${JSON.stringify(data)}`);
  showNotification(`Payment rejected by ${data.adminName}`, 'warning');
});

socket.on('adminNotification', (data) => {
  if (!validateSocketMessage(data)) {
    debugLog('Invalid adminNotification message received');
    return;
  }
  
  debugLog(`Received admin notification: ${JSON.stringify(data)}`);
  showNotification(data.message, data.type || 'info');
});

socket.on('reconnect', (attemptNumber) => {
  debugLog(`Socket reconnected after ${attemptNumber} attempts`);
  showNotification('Connection restored', 'success');
  
  if (currentAdmin) {
    socket.emit('authenticate', { token: localStorage.getItem('adminToken') });
  }
});

socket.on('overdueUpdate', (data) => {
  if (!validateSocketMessage(data)) {
    debugLog('Invalid overdueUpdate message received');
    return;
  }
  
  debugLog(`Received overdueUpdate: ${JSON.stringify(data)}`);
  
  if (currentCustomerId === data.userId) {
    debugLog(`Overdue update for customer ${data.userId}`);
    loadCustomerProfile(currentCustomerId);
  }
  
  if (currentLoanId === data.loanId) {
    showLoanDetails(data.loanId);
  }
  
  showNotification(`Overdue fees updated for loan ${data.loanId}`, 'warning');
});

// ==================== API CLIENT ====================
const apiCache = new Map();
const activeAbortControllers = new Map();

async function apiClient(endpoint, method = 'GET', body = null) {
    performanceMetrics.apiCalls++;
    const startTime = performance.now();
    
    let token = localStorage.getItem("adminToken");
    if (!token) {
        debugLog('No token found - logging out');
        logout();
        throw new Error('Authentication required');
    }

    const cacheKey = `${method}:${endpoint}:${JSON.stringify(body)}`;
    
    // Return cached response if available (for GET requests)
    if (method === 'GET' && apiCache.has(cacheKey)) {
        const { data, timestamp } = apiCache.get(cacheKey);
        // Return cached data if less than 30 seconds old
        if (Date.now() - timestamp < 30000) {
            debugLog(`Returning cached response for ${endpoint}`);
            return data;
        }
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);
    
    // Store the controller for possible cancellation
    const requestId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    activeAbortControllers.set(requestId, controller);

    try {
        debugLog(`API request: ${method} ${endpoint}`);
        let response = await fetch(`${API_BASE_URL}${endpoint}`, {
            method,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: body ? JSON.stringify(body) : null,
            signal: controller.signal
        });

        clearTimeout(timeoutId);
        activeAbortControllers.delete(requestId);
        
        // Handle token expiration
        if (response.status === 401) {
            const errorData = await response.json();
            if (errorData.code === 'TokenExpiredError') {
                debugLog('Token expired - attempting refresh');
                try {
                    const refreshResponse = await fetch(`${API_BASE_URL}/api/admin/refresh-token`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ 
                            refreshToken: localStorage.getItem('adminRefreshToken') 
                        })
                    });

                    if (refreshResponse.ok) {
                        const { token: newToken, refreshToken: newRefreshToken } = await refreshResponse.json();
                        localStorage.setItem('adminToken', newToken);
                        localStorage.setItem('adminRefreshToken', newRefreshToken);
                        
                        // Update socket auth token
                        if (socket) {
                            socket.auth.token = newToken;
                            if (!socket.connected) socket.connect();
                        }
                        
                        // Retry the original request with new token
                        return apiClient(endpoint, method, body);
                    } else {
                        throw new Error('Failed to refresh token');
                    }
                } catch (refreshError) {
                    debugLog(`Token refresh failed: ${refreshError.message}`);
                    logout();
                    throw new Error('Session expired. Please login again.');
                }
            } else {
                throw new Error(errorData.message || 'Authentication failed');
            }
        }
        
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
        
        // Cache successful GET responses
        if (method === 'GET' && !endpoint.includes('/pending-') && data) {
            apiCache.set(cacheKey, {
                data,
                timestamp: Date.now()
            });
        }
        
        return data;
    } catch (error) {
        clearTimeout(timeoutId);
        activeAbortControllers.delete(requestId);
        if (error.name === 'AbortError') {
            debugLog(`API timeout: ${endpoint}`);
            throw new Error('Request timed out');
        }
        debugLog(`API error: ${error.message}`);
        throw error;
    } finally {
        const duration = performance.now() - startTime;
        performanceMetrics.apiCallDuration += duration;
        debugLog(`API call to ${endpoint} took ${duration.toFixed(2)}ms`);
    }
}

function cancelPendingOperations() {
    debugLog(`Canceling ${activeAbortControllers.size} pending operations`);
    activeAbortControllers.forEach((controller, id) => {
        controller.abort();
        activeAbortControllers.delete(id);
    });
}

// ==================== AUTHENTICATION FUNCTIONS ====================
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
        socket.emit('joinAdminRoom');
        debugLog('Joined admin room');
    } else {
        debugLog('Login failed');
    }
}

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
            
            // Update socket auth token
            if (socket) {
                socket.auth.token = data.token;
                if (!socket.connected) socket.connect();
            }
            
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
        
        const response = await apiClient('/api/admin/metrics');
        const metrics = response.data;
        
        debugLog('Dashboard data loaded successfully');
        updateDashboardMetrics(metrics);
        document.getElementById('admin-username').textContent = `Logged in as: ${currentAdmin.username}`;
        
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
        customerDetails.innerHTML = '<div class="spinner"></div>';
        debugLog(`Searching customers: ${query}`);
        
        const response = await apiClient(`/api/admin/customers?search=${encodeURIComponent(query)}`);
        
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

function displayCustomerResults(customers) {
    const container = document.getElementById('customerDetails');
    
    if (!customers.length) {
        container.innerHTML = '<p>No customers found.</p>';
        return;
    }
    
    container.innerHTML = customers.map(customer => {
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
        showLoading(messageDiv.id);
        debugLog(`Updating limit for customer ${customerId} to ${newLimit}`);
        
        const response = await apiClient(
            `/api/admin/customers/${customerId}/limit`,
            'PUT',
            { newLimit }
        );

        showSuccess('Limit updated successfully', messageDiv);
        input.value = response.newLimit;
        
        if (context === 'profile') {
            loadCustomerProfile(customerId);
        }
        
        socket.emit('limitUpdated', {
            userId: customerId,
            newLimit: newLimit,
            adminId: currentAdmin._id,
            timestamp: new Date().toISOString(),
            signature: createEventSignature(`limitUpdate-${customerId}`)
        });

    } catch (error) {
        debugLog(`Limit update error: ${error.message}`);
        showError(error.message, messageDiv);
        
        // Specific handling for different error types
        if (error.message.includes('Customer not found')) {
            showError('Customer not found. Please refresh the page.', messageDiv);
        } else if (error.message.includes('validation failed')) {
            showError('Invalid limit value', messageDiv);
        }
    } finally {
        hideLoading(messageDiv.id);
    }
}

function viewCustomerProfile(customerId) {
    document.getElementById('admin-grid').classList.add('hidden');
    document.getElementById('loans-section').classList.add('hidden');
    document.getElementById('pending-payments-section').classList.add('hidden');
    
    const profileSection = document.getElementById('customer-profile-section');
    profileSection.classList.remove('hidden');
    
    currentCustomerId = customerId;
    profileSection.dataset.customerId = customerId;
    profileSection.innerHTML = '<div class="spinner"></div>';
    
    loadCustomerProfile(customerId);
}

async function processBulkLimits() {
    const fileInput = document.getElementById('bulkLimitFile');
    const resultDiv = document.getElementById('bulkUpdateResult');
    
    if (!fileInput.files.length) {
        showError('Please select a CSV file first', resultDiv);
        return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = async (event) => {
        try {
            showLoading('bulkUpdateResult');
            const csvData = event.target.result;
            const lines = csvData.split('\n');
            const updates = [];
            let successCount = 0;
            let errorCount = 0;
            const errorDetails = [];

            // Parse CSV (skip header if exists)
            const startLine = lines[0].includes('customerId') ? 1 : 0;
            for (let i = startLine; i < lines.length; i++) {
                const line = lines[i].trim();
                if (!line) continue;

                const [customerId, newLimit] = line.split(',');
                if (customerId && newLimit && !isNaN(newLimit)) {
                    updates.push({
                        customerId: customerId.trim(),
                        newLimit: parseFloat(newLimit.trim()),
                        lineNumber: i + 1  // Track line number for error reporting
                    });
                } else {
                    errorDetails.push({
                        line: i + 1,
                        error: 'Invalid format',
                        data: line
                    });
                    errorCount++;
                }
            }

            if (!updates.length && errorDetails.length === 0) {
                throw new Error('No valid records found in CSV');
            }

            // Process updates in batches
            const BATCH_SIZE = 5;
            for (let i = 0; i < updates.length; i += BATCH_SIZE) {
                const batch = updates.slice(i, i + BATCH_SIZE);
                const batchResults = await Promise.allSettled(
                    batch.map(update => 
                        apiClient(
                            `/api/admin/customers/${update.customerId}/limit`,
                            'PUT',
                            { newLimit: update.newLimit }
                        ).catch(error => {
                            return Promise.reject({
                                error,
                                customerId: update.customerId,
                                lineNumber: update.lineNumber
                            });
                        })
                    )
                );

                batchResults.forEach((result, index) => {
                    if (result.status === 'fulfilled') {
                        successCount++;
                        // Notify customer via socket
                        socket.emit('limitUpdated', {
                            userId: batch[index].customerId,
                            newLimit: batch[index].newLimit,
                            adminId: currentAdmin._id,
                            timestamp: new Date().toISOString(),
                            signature: createEventSignature(`bulkLimit-${batch[index].customerId}`)
                        });
                    } else {
                        errorCount++;
                        const error = result.reason.error?.message || result.reason.message;
                        errorDetails.push({
                            line: batch[index].lineNumber,
                            customerId: batch[index].customerId,
                            error: error,
                            data: `${batch[index].customerId},${batch[index].newLimit}`
                        });
                        debugLog(`Failed to update ${batch[index].customerId}: ${error}`);
                    }
                });

                // Update progress
                resultDiv.innerHTML = `
                    <div class="progress-container">
                        <div class="progress-bar" style="width: ${Math.min(100, (i / updates.length) * 100)}%"></div>
                    </div>
                    <div>Processed ${Math.min(i + BATCH_SIZE, updates.length)} of ${updates.length} records</div>
                    <div class="text-success">Success: ${successCount}</div>
                    <div class="text-danger">Errors: ${errorCount}</div>
                `;
            }

            // Store error details for later viewing
            if (errorDetails.length > 0) {
                resultDiv.dataset.errorDetails = JSON.stringify(errorDetails);
            }

            // Final result
            resultDiv.innerHTML = `
                <div class="alert ${errorCount > 0 ? 'alert-warning' : 'alert-success'}">
                    <i class="fas ${errorCount > 0 ? 'fa-exclamation-triangle' : 'fa-check-circle'}"></i>
                    Bulk update completed with ${errorCount} error(s)
                </div>
                <div>Total records processed: ${updates.length + errorDetails.length}</div>
                <div class="text-success">Successfully updated: ${successCount}</div>
                <div class="text-danger">Failed updates: ${errorCount}</div>
                ${errorCount > 0 ? 
                    '<button class="btn btn-sm btn-outline-danger mt-2" onclick="showBulkErrorDetails()">Show Error Details</button>' : 
                    ''
                }
            `;

            // Refresh customer data if viewing a profile
            if (currentCustomerId && updates.some(u => u.customerId === currentCustomerId)) {
                loadCustomerProfile(currentCustomerId);
            }

        } catch (error) {
            showError(`Bulk update failed: ${error.message}`, resultDiv);
            debugLog(`Bulk limit error: ${error.message}`);
        } finally {
            hideLoading('bulkUpdateResult');
        }
    };

    reader.onerror = () => {
        showError('Error reading file', resultDiv);
    };

    reader.readAsText(file);
}

function showBulkErrorDetails() {
    const resultDiv = document.getElementById('bulkUpdateResult');
    const errorDetails = JSON.parse(resultDiv.dataset.errorDetails || '[]');
    
    if (errorDetails.length === 0) {
        showNotification('No error details available', 'info');
        return;
    }

    // Create a modal to display errors
    const modalContent = `
        <div class="modal-header">
            <h5 class="modal-title">Bulk Update Errors</h5>
            <button type="button" class="close" data-dismiss="modal">&times;</button>
        </div>
        <div class="modal-body">
            <div class="table-responsive">
                <table class="table table-sm table-bordered">
                    <thead class="thead-light">
                        <tr>
                            <th>Line #</th>
                            <th>Customer ID</th>
                            <th>Error</th>
                            <th>Data</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${errorDetails.map(error => `
                            <tr>
                                <td>${error.line}</td>
                                <td>${error.customerId || 'N/A'}</td>
                                <td class="text-danger">${error.error}</td>
                                <td><small>${error.data || 'N/A'}</small></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
        </div>
    `;

    // Create or update modal
    let modal = document.getElementById('bulkErrorsModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'bulkErrorsModal';
        modal.className = 'modal fade';
        modal.innerHTML = modalContent;
        document.body.appendChild(modal);
        $(modal).modal(); // Initialize with jQuery
    } else {
        modal.innerHTML = modalContent;
        $(modal).modal('show');
    }
}

async function loadCustomerProfile(customerId) {
    try {
        currentCustomerId = customerId;
        
        const response = await apiClient(`/api/admin/customers/${customerId}`);
        
        if (!response.data || !response.data.customer) {
            throw new Error('Invalid customer data received');
        }
        
        const activeLoan = await apiClient(`/api/admin/loans/active?customerId=${customerId}`);
        renderCustomerProfile(response.data.customer, activeLoan.data);
    } catch (error) {
        console.error('Profile load error:', error);
        const profileSection = document.getElementById('customer-profile-section');
        profileSection.innerHTML = `<p class="error">Error: ${error.message}</p>`;
    }
}

function renderCustomerProfile(customer, activeLoan) {
    const profileSection = document.getElementById('customer-profile-section');
    const currentBalance = customer.currentLoanBalance || 0;
    const availableCredit = customer.maxLoanLimit - currentBalance;
    
    let profileHTML = `
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
        </div>`;
        
    if (activeLoan) {
        const daysRemaining = calculateDaysRemaining(activeLoan.dueDate);
        const isOverdue = daysRemaining < 0;
        
        profileHTML += `
        <div class="profile-section">
            <h4>Active Loan</h4>
            <div class="active-loan-card ${isOverdue ? 'overdue' : ''}">
                <div class="loan-summary">
                    <span class="amount">KES ${activeLoan.amount.toLocaleString()}</span>
                    <span class="status">${isOverdue ? 'OVERDUE' : 'ACTIVE'}</span>
                </div>
                <div class="loan-details">
                    <div>Due: ${formatDate(activeLoan.dueDate)}</div>
                    <div>Days: ${isOverdue ? Math.abs(daysRemaining) + ' overdue' : daysRemaining + ' remaining'}</div>
                    <div>Paid: KES ${activeLoan.amountPaid.toLocaleString()}</div>
                    <div>Balance: KES ${(activeLoan.totalAmount - activeLoan.amountPaid).toLocaleString()}</div>
                </div>
                <button class="action-btn" onclick="showLoanDetails('${activeLoan._id}')">
                    View Details
                </button>
            </div>
        </div>`;
    } else {
        profileHTML += `
        <div class="profile-section">
            <h4>Active Loan</h4>
            <div class="no-active-loan">
                <p>No active loans</p>
            </div>
        </div>`;
    }
    
    profileHTML += `
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
        
        <div class="profile-section">
            <button class="luxury-btn" onclick="window.open('/profile.html?adminView=true&userId=${customer._id}', '_blank')" 
              style="margin-top: 15px; background: var(--blue)">
              <i class="fas fa-user-secret"></i> VIEW AS CUSTOMER
            </button>
        </div>
    </div>`;
    
    profileSection.innerHTML = profileHTML;
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

// ==================== LOAN MANAGEMENT ====================
async function showLoans(status = 'pending', page = 1) {
    currentView = 'loans';
    
    try {
        showLoading('loans');
        debugLog(`Loading ${status} loans, page ${page}`);
        
        // MODIFIED: Always include active and defaulted loans in active view
        const statusParam = status === 'active' ? 'active,defaulted' : status;
        
        const response = await apiClient(
            `/api/admin/loan-applications?status=${encodeURIComponent(statusParam)}&page=${page}&limit=20`
        );
        
        // REMOVED: Old filtering logic
        // ADDED: Show all loans from server without filtering
        const loansToDisplay = response.applications || [];
        
        if (status === 'active') {
            displayActiveLoans(loansToDisplay);
        } else {
            displayLoans(loansToDisplay, status, response.totalPages, page);
        }
    } catch (error) {
        debugLog(`Failed to load ${status} loans: ${error.message}`);
        showError(`Failed to load ${status} loans: ${error.message}`);
    } finally {
        hideLoading('loans');
    }
}

function displayActiveLoans(loans) {
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
    if (!loan?.dueDate) return '';
    
    const now = new Date();
    const dueDate = new Date(loan.dueDate);
    const timeRemaining = dueDate - now;
    const daysRemaining = Math.floor(timeRemaining / (1000 * 60 * 60 * 24));
    
    const principal = loan.principal || loan.amount || 0;
    const totalAmount = loan.totalAmount || principal;
    const amountPaid = loan.amountPaid || 0;
    const balance = totalAmount - amountPaid;
    
    // MODIFIED: Only consider completed if status is explicitly 'completed' AND payment is fully approved
    const isCompleted = loan.status === 'completed' && loan.paymentStatus === 'fully_approved';
    const isOverdue = loan.status === 'defaulted' || (daysRemaining < 0 && !isCompleted);
    const isDueSoon = daysRemaining >= 0 && daysRemaining <= 7 && !isCompleted;
    const hasPendingPayments = loan.pendingPayments && loan.pendingPayments.length > 0;
    
    let statusText, statusClass, urgencyBadge = '';
    
    // MODIFIED: Status logic to account for pending payments
    if (isCompleted) {
        statusText = 'PAID IN FULL';
        statusClass = 'status-completed';
    } else if (hasPendingPayments) {
        statusText = 'PENDING PAYMENT APPROVAL';
        statusClass = 'status-pending';
        urgencyBadge = '<div class="pending-badge">PENDING</div>';
    } else if (isOverdue) {
        statusText = `${Math.abs(daysRemaining)} DAY${Math.abs(daysRemaining) !== 1 ? 'S' : ''} OVERDUE`;
        statusClass = 'status-overdue';
        urgencyBadge = '<div class="overdue-badge">OVERDUE</div>';
    } else if (isDueSoon) {
        statusText = `${daysRemaining} DAY${daysRemaining !== 1 ? 'S' : ''} REMAINING`;
        statusClass = 'status-due-soon';
        if (daysRemaining <= 3) {
            urgencyBadge = '<div class="due-soon-badge">DUE SOON</div>';
        }
    } else {
        statusText = `${daysRemaining} DAY${daysRemaining !== 1 ? 'S' : ''} REMAINING`;
        statusClass = 'status-active';
    }
    
    const formatCurrency = (amount) => `KES ${(amount || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    
    // MODIFIED: Card HTML to show pending payment info if exists
    let cardHTML = `
        <div class="loan-card ${isOverdue ? 'loan-overdue' : ''} ${hasPendingPayments ? 'loan-pending' : ''}" data-loan-id="${loan._id}">
            <div class="loan-header">
                <div class="loan-title">
                    <h4>${loan.fullName || 'Unknown Customer'}</h4>
                    <span class="loan-product">${loan.productName || 'Standard Loan'}</span>
                </div>
                <span class="loan-id">#${loan.loanId?.substring(0, 8) || loan._id.substring(0,8)}</span>
            </div>
            
            <div class="loan-details-grid">
                <div class="loan-metric">
                    <span class="metric-label">Principal</span>
                    <span class="metric-value">${formatCurrency(principal)}</span>
                </div>
                <div class="loan-metric">
                    <span class="metric-label">Total Due</span>
                    <span class="metric-value">${formatCurrency(totalAmount)}</span>
                </div>
                <div class="loan-metric">
                    <span class="metric-label">Amount Paid</span>
                    <span class="metric-value positive">${formatCurrency(amountPaid)}</span>
                </div>
                <div class="loan-metric">
                    <span class="metric-label">Balance</span>
                    <span class="metric-value ${balance > 0 ? 'negative' : 'positive'}">${formatCurrency(balance)}</span>
                </div>
            </div>`;
    
    // MODIFIED: Enhanced overdue information display
    if (loan.overdueDays > 0) {
        cardHTML += `
            <div class="overdue-info">
                <span>Overdue: ${loan.overdueDays} day${loan.overdueDays !== 1 ? 's' : ''}</span>
                <span>Fees: KES ${loan.overdueFees?.toLocaleString() || '0'}</span>
                ${hasPendingPayments ? `<span>Pending: ${loan.pendingPayments.length} payment${loan.pendingPayments.length !== 1 ? 's' : ''}</span>` : ''}
            </div>`;
    } else if (hasPendingPayments) {
        cardHTML += `
            <div class="pending-payments-info">
                <span>Pending Payments: ${loan.pendingPayments.length}</span>
                <span>Total Pending: KES ${loan.pendingPayments.reduce((sum, p) => sum + p.amount, 0).toLocaleString()}</span>
            </div>`;
    }
    
    // MODIFIED: Status bar with additional payment status info
    cardHTML += `
            <div class="loan-status-bar">
                <div class="status-info">
                    <span class="${statusClass}">${statusText}</span>
                    ${daysRemaining >= 0 && !isCompleted ? `
                    <span class="due-date">Due: ${dueDate.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}</span>
                    ` : ''}
                    ${hasPendingPayments ? `
                    <span class="pending-date">Submitted: ${formatDate(loan.pendingPayments[0].createdAt)}</span>
                    ` : ''}
                </div>
                <div class="progress-container">
                    <div class="progress-bar" style="width: ${Math.min(100, (amountPaid / totalAmount) * 100)}%"></div>
                </div>
            </div>
            
            <div class="loan-actions">
                <button class="action-btn view-details" onclick="showLoanDetails('${loan._id}')">
                    <i class="fas fa-file-invoice"></i> View Details
                </button>
                ${!isCompleted ? `
                <button class="action-btn record-payment" onclick="showPaymentModal('${loan._id}')">
                    <i class="fas fa-money-bill-wave"></i> Record Payment
                </button>
                ` : ''}
                ${hasPendingPayments ? `
                <button class="action-btn view-pending" onclick="showPendingPayments('${loan._id}')">
                    <i class="fas fa-clock"></i> View Pending
                </button>
                ` : ''}
            </div>
            
            ${urgencyBadge}
        </div>`;
    
    return cardHTML;
}

function displayLoans(loans, status, totalPages = 1, currentPage = 1) {
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
        
        const existingPagination = tableContainer.querySelector('.pagination');
        if (existingPagination) existingPagination.remove();
        
        tableContainer.appendChild(pagination);
    }
    
    document.getElementById('admin-grid').classList.add('hidden');
    document.getElementById('loans-section').classList.remove('hidden');
}

async function showLoanDetails(loanId) {
  currentLoanId = loanId;
  const modal = document.getElementById('loanDetailsModal');
  
  try {
    showLoading('loanDetailsModal');
    const response = await apiClient(`/api/admin/loan-applications/${loanId}`);
    const loan = response.data || response.loan;
    
    const safePrincipal = isNaN(loan.principal) ? 0 : Number(loan.principal);
    const safeAmount = isNaN(loan.amount) ? 0 : Number(loan.amount);
    const safeInterestAmount = isNaN(loan.interestAmount) ? 0 : Number(loan.interestAmount);
    const safeOverdueFees = isNaN(loan.overdueFees) ? 0 : Number(loan.overdueFees);
    const safeAmountPaid = isNaN(loan.amountPaid) ? 0 : Number(loan.amountPaid);
    const safeTotalAmount = safePrincipal + safeInterestAmount + safeOverdueFees;
    const safeBalance = Math.max(0, safeTotalAmount - safeAmountPaid);

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

    const daysRemaining = loan.dueDate ? calculateDaysRemaining(loan.dueDate) : 'N/A';
    const dailyPenalty = safePrincipal * 0.06;
    const maxPaymentAmount = Math.max(0, safeBalance);

    // Start building the modal content
    let modalContent = `
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
        </div>`;

    // Add overdue details if applicable
    if (loan.overdueDays > 0) {
      modalContent += `
        <div class="overdue-details">
          <h4>Overdue Calculation</h4>
          <div class="detail-row">
            <span>Days Overdue:</span>
            <span>${loan.overdueDays} (max 6 days penalty)</span>
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
            <span>Last Calculated:</span>
            <span>${loan.lastOverdueCalculation ? formatDate(loan.lastOverdueCalculation) : 'N/A'}</span>
          </div>
        </div>`;
    }

    // Continue with the rest of the modal content
    modalContent += `
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
      </div>`;

    document.getElementById('loanDetailsContent').innerHTML = modalContent;
    
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

async function forceCompleteLoan(loanId) {
    try {
        debugLog(`Forcing completion of loan: ${loanId}`);
        
        // First confirm with admin
        const confirmed = confirm('Are you sure you want to mark this loan as completed? This action cannot be undone.');
        if (!confirmed) {
            debugLog('Loan completion cancelled by admin');
            return;
        }

        showLoading('loanDetailsModal');
        const response = await apiClient(
            `/api/admin/loan-applications/${loanId}/force-complete`,
            'PATCH',
            { adminId: currentAdmin._id }  // Track which admin performed the action
        );

        if (response.success) {
            const notificationMsg = `Loan #${loanId.substring(0, 8)} marked as completed by ${currentAdmin.username}`;
            showNotification(notificationMsg, 'success');
            debugLog(notificationMsg);
            
            // Refresh all relevant views
            const refreshActions = [
                showLoans('active'),
                showPendingPayments()
            ];
            
            // Refresh customer profile if currently viewing it
            if (currentCustomerId) {
                refreshActions.push(loadCustomerProfile(currentCustomerId));
            }
            
            await Promise.all(refreshActions);
            
            // Notify user and other admins
            if (response.data?.userId) {
                socket.emit('loanStatusUpdate', {
                    loanId: loanId,
                    userId: response.data.userId,
                    newStatus: 'completed',
                    adminName: currentAdmin.username,
                    timestamp: new Date().toISOString(),
                    signature: createEventSignature(`loanComplete-${loanId}`)
                });
                
                socket.emit('adminNotification', {
                    type: 'loan-completed',
                    message: `Loan ${loanId.substring(0, 8)} force-completed by ${currentAdmin.username}`,
                    loanId: loanId,
                    userId: response.data.userId,
                    timestamp: new Date().toISOString(),
                    signature: createEventSignature(`loanNotification-${loanId}`)
                });
            }
            
            closeModal('loanDetailsModal');
        } else {
            throw new Error(response.message || 'Failed to complete loan');
        }
    } catch (error) {
        debugLog(`Failed to force complete loan: ${error.message}`);
        showError(`Failed to mark loan as completed: ${error.message}`, 'loanDetailsModal');
        
        // Specific error handling
        if (error.message.includes('already completed')) {
            showLoans('active'); // Refresh view if loan was already completed
        }
    } finally {
        hideLoading('loanDetailsModal');
    }
}

function showApprovalTerms(loanId) {
    currentLoanId = loanId;
    const modal = document.getElementById('approvalTermsModal');
    
    // Reset form fields
    document.getElementById('interestRate').value = '15'; // Default interest
    document.getElementById('repaymentPeriod').value = '30'; // Default 30 days
    document.getElementById('adminNotes').value = '';
    
    // Display modal with animation
    modal.style.display = 'block';
    setTimeout(() => {
        modal.classList.add('modal-show');
    }, 10);
    
    debugLog(`Showing approval terms for loan: ${loanId}`);
    
    // Focus on first field
    setTimeout(() => {
        document.getElementById('interestRate').focus();
    }, 50);
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

        const principal = response.data.loan.amount;
        const interestAmount = principal * (interestRate / 100);
        const totalAmount = principal + interestAmount;
        
        showSuccess('Loan approved successfully!');
        closeModal('approvalTermsModal');
        showLoans('pending');
        
        socket.emit('loanApproved', {
            loanId: currentLoanId,
            adminId: currentAdmin._id,
            adminName: currentAdmin.username,
            principal: principal,
            interestRate: interestRate,
            totalAmount: totalAmount,
            dueDate: response.data.loan.dueDate,
            userId: response.data.customer._id,
            timestamp: new Date().toISOString(),
            signature: createEventSignature(`loanApproved-${currentLoanId}`)
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
            
            socket.emit('loanUpdate', {
                loanId,
                status: 'rejected',
                adminName: currentAdmin.username,
                timestamp: new Date().toISOString(),
                signature: createEventSignature(`loanRejected-${loanId}`)
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
    currentView = 'payments';
    
    try {
        debugLog('Showing pending payments...');
        
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

        tableBody.innerHTML = '';
        titleElement.textContent = `Pending Payments (${response.payments?.length || 0})`;
        
        if (!response.payments || response.payments.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="5" class="no-payments">No pending payments found</td></tr>';
        } else {
            tableBody.innerHTML = renderPaymentRows(response.payments);
            
            if (response.totalPages > 1) {
                renderPaginationControls(tableBody, response.totalPages, page);
            }
        }
        
        document.getElementById('admin-grid').classList.add('hidden');
        section.classList.remove('hidden');
        
    } catch (error) {
        debugLog(`Payment display error: ${error.message}`);
        showError(`Failed to load payments: ${error.message}`);
        
        if (tableBody) {
            tableBody.innerHTML = '<tr><td colspan="5" class="error-message">Error loading payments</td></tr>';
        }
    } finally {
        hideLoading('pending-payments');
    }
}

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
                        <span class="btn-text">APPROVE</span>
                        <span class="btn-spinner hidden"><i class="fas fa-spinner fa-spin"></i></span>
                    </button>
                    <button class="action-btn reject-btn" onclick="rejectPayment('${payment._id}')">
                        <span class="btn-text">REJECT</span>
                        <span class="btn-spinner hidden"><i class="fas fa-spinner fa-spin"></i></span>
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

async function approvePayment(paymentId) {
    if (!confirm('Are you sure you want to approve this payment?\n\nThis action cannot be undone.')) return;
    
    const row = document.querySelector(`tr[data-payment-id="${paymentId}"]`);
    const approveBtn = row?.querySelector('.approve-btn');
    
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
            { timeout: 30000 }
        );
        
        showNotification('Payment approved successfully!', 'success');
        
        if (row) {
            row.remove();
            const tableBody = document.getElementById('pending-payments-table-body');
            if (tableBody) {
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
        }

        if (response.data && response.data.isFullyPaid) {
            debugLog(`Loan ${response.data.loanId} fully paid`);
            showNotification('Loan fully paid!', 'success');
        }
        
    } catch (error) {
        console.error('Approval failed:', error);
        
        if (error.code === 251 || error.code === 'NoSuchTransaction') {
            showNotification('Transaction error. Please try approving again.', 'error', 5000);
        } 
        else if (error.name === 'AbortError' || error.code === 'ECONNABORTED') {
            showNotification('Request timed out. Please check your connection and try again.', 'error', 5000);
        }
        else if (error.code === 'INVALID_PAYMENT_STATUS') {
            showNotification(`Payment cannot be approved: ${error.message}`, 'error');
        } else if (error.code === 'PAYMENT_NOT_FOUND') {
            showNotification('Payment not found. It may have been processed by another admin.', 'error');
        } else if (error.response?.status === 503) {
            showNotification('Service temporarily unavailable. Please try again later.', 'error', 5000);
        } else {
            showNotification(`Failed to approve payment: ${error.message || 'Please try again'}`, 'error');
        }
        
        if (row) {
            row.classList.remove('processing');
            row.querySelectorAll('button').forEach(btn => btn.disabled = false);
            const tableBody = document.getElementById('pending-payments-table-body');
            if (tableBody) tableBody.appendChild(row);
        }
        updatePendingCount(1);
    } finally {
        toggleButtonLoading(approveBtn, false);
    }
}

async function rejectPayment(paymentId) {
    let reason;
    while (true) {
        reason = prompt('Please enter the rejection reason (min 5 characters, max 500 characters):');
        if (reason === null) return;
        
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
    const rejectBtn = row?.querySelector('.reject-btn');
    const tableBody = document.getElementById('pending-payments-table-body');
    
    if (row) {
        row.classList.add('processing');
        row.querySelectorAll('button').forEach(btn => btn.disabled = true);
    }
    toggleButtonLoading(rejectBtn, true);
    updatePendingCount(-1);

    try {
        let response = await attemptPaymentRejection(paymentId, reason);
        
        if (response?.error === 'TokenExpired') {
            await refreshAdminToken();
            response = await attemptPaymentRejection(paymentId, reason);
        }

        if (response.error) {
            throw new Error(response.message || 'Payment rejection failed');
        }

        showNotification('Payment rejected successfully', 'warning');
        
        if (row) {
            row.remove();
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
        if (error.response?.data?.code === 'TokenExpiredError' || error.message.includes('jwt expired')) {
            return { error: 'TokenExpired', message: error.message };
        }
        throw error;
    }
}

function handlePaymentError(error, row) {
    if (error.response?.data?.code === 'TokenExpiredError' || error.message.includes('jwt expired')) {
        showNotification('Session expired. Please refresh the page and log in again.', 'error', 5000);
    }
    else if (error.code === 251 || error.code === 'NoSuchTransaction') {
        showNotification('Transaction error. Please try the operation again.', 'error', 5000);
    }
    else if (error.name === 'AbortError' || error.code === 'ECONNABORTED') {
        showNotification('Request timed out. Please check your connection and try again.', 'error', 5000);
    }
    else if (error.code === 'INVALID_PAYMENT_STATUS') {
        showNotification(`Payment cannot be processed: ${error.message}`, 'error');
    } else if (error.code === 'PAYMENT_NOT_FOUND') {
        showNotification('Payment not found. It may have been processed by another admin.', 'error');
    } else if (error.response?.status === 503) {
        showNotification('Service temporarily unavailable. Please try again later.', 'error', 5000);
    } else {
        showNotification(`Operation failed: ${error.message || 'Please try again'}`, 'error');
    }
    
    if (row) {
        const tableBody = document.getElementById('pending-payments-table-body');
        row.classList.remove('processing');
        row.querySelectorAll('button').forEach(btn => btn.disabled = false);
        if (tableBody) tableBody.appendChild(row);
    }
    updatePendingCount(1);
}

async function refreshAdminToken() {
    try {
        const refreshToken = localStorage.getItem('adminRefreshToken');
        if (!refreshToken) {
            throw new Error('No refresh token available');
        }

        const response = await fetch(`${API_BASE_URL}/api/admin/refresh-token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refreshToken })
        });

        if (!response.ok) {
            throw new Error('Failed to refresh token');
        }

        const { token, refreshToken: newRefreshToken } = await response.json();
        localStorage.setItem('adminToken', token);
        localStorage.setItem('adminRefreshToken', newRefreshToken);
        
        // Update socket auth token
        if (socket) {
            socket.auth.token = token;
            if (!socket.connected) socket.connect();
        }
        
        return true;
    } catch (error) {
        debugLog(`Token refresh failed: ${error.message}`);
        logout();
        throw error;
    }
}

function toggleButtonLoading(button, isLoading) {
    if (button) {
        button.disabled = isLoading;
        const btnText = button.querySelector('.btn-text');
        const btnSpinner = button.querySelector('.btn-spinner');
        if (btnText) btnText.classList.toggle('hidden', isLoading);
        if (btnSpinner) btnSpinner.classList.toggle('hidden', !isLoading);
        
        const row = button.closest('tr');
        if (row) {
            row.classList.toggle('processing', isLoading);
        }
    }
}

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

// ==================== UTILITY FUNCTIONS ====================
function showLoading(context, message = 'Loading...') {
    const element = typeof context === 'string' 
        ? document.getElementById(context) 
        : context;
    
    if (element) {
        const loadingId = `loading-${Date.now()}`;
        loadingStates.set(element, loadingId);
        
        element.innerHTML = `
            <div class="loading-overlay" id="${loadingId}">
                <div class="spinner"></div>
                <div class="loading-message">${message}</div>
            </div>
            ${element.innerHTML}
        `;
        
        element.classList.add('loading');
    }
}

function hideLoading(context) {
    const element = typeof context === 'string' 
        ? document.getElementById(context) 
        : context;
    
    if (element) {
        const loadingId = loadingStates.get(element);
        if (loadingId) {
            const overlay = document.getElementById(loadingId);
            if (overlay) overlay.remove();
            loadingStates.delete(element);
        }
        element.classList.remove('loading');
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

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.style.display = 'none';
    debugLog(`Closed modal: ${modalId}`);
}

function backToDashboard() {
    debugLog('Returning to dashboard');
    currentView = 'dashboard';
    
    const debugConsole = document.getElementById('debug-console');
    if (debugConsole) {
        debugConsole.style.display = 'none';
        const debugToggleBtn = document.getElementById('debug-toggle-btn');
        if (debugToggleBtn) {
            debugToggleBtn.innerHTML = '<i class="fas fa-bug"></i> SHOW DEBUG';
        }
        localStorage.setItem('debugConsoleVisible', 'false');
    }
    
    const sectionsToHide = [
        'loans-section',
        'pending-payments-section',
        'customer-profile-section'
    ];
    
    sectionsToHide.forEach(sectionId => {
        const section = document.getElementById(sectionId);
        if (section) {
            section.style.display = 'none';
            section.style.zIndex = 'auto';
        }
    });
    
    const adminGrid = document.getElementById('admin-grid');
    if (adminGrid) {
        adminGrid.style.display = 'grid';
        adminGrid.classList.remove('hidden');
    }
    
    currentCustomerId = null;
    currentLoanId = null;
    loadAdminData();
}

let tokenValidationInterval;

function logout() {
    debugLog('Logging out...');
    
    // Clear the token validation interval
    if (tokenValidationInterval) {
        clearInterval(tokenValidationInterval);
    }
    
    try {
        localStorage.removeItem("adminToken");
        localStorage.removeItem("adminRefreshToken");
        localStorage.removeItem("adminId");
        
        const adminKeys = Object.keys(localStorage).filter(key => key.startsWith('admin_'));
        adminKeys.forEach(key => localStorage.removeItem(key));
        
        if (socket?.connected) {
            try {
                socket.disconnect();
                debugLog('Socket disconnected');
            } catch (socketError) {
                debugLog('Socket disconnect error:', socketError);
            }
        }
        
        currentAdmin = currentCustomerId = currentLoanId = null;
        
        const redirectUrl = new URL('/admin.html', window.location.origin);
        redirectUrl.searchParams.set('logout', 'true');
        redirectUrl.searchParams.set('t', Date.now());
        
        let redirectSuccess = false;
        try {
            window.location.assign(redirectUrl.href);
            redirectSuccess = true;
        } catch (e) {
            debugLog(`Primary redirect failed: ${e.message}`);
        }
        
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
        setTimeout(() => {
            window.location.href = '/';
        }, 1000);
    }
}

function debugLog(message) {
    const debugContent = document.getElementById('debug-content');
    if (debugContent) {
        const entry = document.createElement('div');
        entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        debugContent.appendChild(entry);
        debugContent.scrollTop = debugContent.scrollHeight;
    }
    console.log(message);
}

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
    debugConsole.style.zIndex = isVisible ? 'auto' : '10000';
    
    debugToggleBtn.innerHTML = isVisible 
        ? '<i class="fas fa-bug"></i> SHOW DEBUG' 
        : '<i class="fas fa-times"></i> HIDE DEBUG';

    debugLog(`Debug console ${isVisible ? 'hidden' : 'shown'}`);
    
    if (!isVisible) {
        setTimeout(() => {
            const debugContent = document.getElementById('debug-content');
            if (debugContent) {
                debugContent.scrollTop = debugContent.scrollHeight;
            }
        }, 100);
    }

    localStorage.setItem('debugConsoleVisible', !isVisible);
}

function initDebugConsole() {
    const debugConsole = document.getElementById('debug-console');
    const debugToggleBtn = document.getElementById('debug-toggle-btn');
    
    if (!debugConsole || !debugToggleBtn) return;

    const savedState = localStorage.getItem('debugConsoleVisible') === 'true';
    debugConsole.style.display = savedState ? 'block' : 'none';
    
    debugToggleBtn.innerHTML = savedState 
        ? '<i class="fas fa-times"></i> HIDE DEBUG' 
        : '<i class="fas fa-bug"></i> SHOW DEBUG';
}

function setupDebugConsole() {
    initDebugConsole();
    
    document.getElementById('debug-toggle-btn')?.addEventListener('click', toggleDebugConsole);
    
    document.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.shiftKey && e.key === 'D') {
            toggleDebugConsole();
        }
    });
    
    debugLog('Debug console initialized');
}

function createEventSignature(eventId) {
    return btoa(`${eventId}:${currentAdmin._id}:${Date.now()}`);
}

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', () => {
    debugLog('DOM fully loaded');
    setupDebugConsole();
    setupEventListeners();
    
    // Check authentication status and validate token on load
    validateTokenOnLoad().then(() => {
        if (document.getElementById('admin-content')?.classList.contains('hidden') === false) {
            loadAdminData();
        }
    }).catch(() => {
        showLoginContent();
    });
});

async function validateTokenOnLoad() {
    const token = localStorage.getItem("adminToken");
    const refreshToken = localStorage.getItem("adminRefreshToken");
    
    if (!token || !refreshToken) {
        showLoginContent();
        return;
    }

    try {
        // Check if token is about to expire (within 10 minutes)
        const payload = JSON.parse(atob(token.split('.')[1]));
        const expiresIn = (payload.exp * 1000) - Date.now();
        
        if (expiresIn < 600000) { // 10 minutes in milliseconds
            debugLog('Token about to expire - refreshing');
            await refreshAdminToken();
        }
        
        // Validate the token with the server
        await checkAuthStatus();
    } catch (error) {
        debugLog(`Token validation error: ${error.message}`);
        showLoginContent();
        throw error;
    }
}

function showLoginContent() {
    const loginContainer = document.getElementById("login-container");
    const adminContent = document.getElementById("admin-content");
    
    if (loginContainer) loginContainer.classList.remove("hidden");
    if (adminContent) adminContent.classList.add("hidden");
    debugLog('Showing login content');
    
    // Clear any existing token validation interval
    if (window.tokenValidationInterval) {
        clearInterval(window.tokenValidationInterval);
    }
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
        
        // Start token validation after successful login
        startTokenValidationInterval();
    } else {
        debugLog('Admin content container not found');
    }
}

function startTokenValidationInterval() {
    // Clear any existing interval to prevent duplicates
    if (window.tokenValidationInterval) {
        clearInterval(window.tokenValidationInterval);
    }
    
    // Check token every 5 minutes
    window.tokenValidationInterval = setInterval(async () => {
        try {
            const token = localStorage.getItem("adminToken");
            if (!token) {
                debugLog('No token found during periodic check');
                return;
            }
            
            const payload = JSON.parse(atob(token.split('.')[1]));
            const expiresIn = (payload.exp * 1000) - Date.now();
            
            debugLog(`Token expires in ${Math.floor(expiresIn / 60000)} minutes`);
            
            if (expiresIn < 600000) { // 10 minutes remaining
                debugLog('Token nearing expiration - refreshing');
                await refreshAdminToken();
                
                // Show subtle notification to user
                showNotification('Session automatically renewed', 'info');
            }
        } catch (error) {
            debugLog(`Periodic token check failed: ${error.message}`);
            
            // If refresh fails, log the user out
            if (error.message.includes('Failed to refresh')) {
                showNotification('Session expired. Please login again.', 'error');
                setTimeout(logout, 3000);
            }
        }
    }, 300000); // 5 minutes
}

function setupEventListeners() {
    debugLog('Setting up event listeners');
    
    document.getElementById("login-button")?.addEventListener("click", checkPassword);
    document.getElementById("username-input")?.addEventListener("keypress", e => {
        if (e.key === 'Enter') checkPassword();
    });
    document.getElementById("password-input")?.addEventListener("keypress", e => {
        if (e.key === 'Enter') checkPassword();
    });

    document.getElementById("searchCustomer")?.addEventListener("keypress", e => {
        if (e.key === 'Enter') searchCustomer();
    });

    document.getElementById("reportType")?.addEventListener("change", () => {
        const customDateRange = document.getElementById("customDateRange");
        if (customDateRange) {
            customDateRange.style.display = 
                document.getElementById("reportType").value === 'custom' ? 'block' : 'none';
        }
    });

    document.getElementById("bulkLimitFile")?.addEventListener("change", function() {
        const bulkUpdateResult = document.getElementById("bulkUpdateResult");
        if (bulkUpdateResult) {
            bulkUpdateResult.textContent = "";
        }
    });
    
    document.querySelectorAll('.close-modal').forEach(btn => {
        btn.addEventListener('click', () => {
            const modal = btn.closest('.modal');
            if (modal) {
                modal.style.display = 'none';
            }
        });
    });
    
    document.getElementById("approvalTermsModal")?.addEventListener("click", function(e) {
        if (e.target === this) closeModal('approvalTermsModal');
    });
    
    document.getElementById("reportModal")?.addEventListener("click", function(e) {
        if (e.target === this) closeModal('reportModal');
    });
    
    document.getElementById("loanDetailsModal")?.addEventListener("click", function(e) {
        if (e.target === this) closeModal('loanDetailsModal');
    });
    
    document.getElementById("generateReportBtn")?.addEventListener("click", generateReport);
    
    // Improved loan button event listeners
    const loanButtons = document.querySelectorAll('.luxury-btn[data-loan-type]');
    loanButtons.forEach(btn => {
        // Remove any existing listeners first
        const newBtn = btn.cloneNode(true);
        btn.parentNode.replaceChild(newBtn, btn);
        newBtn.addEventListener('click', (e) => {
            e.preventDefault();
            const loanType = newBtn.getAttribute('data-loan-type');
            currentView = 'loans';
            showLoans(loanType);
        });
    });
    
    document.getElementById('pending-payments-btn')?.addEventListener('click', () => {
        currentView = 'payments';
        showPendingPayments();
    });
    
    document.getElementById('hide-loans-btn')?.addEventListener('click', (e) => {
        e.preventDefault();
        debugLog('Hide Loans button clicked');
        backToDashboard();
    });
       
    document.getElementById('logout-btn')?.addEventListener('click', (e) => {
        e.preventDefault();
        logout();
    });

    document.getElementById('process-bulk-btn')?.addEventListener('click', processBulkLimits);
    
    document.getElementById('confirm-approval-btn')?.addEventListener('click', confirmLoanApproval);
    
    document.getElementById('refresh-admin-btn')?.addEventListener('click', async (e) => {
        e.preventDefault();
        await refreshAdminPortal();
    });
}

async function refreshAdminPortal() {
    const refreshBtn = document.getElementById('refresh-admin-btn');
    if (!refreshBtn) {
        debugLog('Refresh button not found');
        return;
    }

    const originalHTML = refreshBtn.innerHTML;
    const originalDisabled = refreshBtn.disabled;
    
    try {
        refreshBtn.innerHTML = '<i class="fas fa-sync fa-spin"></i> Refreshing...';
        refreshBtn.disabled = true;
        debugLog('Refresh initiated');
        showNotification('Refreshing data...', 'info');

        const timeout = setTimeout(() => {
            if (refreshBtn.innerHTML.includes('fa-spin')) {
                showNotification('Refresh is taking longer than expected...', 'warning');
                debugLog('Refresh operation taking longer than expected');
            }
        }, 5000);

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

        clearTimeout(timeout);
        showNotification('Portal data refreshed', 'success');
        debugLog('Refresh completed successfully');
    } catch (error) {
        console.error('Refresh failed:', error);
        debugLog(`Refresh failed: ${error.message}`);
        showNotification(`Refresh failed: ${error.message}`, 'error');
        
        if (error.message.includes('authentication')) {
            debugLog('Authentication error detected during refresh');
            setTimeout(logout, 2000);
        }
    } finally {
        if (refreshBtn) {
            refreshBtn.innerHTML = originalHTML;
            refreshBtn.disabled = originalDisabled;
        }
    }
}

function downloadLoanDocuments(loanId) {
  debugLog(`Downloading documents for loan: ${loanId}`);
  showNotification('Preparing documents for download...', 'info');
  
  setTimeout(() => {
    showNotification('Documents ready for download!', 'success');
  }, 2000);
}

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
      showLoanDetails(loanId);
      
      showPendingPayments();
      if (currentCustomerId) loadCustomerProfile(currentCustomerId);
    }
  } catch (error) {
    showError(`Failed to record payment: ${error.message}`);
  }
}

function calculateDaysRemaining(dueDate) {
    if (!dueDate) return 'N/A';
    const now = new Date();
    const due = new Date(dueDate);
    const diffTime = due - now;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
}

// Card click handler utility
function handleCardClick(card, callback) {
    let isProcessing = false;
    
    card.addEventListener('click', async (e) => {
        if (isProcessing) return;
        isProcessing = true;
        
        // Add visual feedback
        card.style.opacity = '0.7';
        
        try {
            await callback(e);
        } catch (error) {
            console.error('Card click error:', error);
        } finally {
            // Restore card appearance
            setTimeout(() => {
                card.style.opacity = '1';
                isProcessing = false;
            }, 300);
        }
    });
}

// Modal management
let activeModal = null;

function showModal(modalId) {
    if (activeModal) {
        closeModal(activeModal);
    }
    
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'block';
        activeModal = modalId;
        
        // Add escape key handler
        const keyHandler = (e) => {
            if (e.key === 'Escape') {
                closeModal(modalId);
                document.removeEventListener('keydown', keyHandler);
            }
        };
        
        document.addEventListener('keydown', keyHandler);
    }
}

// View manager for better navigation control
const viewManager = {
    currentView: 'dashboard',
    views: {},
    
    registerView(name, config) {
        this.views[name] = config;
    },
    
    showView(name, params) {
        if (this.views[name]) {
            // Hide current view
            if (this.views[this.currentView]?.hide) {
                this.views[this.currentView].hide();
            }
            
            // Show new view
            this.currentView = name;
            this.views[name].show(params);
        }
    }
};

// Register views during initialization
viewManager.registerView('dashboard', {
    show: () => {
        document.getElementById('admin-grid').classList.remove('hidden');
        loadAdminData();
    },
    hide: () => {
        document.getElementById('admin-grid').classList.add('hidden');
    }
});

viewManager.registerView('loans', {
    show: (status) => showLoans(status),
    hide: () => {
        document.getElementById('loans-section').classList.add('hidden');
    }
});

// Performance tracking utility
function trackPerformance(name, action) {
    const start = performance.now();
    const result = action();
    const duration = performance.now() - start;
    
    debugLog(`Performance: ${name} took ${duration.toFixed(2)}ms`);
    
    if (duration > 500) {
        showNotification(`${name} is taking longer than expected`, 'warning');
    }
    
    return result;
}