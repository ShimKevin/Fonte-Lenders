document.addEventListener('DOMContentLoaded', function() {
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

    // Initialize the admin interface
    initAdmin();

    function initAdmin() {
        // Event listeners
        loginButton.addEventListener('click', handleLogin);
        logoutButton.addEventListener('click', handleLogout);
        debugToggleButton.addEventListener('click', toggleDebugConsole);
        refreshButton.addEventListener('click', refreshAdminData);
        pendingPaymentsBtn.addEventListener('click', showPendingPayments);
        hidePaymentsBtn.addEventListener('click', showDashboard);
        processBulkBtn.addEventListener('click', processBulkLimitUpdate);

        // Handle Enter key in login form
        usernameInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') handleLogin();
        });
        passwordInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') handleLogin();
        });

        // Loan card click handlers
        document.querySelectorAll('[data-loan-type]').forEach(card => {
            card.addEventListener('click', function() {
                const loanType = this.getAttribute('data-loan-type');
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
            
        } catch (error) {
            console.error('Login error:', error);
            showError(error.message || 'Login failed. Please try again.');
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

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || 'Token validation failed');
            }

            // Token is valid
            adminData = data.admin;
            loginContainer.classList.add('hidden');
            adminContent.classList.remove('hidden');
            document.getElementById('admin-username').textContent = `Logged in as: ${adminData.username}`;
            
            // Initialize socket connection
            initSocketConnection(token);
            
            // Load initial data
            loadAdminData();
            
        } catch (error) {
            console.error('Token validation error:', error);
            localStorage.removeItem('adminToken');
        }
    }

    function handleLogout() {
        localStorage.removeItem('adminToken');
        if (socket) {
            socket.disconnect();
        }
        adminContent.classList.add('hidden');
        loginContainer.classList.remove('hidden');
        usernameInput.value = '';
        passwordInput.value = '';
        errorMessage.classList.add('hidden');
        adminData = null;
    }

    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.classList.remove('hidden');
        setTimeout(() => {
            errorMessage.classList.add('hidden');
        }, 5000);
    }

    // ==================== SOCKET.IO FUNCTIONS ====================
    function initSocketConnection(token) {
        if (socket) {
            socket.disconnect();
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
    }

    function showLoansSection(loanType) {
        currentView = 'loans';
        currentLoanType = loanType;
        
        // Hide other sections
        pendingPaymentsSection.classList.add('hidden');
        customerProfileSection.classList.add('hidden');
        document.getElementById('admin-grid').style.display = 'none';
        
        // Show loans section
        loansSection.classList.remove('hidden');
        document.getElementById('loans-section-title').textContent = `${loanType.charAt(0).toUpperCase() + loanType.slice(1)} Loans`;
        
        // Show appropriate view (grid for active loans, table for others)
        if (loanType === 'active') {
            loansGridContainer.style.display = 'block';
            loansTableContainer.style.display = 'none';
        } else {
            loansGridContainer.style.display = 'none';
            loansTableContainer.style.display = 'block';
        }
        
        // Load data
        refreshLoansData();
    }

    function showPendingPayments() {
        currentView = 'pending-payments';
        loansSection.classList.add('hidden');
        customerProfileSection.classList.add('hidden');
        document.getElementById('admin-grid').style.display = 'none';
        pendingPaymentsSection.classList.remove('hidden');
        refreshPendingPayments();
    }

    function showCustomerProfile(customer) {
        currentView = 'customer-profile';
        currentCustomer = customer;
        loansSection.classList.add('hidden');
        pendingPaymentsSection.classList.add('hidden');
        document.getElementById('admin-grid').style.display = 'none';
        customerProfileSection.classList.remove('hidden');
        
        renderCustomerProfile(customer);
    }

    function backToCustomerSearch() {
        showDashboard();
        customerDetailsContainer.innerHTML = '';
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
            
        } catch (error) {
            console.error('Error loading admin data:', error);
            showNotification('Failed to load dashboard data', 'error');
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
        } catch (error) {
            console.error('Refresh error:', error);
            showNotification('Failed to refresh data', 'error');
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
            
        } catch (error) {
            console.error('Error loading loans:', error);
            showNotification('Failed to load loans', 'error');
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
        card.innerHTML = `
            <div class="loan-header">
                <h4>${loan.fullName}</h4>
                <span class="status-${loan.status}">${loan.status.toUpperCase()}</span>
            </div>
            <div class="loan-details">
                <div class="detail">
                    <span>Principal</span>
                    <span>KES ${loan.amount.toLocaleString()}</span>
                </div>
                <div class="detail">
                    <span>Total Due</span>
                    <span>KES ${totalAmount.toLocaleString()}</span>
                </div>
                <div class="detail">
                    <span>Amount Paid</span>
                    <span>KES ${amountPaid.toLocaleString()}</span>
                </div>
                <div class="detail">
                    <span>Amount Due</span>
                    <span>KES ${amountDue.toLocaleString()}</span>
                </div>
                <div class="detail">
                    <span>${isOverdue ? 'Days Overdue' : 'Days Remaining'}</span>
                    <span class="${isOverdue ? 'text-warning' : ''}">
                        ${isOverdue ? overdueDays : daysRemaining}
                        ${isOverdue && overdueDays > 6 ? ' (penalty capped)' : ''}
                    </span>
                </div>
                <div class="detail">
                    <span>Due Date</span>
                    <span>${formatDate(loan.dueDate)}</span>
                </div>
            </div>
            <div class="progress-container" style="margin-top: 15px; height: 10px; background: #333; border-radius: 5px;">
                <div class="progress-bar" style="height: 100%; width: ${progress}%; background: ${progress === 100 ? '#4CAF50' : '#FFD700'}; border-radius: 5px;"></div>
            </div>
            <div class="loan-actions" style="margin-top: 15px; display: flex; gap: 10px;">
                <button class="luxury-btn" data-action="view" data-loan-id="${loan._id}" style="padding: 8px 15px; font-size: 14px;">View Details</button>
                ${loan.status === 'pending' ? `
                    <button class="luxury-btn" data-action="approve" data-loan-id="${loan._id}" style="padding: 8px 15px; font-size: 14px; background: #4CAF50;">Approve</button>
                    <button class="luxury-btn" data-action="reject" data-loan-id="${loan._id}" style="padding: 8px 15px; font-size: 14px; background: #f44336;">Reject</button>
                ` : ''}
                ${isOverdue ? `
                    <button class="luxury-btn" data-action="force-complete" data-loan-id="${loan._id}" style="padding: 8px 15px; font-size: 14px; background: #2196F3;">Mark Complete</button>
                ` : ''}
            </div>
        `;
        
        // Add event listeners to buttons
        card.querySelectorAll('button').forEach(btn => {
            btn.addEventListener('click', function() {
                const action = this.getAttribute('data-action');
                const loanId = this.getAttribute('data-loan-id');
                
                switch (action) {
                    case 'view':
                        showLoanDetails(loanId);
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
                            showLoanDetails(loanId);
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

    async function showLoanDetails(loanId) {
        try {
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
            
        } catch (error) {
            console.error('Error loading loan details:', error);
            showNotification('Failed to load loan details', 'error');
        }
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
                <button class="luxury-btn" onclick="window.location.href='/api/admin/loans/${loan._id}/documents'" style="padding: 10px 15px;">
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
        document.getElementById('interestRate').value = '15';
        document.getElementById('repaymentPeriod').value = '30';
        document.getElementById('adminNotes').value = '';
        document.getElementById('confirm-approval-btn').setAttribute('data-loan-id', loanId);
        approvalTermsModal.style.display = 'flex';
    }

    function showRejectionModal(loanId) {
        const reason = prompt('Enter rejection reason:');
        if (reason && reason.trim() !== '') {
            rejectLoan(loanId, reason.trim());
        }
    }

    async function approveLoan(loanId, terms) {
        try {
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
            refreshLoansData();
            refreshAdminData();
            
        } catch (error) {
            console.error('Error approving loan:', error);
            showNotification(error.message || 'Failed to approve loan', 'error');
        }
    }

    async function rejectLoan(loanId, reason) {
        try {
            const response = await fetch(`${API_BASE_URL}/api/admin/loan-applications/${loanId}/reject`, {
                method: 'PATCH',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ reason })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to reject loan');
            }
            
            showNotification('Loan rejected successfully', 'success');
            refreshLoansData();
            refreshAdminData();
            
        } catch (error) {
            console.error('Error rejecting loan:', error);
            showNotification(error.message || 'Failed to reject loan', 'error');
        }
    }

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
            
        } catch (error) {
            console.error('Error completing loan:', error);
            showNotification(error.message || 'Failed to complete loan', 'error');
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
            
        } catch (error) {
            console.error('Error recording payment:', error);
            showNotification(error.message || 'Failed to record payment', 'error');
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
            
        } catch (error) {
            console.error('Error loading pending payments:', error);
            showNotification('Failed to load pending payments', 'error');
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
            
        } catch (error) {
            console.error('Error approving payment:', error);
            showNotification(error.message || 'Failed to approve payment', 'error');
        }
    }

    async function rejectPayment(paymentId) {
        const reason = prompt('Enter rejection reason:');
        if (!reason || reason.trim() === '') {
            alert('Please enter a valid reason');
            return;
        }
        
        try {
            const response = await fetch(`${API_BASE_URL}/api/admin/payments/${paymentId}/reject`, {
                method: 'PATCH',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ reason })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to reject payment');
            }
            
            showNotification('Payment rejected successfully', 'success');
            refreshPendingPayments();
            
        } catch (error) {
            console.error('Error rejecting payment:', error);
            showNotification(error.message || 'Failed to reject payment', 'error');
        }
    }

    // ==================== CUSTOMER MANAGEMENT FUNCTIONS ====================
    async function searchCustomer() {
        const searchTerm = searchCustomerInput.value.trim();
        if (!searchTerm) {
            alert('Please enter a search term');
            return;
        }
        
        try {
            const response = await fetch(`${API_BASE_URL}/api/admin/customers?search=${encodeURIComponent(searchTerm)}`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
                }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to search customers');
            }
            
            renderCustomerSearchResults(data.customers);
            
        } catch (error) {
            console.error('Error searching customers:', error);
            showNotification(error.message || 'Failed to search customers', 'error');
        }
    }

    function renderCustomerSearchResults(customers) {
        customerDetailsContainer.innerHTML = '';
        
        if (!customers || customers.length === 0) {
            customerDetailsContainer.innerHTML = '<p>No customers found</p>';
            return;
        }
        
        customers.forEach(customer => {
            const customerCard = document.createElement('div');
            customerCard.className = 'customer-card';
            customerCard.innerHTML = `
                <div class="customer-header">
                    <h4>${customer.fullName}</h4>
                    <span class="status-${customer.verificationStatus || 'pending'}">${(customer.verificationStatus || 'pending').toUpperCase()}</span>
                </div>
                <div class="detail-row">
                    <span>Customer ID:</span>
                    <span>${customer.customerId}</span>
                </div>
                <div class="detail-row">
                    <span>Phone:</span>
                    <span>${customer.phoneNumber}</span>
                </div>
                <div class="detail-row">
                    <span>Email:</span>
                    <span>${customer.email || 'N/A'}</span>
                </div>
                <div class="detail-row">
                    <span>Loan Limit:</span>
                    <span>KES ${customer.maxLoanLimit.toLocaleString()}</span>
                </div>
                <div class="detail-row">
                    <span>Current Balance:</span>
                    <span>KES ${customer.currentLoanBalance.toLocaleString()}</span>
                </div>
                <div class="detail-row">
                    <span>Available:</span>
                    <span>KES ${(customer.maxLoanLimit - customer.currentLoanBalance).toLocaleString()}</span>
                </div>
                <div class="limit-controls">
                    <div class="limit-input-group">
                        <input type="number" id="newLimit-${customer._id}" placeholder="New loan limit" min="0">
                        <button class="luxury-btn" onclick="updateCustomerLimit('${customer._id}')" style="padding: 8px 15px;">Update Limit</button>
                    </div>
                    <div class="limit-message" id="limitMessage-${customer._id}"></div>
                </div>
                <div class="customer-actions" style="margin-top: 15px; display: flex; gap: 10px;">
                    <button class="luxury-btn" onclick="viewCustomerProfile('${customer._id}')" style="padding: 8px 15px;">View Profile</button>
                    ${customer.activeLoan ? `
                        <button class="luxury-btn" onclick="viewCustomerLoan('${customer._id}')" style="padding: 8px 15px; background: #FFD700; color: #000;">View Active Loan</button>
                    ` : ''}
                </div>
            `;
            
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
            return null;
        }
    }

    function renderCustomerProfile(customer) {
        if (!customer) return;
        
        customerProfileSection.innerHTML = `
            <div class="profile-header">
                <button class="back-btn" onclick="backToCustomerSearch()">
                    <i class="fas fa-arrow-left"></i> Back to Search
                </button>
                <h2>${customer.fullName}'s Profile</h2>
            </div>
            
            <div class="customer-profile-grid">
                <div class="profile-section">
                    <h3><i class="fas fa-user"></i> Personal Information</h3>
                    <div class="profile-field">
                        <strong>Full Name:</strong>
                        <span>${customer.fullName}</span>
                    </div>
                    <div class="profile-field">
                        <strong>Customer ID:</strong>
                        <span>${customer.customerId}</span>
                    </div>
                    <div class="profile-field">
                        <strong>Phone Number:</strong>
                        <span>${customer.phoneNumber}</span>
                    </div>
                    <div class="profile-field">
                        <strong>Email:</strong>
                        <span>${customer.email || 'N/A'}</span>
                    </div>
                    <div class="profile-field">
                        <strong>Verification Status:</strong>
                        <span class="status-${customer.verificationStatus || 'pending'}">${(customer.verificationStatus || 'pending').toUpperCase()}</span>
                    </div>
                    <div class="profile-field">
                        <strong>Member Since:</strong>
                        <span>${formatDate(customer.createdAt)}</span>
                    </div>
                </div>
                
                <div class="profile-section">
                    <h3><i class="fas fa-credit-card"></i> Loan Information</h3>
                    <div class="profile-field">
                        <strong>Maximum Loan Limit:</strong>
                        <span>KES ${customer.maxLoanLimit.toLocaleString()}</span>
                    </div>
                    <div class="profile-field">
                        <strong>Current Loan Balance:</strong>
                        <span>KES ${customer.currentLoanBalance.toLocaleString()}</span>
                    </div>
                    <div class="profile-field">
                        <strong>Available Credit:</strong>
                        <span>KES ${(customer.maxLoanLimit - customer.currentLoanBalance).toLocaleString()}</span>
                    </div>
                    
                    <div class="limit-controls" style="margin-top: 20px;">
                        <h4>Update Loan Limit</h4>
                        <div class="limit-input-group">
                            <input type="number" id="newCustomerLimit" placeholder="New loan limit" min="0" value="${customer.maxLoanLimit}">
                            <button class="luxury-btn" onclick="updateCustomerLimit('${customer._id}', true)" style="padding: 8px 15px;">Update Limit</button>
                        </div>
                        <div class="limit-message" id="customerLimitMessage"></div>
                    </div>
                </div>
                
                ${customer.activeLoan ? `
                <div class="profile-section">
                    <h3><i class="fas fa-file-invoice"></i> Active Loan</h3>
                    <div class="profile-field">
                        <strong>Loan Amount:</strong>
                        <span>KES ${customer.activeLoan.amount.toLocaleString()}</span>
                    </div>
                    <div class="profile-field">
                        <strong>Amount Paid:</strong>
                        <span>KES ${customer.activeLoan.amountPaid.toLocaleString()}</span>
                    </div>
                    <div class="profile-field">
                        <strong>Status:</strong>
                        <span class="status-${customer.activeLoan.status}">${customer.activeLoan.status.toUpperCase()}</span>
                    </div>
                    <div class="profile-field">
                        <strong>Due Date:</strong>
                        <span>${formatDate(customer.activeLoan.dueDate)}</span>
                    </div>
                    <button class="luxury-btn" onclick="showLoanDetails('${customer.activeLoan._id}')" style="margin-top: 15px; width: 100%;">
                        View Loan Details
                    </button>
                </div>
                ` : ''}
            </div>
            
            <div class="profile-actions" style="margin-top: 30px; text-align: center;">
                <button class="luxury-btn danger-btn" onclick="deleteCustomer('${customer._id}')" style="padding: 10px 20px;">
                    <i class="fas fa-trash-alt"></i> Delete Customer
                </button>
            </div>
        `;
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
            
            messageElement.textContent = 'Loan limit updated successfully';
            messageElement.className = 'limit-message success';
            
            // Refresh data
            if (isProfileView && currentCustomer) {
                const updatedCustomer = await fetchCustomerDetails(currentCustomer._id);
                renderCustomerProfile(updatedCustomer);
            } else {
                searchCustomer();
            }
            
            showNotification('Loan limit updated successfully', 'success');
            
        } catch (error) {
            console.error('Error updating limit:', error);
            messageElement.textContent = error.message || 'Failed to update limit';
            messageElement.className = 'limit-message error';
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
            
        } catch (error) {
            console.error('Error deleting customer:', error);
            showNotification(error.message || 'Failed to delete customer', 'error');
        }
    }

    function viewCustomerProfile(customerId) {
        fetchCustomerDetails(customerId).then(customer => {
            if (customer) {
                showCustomerProfile(customer);
            }
        });
    }

    function viewCustomerLoan(customerId) {
        fetchCustomerDetails(customerId).then(customer => {
            if (customer && customer.activeLoan) {
                showLoanDetails(customer.activeLoan._id);
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
            
        } catch (error) {
            console.error('Bulk update error:', error);
            bulkUpdateResult.innerHTML = `
                <div style="color: #f44336;">
                    <i class="fas fa-times-circle"></i> ${error.message || 'Failed to process bulk update'}
                </div>
            `;
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
            
        } catch (error) {
            console.error('Report generation error:', error);
            showNotification(error.message || 'Failed to generate report', 'error');
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
    function formatDate(dateString) {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleDateString('en-GB', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric'
        });
    }

    function showNotification(message, type = 'info') {
        const existingNotifications = document.querySelectorAll('.notification');
        existingNotifications.forEach(notification => {
            notification.remove();
        });

        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'times-circle' : 'info-circle'}"></i>
                <span>${message}</span>
            </div>
        `;

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.style.opacity = '0';
            setTimeout(() => notification.remove(), 300);
        }, 5000);
    }

    function toggleDebugConsole() {
        debugMode = !debugMode;
        debugConsole.style.display = debugMode ? 'block' : 'none';
        debugToggleButton.querySelector('.debug-btn-text').textContent = debugMode ? 'HIDE DEBUG' : 'SHOW DEBUG';
    }

    function logDebug(message, data) {
        if (!debugMode) return;
        
        const entry = document.createElement('div');
        entry.innerHTML = `<span style="color: #4CAF50;">[${new Date().toLocaleTimeString()}]</span> ${message}`;
        
        if (data) {
            const dataElement = document.createElement('pre');
            dataElement.style.margin = '5px 0 0 20px';
            dataElement.style.color = '#aaa';
            dataElement.textContent = JSON.stringify(data, null, 2);
            entry.appendChild(dataElement);
        }
        
        debugContent.appendChild(entry);
        debugContent.scrollTop = debugContent.scrollHeight;
    }

    function backToDashboard() {
        toggleDebugConsole();
    }

    // ==================== GLOBAL FUNCTION EXPORTS ====================
    // These functions need to be available in the global scope for HTML onclick handlers
    window.showApprovalTermsModal = showApprovalTermsModal;
    window.showRejectionModal = showRejectionModal;
    window.forceCompleteLoan = forceCompleteLoan;
    window.showRecordPaymentModal = showRecordPaymentModal;
    window.updateCustomerLimit = updateCustomerLimit;
    window.viewCustomerProfile = viewCustomerProfile;
    window.viewCustomerLoan = viewCustomerLoan;
    window.showLoanDetails = showLoanDetails;
    window.backToCustomerSearch = backToCustomerSearch;
    window.backToDashboard = backToDashboard;

    // Confirm approval button handler
    document.getElementById('confirm-approval-btn').addEventListener('click', function() {
        const loanId = this.getAttribute('data-loan-id');
        const interestRate = parseFloat(document.getElementById('interestRate').value);
        const repaymentPeriod = parseInt(document.getElementById('repaymentPeriod').value);
        const adminNotes = document.getElementById('adminNotes').value;
        
        if (isNaN(interestRate) || interestRate <= 0 || interestRate > 30) {
            alert('Please enter a valid interest rate between 1 and 30');
            return;
        }
        
        if (isNaN(repaymentPeriod) || repaymentPeriod < 7 || repaymentPeriod > 90) {
            alert('Please enter a valid repayment period between 7 and 90 days');
            return;
        }
        
        approveLoan(loanId, {
            interestRate,
            repaymentPeriod,
            adminNotes
        });
    });

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

    // Hide loans button handler
    document.getElementById('hide-loans-btn').addEventListener('click', showDashboard);

    // Initialize custom date range visibility
    document.getElementById('customDateRange').style.display = 'none';
});