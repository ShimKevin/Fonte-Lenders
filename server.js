require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const path = require('path');
const axios = require('axios');
const crypto = require('crypto');
const http = require('http');
const { Server } = require('socket.io');
const Joi = require('joi');

const app = express();
const PORT = process.env.PORT || 3001;
const server = http.createServer(app);

// ==================== SOCKET.IO SETUP ====================
const io = new Server(server, {
  cors: {
    origin: [
      'http://localhost:3000',
      'http://localhost:3000/admin',
      'https://fonte-lenders.onrender.com'
    ],
    methods: ['GET', 'POST'],
    credentials: true
  }
});

io.on('connection', (socket) => {
  console.log(`⚡️ Socket connected: ${socket.id}`);

  socket.on('disconnect', () => {
    console.log(`🔌 Socket disconnected: ${socket.id}`);
  });

  socket.on('joinAdminRoom', () => {
    socket.join('adminRoom');
    console.log(`👑 Admin joined admin room: ${socket.id}`);
  });

  socket.on('joinUserRoom', (userId) => {
    socket.join(`user_${userId}`);
    console.log(`👤 User ${userId} joined room`);
  });

  // ==================== REAL-TIME UPDATE HANDLERS ====================
  socket.on('limitUpdated', (data) => {
    console.log(`📈 Limit update for user ${data.userId}: ${data.newLimit}`);
    io.to(`user_${data.userId}`).emit('limitUpdate', {
      newLimit: data.newLimit
    });
  });

  socket.on('loanApproved', (data) => {
    console.log(`✅ Loan approved for user ${data.userId}: ${data.loanId}`);
    io.to(`user_${data.userId}`).emit('loanApproved', data);
  });

  socket.on('paymentApproved', (data) => {
    console.log(`💰 Payment approved for user ${data.userId}: ${data.amount}`);
    io.to(`user_${data.userId}`).emit('paymentApproved', data);
  });

  socket.on('forceCompleteLoan', (data) => {
    console.log(`🏁 Loan force completed for user ${data.userId}: ${data.loanId}`);
    io.to(`user_${data.userId}`).emit('loanCompleted', data);
  });

  // ==================== LOAN APPROVAL HANDLERS ====================
  socket.on('loanApproval', (data) => {
    console.log(`🔔 Received loan approval request for ${data.loanId}`);
    console.log(`📋 Terms: ${data.interestRate}%, ${data.repaymentPeriod} days`);

    // Notify all admins about new approval request
    io.to('adminRoom').emit('loanApprovalRequest', {
      loanId: data.loanId,
      adminId: data.adminId,
      interestRate: data.interestRate,
      repaymentPeriod: data.repaymentPeriod
    });
  });

  socket.on('loanRejection', (data) => {
    console.log(`🚫 Received loan rejection for ${data.loanId}: ${data.reason}`);

    // Notify all admins about rejection
    io.to('adminRoom').emit('loanRejectionRequest', {
      loanId: data.loanId,
      adminId: data.adminId,
      reason: data.reason
    });
  });

  // ==================== PAYMENT SUBMISSION HANDLER ====================
  socket.on('paymentSubmitted', (data) => {
    console.log(`💸 New payment submitted by ${data.fullName}: ${data.reference} for KES ${data.amount}`);
    io.to('adminRoom').emit('newPayment', {
      paymentId: data.paymentId,
      userId: data.userId,
      fullName: data.fullName,
      amount: data.amount,
      reference: data.reference,
      timestamp: new Date()
    });
  });

  // ==================== PAYMENT APPROVAL HANDLER ====================
  socket.on('paymentApproved', (data) => {
    console.log(`💳 Payment approved for user ${data.userId}: ${data.amount}`);
    io.to(`user_${data.userId}`).emit('paymentApproved', {
      amount: data.amount,
      loanId: data.loanId,
      newBalance: data.newBalance
    });
  });
});

// ==================== MONGODB CONNECTION ====================
const MONGODB_URI = process.env.MONGODB_URI || "mongodb+srv://kevinshimanjala:FonteLenders%40254@cluster0.g2bzscn.mongodb.net/fonte_lenders?retryWrites=true&w=majority&appName=Cluster0";

const mongooseOptions = {
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 30000,
  connectTimeoutMS: 5000,
  retryWrites: true,
  retryReads: true,
  maxPoolSize: 10,
  ssl: true,
  tlsAllowInvalidCertificates: false
};

const connectWithRetry = async (attempt = 1) => {
  try {
    console.log(`⌛ Attempting MongoDB connection (attempt ${attempt})...`);
    await mongoose.connect(MONGODB_URI, mongooseOptions);
    console.log('✅ MongoDB connected successfully');
    return true;
  } catch (err) {
    console.error('❌ MongoDB connection error:', err.message);
    
    if (attempt < 3) {
      console.log(`🔄 Retrying in 5 seconds...`);
      await new Promise(resolve => setTimeout(resolve, 5000));
      return connectWithRetry(attempt + 1);
    }
    
    console.error('💥 Failed to connect after 3 attempts');
    return false;
  }
};

// ==================== JENGA API INTEGRATION ====================
const JENGA_API_KEY = process.env.JENGA_API_KEY;
const JENGA_API_URL = process.env.JENGA_API_URL || 'https://sandbox.jengahq.io';

async function verifyIDWithJenga(idNumber, fullName) {
  try {
    if (process.env.NODE_ENV === 'development' && process.env.USE_MOCK_VERIFICATION === 'true') {
      console.log('Using mock ID verification for development');
      return {
        success: true,
        verifiedBy: 'mock',
        message: 'Mock verification successful',
        timestamp: new Date().toISOString()
      };
    }

    if (!JENGA_API_KEY) {
      console.error('Jenga API key not configured');
      throw new Error('Jenga API key not configured');
    }

    try {
      await axios.head(JENGA_API_URL, { timeout: 5000 });
    } catch (reachabilityError) {
      console.error('Jenga API endpoint not reachable:', reachabilityError.message);
      if (process.env.ENABLE_FALLBACK_VERIFICATION === 'true') {
        return {
          success: true,
          verifiedBy: 'fallback',
          message: 'Verification pending manual review (API unreachable)',
          fallback: true,
          timestamp: new Date().toISOString()
        };
      }
      throw new Error('Jenga API endpoint not reachable');
    }

    const response = await axios.post(
      `${JENGA_API_URL}/identity/v2/verify`,
      {
        idNumber: idNumber,
        fullName: fullName
      },
      {
        headers: {
          'Authorization': `Bearer ${JENGA_API_KEY}`,
          'Content-Type': 'application/json'
        },
        timeout: 10000
      }
    );

    if (response.data && response.data.success) {
      return {
        success: true,
        verifiedBy: 'jenga',
        message: 'Verification successful',
        timestamp: response.data.timestamp,
        rawResponse: response.data
      };
    } else {
      return {
        success: false,
        verifiedBy: 'jenga',
        message: response.data?.message || 'Verification failed',
        timestamp: new Date().toISOString(),
        rawResponse: response.data
      };
    }
  } catch (error) {
    console.error('Jenga verification error:', error.message);
    
    if (error.code === 'ENOTFOUND') {
      console.error('DNS resolution failed for Jenga API endpoint');
      if (process.env.ENABLE_FALLBACK_VERIFICATION === 'true') {
        return {
          success: true,
          verifiedBy: 'fallback',
          message: 'Verification pending manual review (DNS resolution failed)',
          fallback: true,
          timestamp: new Date().toISOString()
        };
      }
      throw new Error('Jenga API endpoint could not be resolved');
    }
    
    if (process.env.ENABLE_FALLBACK_VERIFICATION === 'true') {
      console.log('Attempting fallback verification...');
      return {
        success: true,
        verifiedBy: 'fallback',
        message: 'Verification pending manual review',
        fallback: true,
        timestamp: new Date().toISOString()
      };
    }
    
    throw error;
  }
}

// ==================== MODELS ====================
const paymentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'Customer', required: true },
  loanId: { type: mongoose.Schema.Types.ObjectId, ref: 'LoanApplication', required: true },
  amount: { type: Number, required: true },
  paymentMethod: { type: String, required: true, enum: ['M-Pesa Paybill', 'Bank Transfer', 'Cash'] },
  reference: { type: String, required: true },
  transactionId: String,
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected'], 
    default: 'pending' 
  },
  paymentDetails: Object,
  completedAt: Date,
  paymentDate: { type: Date, default: Date.now }
}, { timestamps: true });

const loanApplicationSchema = new mongoose.Schema({
  customerId: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'Customer', required: true },
  fullName: { type: String, required: true },
  phoneNumber: { type: String, required: true },
  email: String,
  amount: { type: Number, required: true, min: 1000, max: 300000 },
  amountPaid: { type: Number, default: 0 },
  purpose: String,
  guarantor: {
    name: { type: String, required: true },
    idNumber: { type: String, required: true },
    phoneNumber: { type: String, required: true },
    relationship: { type: String, default: 'Personal' }
  },
  signature: { type: String, required: true },
  verificationStatus: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'active', 'completed'], default: 'pending' },
  adminNotes: String,
  verificationData: Object,
  dueDate: Date,
  approvedAt: Date,
  rejectedAt: Date,
  paymentDetails: {
    mode: { type: String, enum: ['M-Pesa'], default: 'M-Pesa' },
    mpesaNumber: String,
    bankAccount: {
      bankName: String,
      accountNumber: String,
      accountName: String
    }
  },
  repaymentSchedule: [{
    dueDate: Date,
    amount: Number,
    paidAmount: { type: Number, default: 0 }, // Track partial payments
    status: { 
      type: String, 
      enum: ['pending', 'paid', 'overdue', 'partial'], // Added 'partial'
      default: 'pending' 
    },
    paidAt: Date
  }],
  totalAmount: { type: Number } // Total amount including interest
}, { timestamps: true });

// Add indexes for frequent queries
loanApplicationSchema.index({ userId: 1, status: 1 });
paymentSchema.index({ userId: 1, status: 1 });

const customerSchema = new mongoose.Schema({
  customerId: { type: String, unique: true, required: true },
  fullName: { type: String, required: true },
  phoneNumber: { type: String, unique: true, required: true },
  email: { type: String, unique: true, sparse: true },
  password: { type: String, required: true, select: false },
  maxLoanLimit: { type: Number, default: 300000, min: 0 },
  currentLoanBalance: { type: Number, default: 0, min: 0 },
  verificationStatus: { type: String, default: 'pending', enum: ['pending', 'verified', 'rejected'] },
  creditScore: { type: Number, default: 500, min: 300, max: 850 },
  lastLogin: Date,
  paymentPreferences: {
    mode: { 
      type: String, 
      enum: ['M-Pesa Paybill'],
      default: 'M-Pesa Paybill' 
    },
    paybillDetails: {
      paybillNumber: { 
        type: String, 
        default: '522533',
        immutable: true
      },
      accountNumber: { 
        type: String, 
        default: '7883032',
        immutable: true 
      }
    },
    mpesaNumber: String
  },
  activeLoan: { type: mongoose.Schema.Types.ObjectId, ref: 'LoanApplication' }
}, { timestamps: true });

const adminSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true, select: false },
  role: { type: String, enum: ['admin', 'superadmin'], default: 'admin' },
  lastLogin: Date
}, { timestamps: true });

const tokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'Customer' },
  token: { type: String, required: true },
  expiresAt: { type: Date, required: true, index: { expires: '7d' } },
  purpose: { type: String, enum: ['refresh', 'password_reset'], default: 'refresh' }
});

// ==================== SCHEMA HOOKS AND METHODS ====================
customerSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

customerSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

adminSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
  }
  next();
});

adminSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const Payment = mongoose.model('Payment', paymentSchema);
const LoanApplication = mongoose.model('LoanApplication', loanApplicationSchema);
const Customer = mongoose.model('Customer', customerSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Token = mongoose.model('Token', tokenSchema);

// ==================== CONFIGURATION ====================
if (!process.env.JWT_SECRET) {
  console.error('FATAL ERROR: JWT_SECRET is not defined.');
  process.exit(1);
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==================== MIDDLEWARE ====================
app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://localhost:3000/admin',
    'https://fonte-lenders.onrender.com'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  res.jsonResponse = (data, status = 200) => {
    res.status(status).json({
      success: status >= 200 && status < 300,
      ...data
    });
  };
  next();
});

app.use((req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET, {
        ignoreExpiration: false,
        algorithms: ['HS256']
      });
      
      req.authenticatedUser = decoded.id.toString();
      console.log(`✅ Valid token for: ${req.authenticatedUser} (Route: ${req.path})`);
    } catch (error) {
      console.error(`❌ Token verification failed for ${req.path}: ${error.name} - ${error.message}`);
      req.tokenError = error;
    }
  }
  
  next();
});

const loginAttempts = new Map();

const loginRateLimiter = (req, res, next) => {
  if (req.path === '/api/login' && req.method === 'POST') {
    const key = `${req.ip}-${req.body.phone}`;
    const now = Date.now();
    
    if (loginAttempts.has(key)) {
      const lastAttempt = loginAttempts.get(key);
      if (now - lastAttempt < 2000) {
        return res.status(429).json({
          success: false,
          code: 'TOO_MANY_REQUESTS',
          redirect: '/login?error=rate_limit'
        });
      }
    }
    
    loginAttempts.set(key, now);
    setTimeout(() => loginAttempts.delete(key), 2000);
  }
  next();
};

const authenticate = async (req, res, next) => {
  if (!req.authenticatedUser) {
    const error = req.tokenError || new Error('Missing authentication');
    return handleAuthError(error, res);
  }

  try {
    const user = await Customer.findById(req.authenticatedUser).select('-password').lean();
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        code: 'USER_NOT_FOUND',
        redirect: '/login?error=user_not_found'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    handleAuthError(error, res);
  }
};

const authenticateAdmin = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ 
      success: false, 
      code: 'MISSING_TOKEN',
      redirect: '/admin/login?error=missing_token'
    });
  }

  const token = authHeader.split(' ')[1];
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      ignoreExpiration: false,
      algorithms: ['HS256']
    });
    
    const admin = await Admin.findById(decoded.id).select('-password').lean();
    
    if (!admin) {
      return res.status(401).json({ 
        success: false, 
        code: 'ADMIN_NOT_FOUND',
        redirect: '/admin/login?error=admin_not_found'
      });
    }

    req.admin = admin;
    next();
  } catch (error) {
    console.error('❌ Admin auth error:', error.name, '-', error.message);
    
    const response = {
      success: false,
      code: 'ADMIN_AUTH_FAILED',
      redirect: '/admin/login?error=auth_failed'
    };

    if (error.name === 'TokenExpiredError') {
      response.code = 'TOKEN_EXPIRED';
      response.redirect = '/admin/login?error=token_expired';
    } else if (error.name === 'JsonWebTokenError') {
      response.code = 'INVALID_TOKEN';
      response.redirect = '/admin/login?error=invalid_token';
    }

    return res.status(401).json(response);
  }
};

const handleAuthError = (error, res) => {
  console.error('❌ Authentication error:', error.name, '-', error.message);
  
  const errorResponse = {
    success: false,
    code: 'AUTH_FAILED',
    redirect: '/login?error=auth_failed'
  };

  if (error.name === 'TokenExpiredError') {
    errorResponse.code = 'TOKEN_EXPIRED';
    errorResponse.redirect = '/login?error=token_expired';
  } else if (error.name === 'JsonWebTokenError') {
    errorResponse.code = 'INVALID_TOKEN';
    errorResponse.redirect = '/login?error=invalid_token';
  }

  return res.status(401).json(errorResponse);
};

app.use(loginRateLimiter);

// ==================== EMAIL SERVICE ====================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

async function sendEmail(options) {
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      ...options
    });
    console.log('Email sent to:', options.to);
    return true;
  } catch (error) {
    console.error('Email error:', error);
    return false;
  }
}

// ==================== JOI VALIDATION SCHEMAS ====================
const paymentSchemaJoi = Joi.object({
  reference: Joi.string().required().pattern(/[a-zA-Z0-9]{8,}/),
  amount: Joi.number().required().min(100).max(1000000)
});

// ==================== ROUTES ====================

// ==================== ADMIN ROUTES ====================
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'), (err) => {
    if (err) {
      console.error('Admin panel delivery error:', err);
      res.jsonResponse({
        success: false,
        message: 'Admin panel not found',
        code: 'ADMIN_PANEL_NOT_FOUND'
      }, 404);
    }
  });
});

app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (!username || !password) {
      console.warn(`Login attempt with missing credentials from IP: ${clientIP}`);
      return res.status(400).json({
        success: false,
        code: 'MISSING_CREDENTIALS',
        message: 'Both username and password are required',
        clientIP
      });
    }

    const normalizedUsername = username.trim().toLowerCase();
    console.log(`Admin login attempt from IP: ${clientIP}, Username: ${normalizedUsername}`);

    const admin = await Admin.findOne({ 
      username: { $regex: new RegExp(`^${normalizedUsername}$`, 'i') }
    }).select('+password');

    if (!admin || !(await admin.comparePassword(password))) {
      console.warn(`Invalid credentials for: ${normalizedUsername} from IP: ${clientIP}`);
      return res.status(401).json({
        success: false,
        code: 'INVALID_CREDENTIALS',
        message: 'Invalid username or password',
        clientIP
      });
    }

    const token = jwt.sign({
      id: admin._id.toString(),
      role: admin.role,
      username: admin.username
    }, process.env.JWT_SECRET, {
      expiresIn: '8h',
      algorithm: 'HS256'
    });

    admin.lastLogin = new Date();
    await admin.save();

    res.json({
      success: true,
      token,
      admin: {
        id: admin._id,
        username: admin.username,
        role: admin.role,
        lastLogin: admin.lastLogin
      }
    });

  } catch (error) {
    console.error('❌ Admin login error:', error);
    res.status(500).json({
      success: false,
      code: 'LOGIN_FAILED',
      message: 'Authentication service unavailable. Please try again later.',
      systemError: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

app.get('/api/admin/metrics', authenticateAdmin, async (req, res) => {
  try {
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

    const [totalCustomers, activeLoans, pendingApplications, overdueLoans, weeklyApplications, payments] = await Promise.all([
      Customer.countDocuments(),
      LoanApplication.countDocuments({ status: 'active' }),
      LoanApplication.countDocuments({ status: 'pending' }),
      LoanApplication.countDocuments({ status: 'active', dueDate: { $lt: new Date() } }),
      LoanApplication.countDocuments({ createdAt: { $gte: oneWeekAgo } }),
      Payment.aggregate([
        { $match: { completedAt: { $gte: oneWeekAgo } } },
        { $group: { _id: null, total: { $sum: "$amount" } } }
      ])
    ]);

    res.json({
      success: true,
      data: {
        totalCustomers,
        activeLoans,
        pendingApplications,
        overdueLoans,
        weeklyApplications,
        weeklyPayments: payments[0]?.total || 0
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Metrics error:', error);
    res.status(500).json({
      success: false,
      code: 'METRICS_ERROR',
      message: 'Failed to load system metrics',
      systemError: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

app.get('/api/admin/validate-token', authenticateAdmin, (req, res) => {
  console.log('Token validation successful for admin:', req.admin.username);
  
  const adminResponse = {
    ...req.admin,
    id: req.admin._id.toString(),
    _id: req.admin._id.toString()
  };

  res.json({ 
    success: true, 
    admin: adminResponse
  });
});

// ==================== UPDATED CUSTOMER SEARCH ====================
app.get('/api/admin/customers', authenticateAdmin, async (req, res) => {
  try {
    const { search } = req.query;
    const filter = search ? {
      $or: [
        { customerId: search },
        { fullName: new RegExp(search, 'i') },
        { phoneNumber: search }
      ]
    } : {};

    // Return all matching customers without pagination
    const customers = await Customer.find(filter)
      .select('-password -__v')
      .lean();

    res.json({
      success: true,
      customers
    });
  } catch (error) {
    console.error('Customers fetch error:', error);
    res.status(500).json({ 
      success: false, 
      code: 'CUSTOMERS_ERROR', 
      message: 'Failed to fetch customers' 
    });
  }
});

// Get customer details including active loan
app.get('/api/admin/customers/:id', authenticateAdmin, async (req, res) => {
  try {
    const customer = await Customer.findById(req.params.id)
      .select('-password')
      .populate('activeLoan')
      .lean();

    if (!customer) {
      return res.status(404).json({
        success: false,
        message: 'Customer not found'
      });
    }

    res.json({
      success: true,
      customer
    });
  } catch (error) {
    console.error('Customer details error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get customer details'
    });
  }
});

// ==================== UPDATE CUSTOMER LIMIT ENDPOINT ====================
app.put('/api/admin/customers/:id/limit', authenticateAdmin, async (req, res) => {
  try {
    const { newLimit } = req.body;
    const numericLimit = Number(newLimit);
    
    if (isNaN(numericLimit) || numericLimit < 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Valid loan limit (non-negative number) is required' 
      });
    }

    const customer = await Customer.findById(req.params.id);
    if (!customer) {
      return res.status(404).json({ 
        success: false, 
        message: 'Customer not found' 
      });
    }

    const previousLimit = customer.maxLoanLimit;
    customer.maxLoanLimit = numericLimit;
    await customer.save();

    // Notify user
    io.to(`user_${customer._id}`).emit('loanLimitUpdate', {
      newLimit: customer.maxLoanLimit,
      updatedAt: new Date()
    });

    // Notify admin with enhanced details
    io.to('adminRoom').emit('customerUpdate', {
      customerId: customer._id,
      fullName: customer.fullName,
      phoneNumber: customer.phoneNumber,
      updateType: 'loanLimit',
      previousLimit,
      newLimit: customer.maxLoanLimit,
      updatedAt: new Date()
    });

    res.json({ 
      success: true, 
      message: 'Loan limit updated successfully', 
      newLimit: customer.maxLoanLimit 
    });
  } catch (error) {
    console.error('Update loan limit error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to update loan limit' 
    });
  }
});

app.get('/api/admin/loan-applications', authenticateAdmin, async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    
    const query = {};
    if (status) query.status = status;
    
    const applications = await LoanApplication.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .lean();

    const count = await LoanApplication.countDocuments(query);

    res.jsonResponse({
      success: true,
      applications,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count,
        pages: Math.ceil(count / limit)
      }
    });
  } catch (error) {
    console.error('Error fetching loan applications:', error);
    res.jsonResponse({
      success: false,
      message: 'Failed to fetch loan applications',
      code: 'LOAN_APPLICATIONS_FETCH_ERROR'
    }, 500);
  }
});

app.get('/api/admin/loan-applications/:id', authenticateAdmin, async (req, res) => {
  try {
    const loan = await LoanApplication.findById(req.params.id)
      .populate('userId', 'fullName phoneNumber')
      .lean();

    if (!loan) {
      return res.status(404).json({ 
        success: false, 
        message: 'Loan application not found' 
      });
    }

    res.json({
      success: true,
      loan
    });
  } catch (error) {
    console.error('Loan details error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to load loan details'
    });
  }
});

// ==================== LOAN APPROVAL ENDPOINT (UPDATED) ====================
app.patch('/api/admin/loan-applications/:id/approve', authenticateAdmin, async (req, res) => {
  try {
    const { interestRate, repaymentPeriod, adminNotes } = req.body;
    
    // Validate inputs
    if (!interestRate || !repaymentPeriod) {
      return res.status(400).json({
        success: false,
        message: 'Interest rate and repayment period are required'
      });
    }

    const loan = await LoanApplication.findById(req.params.id)
      .populate('userId', 'fullName phoneNumber email');
    
    if (!loan) {
      return res.status(404).json({
        success: false,
        message: 'Loan application not found'
      });
    }

    if (loan.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Loan is not in pending status'
      });
    }

    // Calculate loan details
    const principal = loan.amount;
    const interestAmount = principal * (interestRate / 100);
    const totalAmount = principal + interestAmount;
    
    // Set due date (repaymentPeriod in days)
    const dueDate = new Date();
    dueDate.setDate(dueDate.getDate() + parseInt(repaymentPeriod));

    // Create repayment schedule
    const repaymentSchedule = [{
      dueDate: dueDate,
      amount: totalAmount,
      status: 'pending'
    }];

    // Update loan details
    loan.status = 'active';
    loan.approvedAt = new Date();
    loan.adminNotes = adminNotes;
    loan.principal = principal;          // Set explicitly
    loan.interestRate = interestRate;
    loan.interestAmount = interestAmount; // Set explicitly
    loan.totalAmount = totalAmount;       // Set explicitly
    loan.dueDate = dueDate;
    loan.repaymentSchedule = repaymentSchedule;

    // Update customer
    const customer = await Customer.findById(loan.userId);
    customer.currentLoanBalance += principal;
    customer.activeLoan = loan._id;

    await Promise.all([loan.save(), customer.save()]);

    // Notify admins
    io.to('adminRoom').emit('loanApproved', {
      loanId: loan._id,
      adminName: req.admin.username,
      principal: principal,
      interestRate: interestRate,
      totalAmount: totalAmount,
      dueDate: dueDate,
      customerId: customer._id,
      customerName: customer.fullName
    });

    // Notify user
    io.to(`user_${customer._id}`).emit('loanApproved', {
      loanId: loan._id,
      principal: principal,
      interestRate: interestRate,
      totalAmount: totalAmount,
      dueDate: dueDate
    });

    // Send approval email
    if (customer.email) {
      await sendEmail({
        to: customer.email,
        subject: 'Loan Approved',
        html: `
          <h2>Loan Approved!</h2>
          <p>Your loan request has been approved. Below are the details:</p>
          
          <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Principal Amount</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">KES ${principal.toLocaleString()}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Interest Rate</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${interestRate}%</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Interest Amount</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">KES ${interestAmount.toLocaleString()}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Total Repayable</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">KES ${totalAmount.toLocaleString()}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Due Date</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${dueDate.toLocaleDateString()}</td>
            </tr>
          </table>
          
          <p><strong>Repayment Instructions:</strong></p>
          <p>Paybill: 522533</p>
          <p>Account: 7883032</p>
        `
      });
    }

    // Return updated response with customer details
    res.json({
      success: true,
      data: {
        loan: {
          _id: loan._id,
          principal: loan.principal,         // From updated loan object
          interestAmount: loan.interestAmount, // From updated loan object
          totalAmount: loan.totalAmount,       // From updated loan object
          dueDate: loan.dueDate
        },
        customer: {
          _id: customer._id,
          currentLoanBalance: customer.currentLoanBalance
        }
      }
    });

  } catch (error) {
    console.error('Loan approval error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to approve loan'
    });
  }
});

// ==================== LOAN REJECTION ENDPOINT ====================
app.patch('/api/admin/loan-applications/:id/reject', authenticateAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    
    const loan = await LoanApplication.findById(req.params.id)
      .populate('userId', 'fullName phoneNumber email');
    
    if (!loan) {
      return res.status(404).json({
        success: false,
        message: 'Loan application not found'
      });
    }

    if (loan.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Loan is not in pending status'
      });
    }

    loan.status = 'rejected';
    loan.rejectedAt = new Date();
    loan.adminNotes = reason;

    await loan.save();

    // Notify user
    const customer = loan.userId;
    if (customer) {
      io.to(`user_${customer._id}`).emit('loanRejected', {
        loanId: loan._id,
        reason
      });
      
      if (customer.email) {
        await sendEmail({
          to: customer.email,
          subject: 'Loan Application Rejected',
          html: `<p>Your loan application has been rejected. Reason: ${reason}</p>`
        });
      }
    }

    res.json({
      success: true,
      message: 'Loan rejected successfully'
    });
    
  } catch (error) {
    console.error('Loan rejection error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reject loan'
    });
  }
});

app.get('/api/admin/reports/:type', authenticateAdmin, async (req, res) => {
  try {
    const { type } = req.params;
    res.json({
      success: true,
      data: {
        title: `${type} Report`,
        startDate: new Date().toISOString(),
        endDate: new Date().toISOString(),
        totalLoans: 0,
        newCustomers: 0,
        repaymentsReceived: 0,
        defaultRate: 0
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Report generation failed' });
  }
});

app.get('/api/admin/pending-payments', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.query;
    const filter = status ? { status } : { status: 'pending' }; // Default to pending
    
    const payments = await Payment.find(filter)
      .populate('userId', 'fullName phoneNumber') // ADDED USER DETAILS
      .populate('loanId', 'amount amountPaid')
      .sort({ createdAt: -1 });
      
    res.json({
      success: true,
      payments
    });
    
  } catch (error) {
    console.error('Payments fetch error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch payments'
    });
  }
});

app.get('/api/admin/profile', authenticateAdmin, async (req, res) => {
  try {
    if (!req.admin) {
      return res.status(404).json({ 
        success: false, 
        message: 'Admin not found' 
      });
    }
    
    res.json({ 
      success: true, 
      data: req.admin 
    });
  } catch (error) {
    console.error('Admin fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch admin data' 
    });
  }
});

// ==================== PAYMENT SUBMISSION ROUTE ====================
app.post('/api/payments/submit', authenticate, async (req, res) => {
  try {
    const { error } = paymentSchemaJoi.validate(req.body);
    if (error) return res.status(400).json({ 
      success: false, 
      message: error.details[0].message 
    });
    
    const user = await Customer.findById(req.user._id);
    if (!user) return res.status(404).json({ 
      success: false, 
      message: 'User not found' 
    });

    const activeLoan = await LoanApplication.findOne({
      userId: user._id,
      status: 'active'
    });
    
    if (!activeLoan) return res.status(400).json({ 
      success: false, 
      message: 'No active loan found' 
    });

    const { reference, amount } = req.body;
    
    // Get total remaining amount (including interest)
    const totalRemaining = activeLoan.totalAmount - (activeLoan.amountPaid || 0);
    
    if (amount > totalRemaining) {
      return res.status(400).json({
        success: false,
        message: `Payment exceeds loan balance. Maximum payment: KES ${totalRemaining.toLocaleString()}`
      });
    }

    // Create payment record with user details
    const paymentRecord = new Payment({
      userId: user._id,
      loanId: activeLoan._id,
      amount: amount,
      paymentMethod: 'M-Pesa Paybill',
      reference: reference,
      status: 'pending',
      userDetails: {
        fullName: user.fullName,
        phoneNumber: user.phoneNumber,
        customerId: user.customerId
      }
    });

    await paymentRecord.save();

    // NOTIFY ADMINS VIA SOCKET WITH USER DETAILS
    io.emit('paymentSubmitted', {
      paymentId: paymentRecord._id,
      userId: user._id,
      fullName: user.fullName,
      amount: amount,
      reference: reference,
      timestamp: new Date()
    });

    res.json({
      success: true,
      message: 'Payment submitted for admin approval',
      payment: paymentRecord
    });

  } catch (error) {
    console.error('Payment submission error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit payment'
    });
  }
});

app.patch('/api/admin/payments/:id/approve', authenticateAdmin, async (req, res) => {
  try {
    const payment = await Payment.findById(req.params.id)
      .populate('userId')
      .populate('loanId');
    
    if (!payment) {
      return res.status(404).json({ 
        success: false, 
        message: 'Payment not found' 
      });
    }

    if (payment.status === 'approved') {
      return res.status(400).json({
        success: false,
        message: 'Payment already approved'
      });
    }

    const loan = payment.loanId;
    const customer = payment.userId;
    const paymentAmount = payment.amount;
    
    // Update loan amount paid
    loan.amountPaid = (loan.amountPaid || 0) + paymentAmount;
    
    // Apply payment to installments
    let remainingAmount = paymentAmount;
    for (const installment of loan.repaymentSchedule) {
      // Only process pending installments
      if (['pending', 'partial'].includes(installment.status) && remainingAmount > 0) {
        // Calculate remaining due for this installment
        const installmentDue = installment.amount - (installment.paidAmount || 0);
        const amountToApply = Math.min(remainingAmount, installmentDue);
        
        // Update paid amount
        installment.paidAmount = (installment.paidAmount || 0) + amountToApply;
        installment.paidAt = new Date();
        
        // Update status
        if (installment.paidAmount >= installment.amount) {
          installment.status = 'paid';
        } else if (amountToApply > 0) {
          installment.status = 'partial';
        }
        
        remainingAmount -= amountToApply;
        
        // Stop processing if payment is exhausted
        if (remainingAmount <= 0) break;
      }
    }
    
    // Check if loan is fully paid
    if (loan.amountPaid >= loan.totalAmount) {
      loan.status = 'completed';
      customer.activeLoan = null;
      
      // Notify user
      io.to(`user_${customer._id}`).emit('loanCompleted', {
        loanId: loan._id,
        amountPaid: paymentAmount
      });
    }
    
    // Update customer balance
    customer.currentLoanBalance = Math.max(0, customer.currentLoanBalance - paymentAmount);
    
    // Update payment status
    payment.status = 'approved';
    payment.completedAt = new Date();
    payment.approvedBy = req.admin.username;
    
    await Promise.all([loan.save(), customer.save(), payment.save()]);
    
    // Notify user
    io.to(`user_${customer._id}`).emit('paymentApproved', {
      amount: paymentAmount,
      newBalance: customer.currentLoanBalance,
      loanId: loan._id,
      isFullyPaid: loan.status === 'completed'
    });
    
    // Send confirmation email
    if (customer.email) {
      await sendEmail({
        to: customer.email,
        subject: 'Payment Approved',
        html: `
          <p>Your payment of KES ${payment.amount.toLocaleString()} has been approved.</p>
          ${loan.status === 'completed' 
            ? '<p>Your loan has been fully paid!</p>' 
            : `<p>New loan balance: KES ${customer.currentLoanBalance.toLocaleString()}</p>`}
        `
      });
    }
    
    res.json({
      success: true,
      data: {
        userId: customer._id,
        loanId: loan._id,
        amount: paymentAmount,
        newBalance: customer.currentLoanBalance
      }
    });
    
  } catch (error) {
    console.error('Payment approval error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to approve payment',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

app.patch('/api/admin/payments/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const payment = await Payment.findById(req.params.id)
      .populate('userId')
      .populate('loanId');
    
    if (!payment) return res.status(404).json({ 
      success: false, 
      message: 'Payment not found' 
    });

    if (payment.status === 'approved') {
      return res.status(400).json({
        success: false,
        message: 'Payment already approved'
      });
    }

    if (status === 'approved') {
      const loan = payment.loanId;
      const user = payment.userId;
      
      // Update loan
      loan.amountPaid = (loan.amountPaid || 0) + payment.amount;
      
      // Add to repayment schedule
      loan.repaymentSchedule.push({
        dueDate: new Date(),
        amount: payment.amount,
        status: 'paid',
        paidAt: new Date()
      });
      
      // Check if loan is fully paid
      if (loan.amountPaid >= loan.totalAmount) {
        loan.status = 'completed';
        user.activeLoan = null;
        
        // Notify user
        io.to(`user_${user._id}`).emit('loanCompleted', {
          loanId: loan._id,
          amountPaid: payment.amount
        });
      }
      
      // Update customer balance
      user.currentLoanBalance = Math.max(0, user.currentLoanBalance - payment.amount);
      
      // Update payment status
      payment.status = 'approved';
      payment.completedAt = new Date();
      
      await Promise.all([loan.save(), user.save(), payment.save()]);
      
      // Notify user
      io.to(`user_${user._id}`).emit('paymentApproved', {
        amount: payment.amount,
        newBalance: user.currentLoanBalance,
        reference: payment.reference
      });
      
      // Send confirmation email
      if (user.email) {
        await sendEmail({
          to: user.email,
          subject: 'Payment Approved',
          html: `<p>Your payment of KES ${payment.amount} has been approved. New balance: KES ${user.currentLoanBalance}</p>`
        });
      }
      
      res.json({
        success: true,
        message: 'Payment approved successfully',
        newBalance: user.currentLoanBalance
      });
      
    } else if (status === 'rejected') {
      payment.status = 'rejected';
      await payment.save();
      
      res.json({
        success: true,
        message: 'Payment rejected'
      });
    } else {
      res.status(400).json({
        success: false,
        message: 'Invalid status'
      });
    }
    
  } catch (error) {
    console.error('Payment status update error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update payment status'
    });
  }
});

app.get('/api/admin/payments', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.query;
    const filter = status ? { status } : {};
    
    const payments = await Payment.find(filter)
      .populate('userId', 'fullName phoneNumber')
      .populate('loanId', 'amount amountPaid')
      .sort({ createdAt: -1 });
      
    res.json({
      success: true,
      payments
    });
    
  } catch (error) {
    console.error('Payments fetch error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch payments'
    });
  }
});

app.patch('/api/admin/loan-applications/:id/force-complete', authenticateAdmin, async (req, res) => {
  try {
    const loan = await LoanApplication.findById(req.params.id).populate('userId');
    if (!loan) {
      return res.status(404).json({ success: false, message: 'Loan not found' });
    }

    loan.status = 'completed';
    loan.amountPaid = loan.totalAmount;
    
    const customer = loan.userId;
    customer.currentLoanBalance = Math.max(0, customer.currentLoanBalance - (loan.totalAmount - (loan.amountPaid || 0)));
    customer.activeLoan = null;

    await Promise.all([loan.save(), customer.save()]);

    res.json({ 
      success: true,
      message: 'Loan force completed successfully',
      data: {
        userId: customer._id,
        amount: loan.amount,
        totalAmount: loan.totalAmount
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ==================== CUSTOMER AUTHENTICATION ====================
app.get('/debug/users', async (req, res) => {
  try {
    const users = await Customer.find({});
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const { fullName, idNumber, phone, email, password } = req.body;

    const cleanPassword = password.trim();
    const cleanPhone = phone.replace(/\D/g, '').trim();
    const cleanEmail = email ? email.trim() : null;
    const cleanFullName = fullName.trim();
    const cleanIdNumber = idNumber.trim();

    if (!cleanFullName || !cleanIdNumber || !cleanPhone || !cleanPassword) {
      return res.status(400).json({
        success: false,
        message: 'All required fields must be provided'
      });
    }

    if (cleanPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters'
      });
    }

    const existingUser = await Customer.findOne({ 
      $or: [
        { customerId: cleanIdNumber }, 
        { phoneNumber: cleanPhone }
      ] 
    });
    
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User already exists with this ID or phone number'
      });
    }

    const newCustomer = new Customer({
      fullName: cleanFullName,
      customerId: cleanIdNumber,
      phoneNumber: cleanPhone,
      email: cleanEmail,
      password: cleanPassword,
      verificationStatus: 'pending'
    });

    await newCustomer.save();

    console.log('New user created with hashed password:', {
      userId: newCustomer._id,
      passwordHash: newCustomer.password
    });

    const token = jwt.sign(
      { 
        id: newCustomer._id,
        phone: newCustomer.phoneNumber,
        customerId: newCustomer.customerId 
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
    );

    const refreshToken = crypto.randomBytes(40).toString('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    
    await Token.create({
      userId: newCustomer._id,
      token: refreshToken,
      expiresAt
    });

    const userData = newCustomer.toObject();
    delete userData.password;

    if (cleanEmail) {
      try {
        await sendEmail({
          to: cleanEmail,
          subject: 'Welcome to Fonte Lenders',
          html: `<h2>Welcome, ${cleanFullName}!</h2>
                 <p>Your registration with Fonte Lenders is complete.</p>
                 <p>You can now apply for loans through our platform.</p>`
        });
        console.log('Welcome email sent to:', cleanEmail);
      } catch (emailError) {
        console.error('Failed to send welcome email:', emailError);
      }
    }

    res.status(201).json({
      success: true,
      message: 'Registration successful',
      token,
      refreshToken,
      user: userData
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Registration failed. Please try again.',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    console.log('Login request body:', req.body);
    
    const { phone, password } = req.body;
    const cleanPhone = phone.replace(/\D/g, '').trim();
    const cleanPassword = password.trim();

    const user = await Customer.findOne({
      $or: [
        { phoneNumber: cleanPhone },
        { phoneNumber: `254${cleanPhone.substring(cleanPhone.length - 9)}` },
        { phoneNumber: `0${cleanPhone.substring(cleanPhone.length - 9)}` }
      ]
    }).select('+password');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const isMatch = await user.comparePassword(cleanPassword);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      { 
        id: user._id.toString()
      },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    const refreshToken = crypto.randomBytes(40).toString('hex');
    await Token.create({
      userId: user._id,
      token: refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });

    console.log('Generated Token:', token);
    console.log('Decoded Payload:', jwt.decode(token));

    const userData = user.toObject();
    delete userData.password;

    res.json({
      success: true,
      token,
      refreshToken,
      user: {
        _id: user._id.toString(),
        phone: user.phoneNumber,
        customerId: user.customerId
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed. Please try again.'
    });
  }
});

// ==================== UPDATED PROFILE ENDPOINT ====================
app.get('/api/user/profile', authenticate, async (req, res) => {
  try {
    const user = await Customer.findById(req.user._id)
      .populate({
        path: 'activeLoan',
        match: { status: 'active' },
        select: 'amount amountPaid dueDate repaymentSchedule status totalAmount'
      })
      .lean();

    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found'
      });
    }

    const availableLimit = user.maxLoanLimit - user.currentLoanBalance;
    const activeLoan = user.activeLoan;

    let loanDetails = null;
    if (activeLoan) {
      const now = new Date();
      const dueDate = new Date(activeLoan.dueDate);
      const daysRemaining = Math.ceil((dueDate - now) / 86400000);
      const totalPaid = activeLoan.amountPaid;
      const progress = (totalPaid / activeLoan.totalAmount) * 100;
      
      loanDetails = {
        amount: activeLoan.amount,
        totalAmount: activeLoan.totalAmount,
        amountPaid: totalPaid,
        amountRemaining: activeLoan.totalAmount - totalPaid,
        progress: Math.round(progress * 100) / 100,
        purpose: activeLoan.purpose,
        status: activeLoan.status,
        dueDate: dueDate.toISOString(),
        daysRemaining: Math.max(daysRemaining, 0),
        lastPayment: activeLoan.repaymentSchedule.slice(-1)[0]
      };
    }

    res.json({
      success: true,
      user: {
        ...user,
        availableLimit,
        password: undefined,
        __v: undefined
      },
      activeLoan: loanDetails
    });

  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to load profile'
    });
  }
});

// ==================== PASSWORD RESET ENDPOINTS ====================
app.post('/api/request-password-reset', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    const cleanEmail = email.trim();
    const user = await Customer.findOne({ email: cleanEmail });
    
    const response = {
      success: true,
      message: 'If this email is registered, you will receive a reset code shortly.'
    };

    if (user) {
      const token = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

      await Token.deleteMany({ 
        userId: user._id,
        purpose: 'password_reset'
      });

      const tokenDoc = await Token.create({
        userId: user._id,
        token,
        expiresAt,
        purpose: 'password_reset'
      });

      console.log(`Generated password reset token for ${user.email}:`, {
        tokenId: tokenDoc._id,
        token: token,
        expiresAt: expiresAt
      });

      const emailSent = await sendEmail({
        to: user.email,
        subject: 'Fonte Lenders - Password Reset Code',
        html: `
          <h2>Password Reset Request</h2>
          <p>You requested to reset your password for Fonte Lenders.</p>
          <p>Your verification code is: <strong>${token}</strong></p>
          <p>This code will expire in 15 minutes.</p>
          <p>If you didn't request this, please ignore this email.</p>
          <p style="margin-top: 20px; color: #888;">
            <em>Please check your spam folder if you don't see this email in your inbox.</em>
          </p>
        `
      });

      if (!emailSent) {
        console.error('Failed to send password reset email to:', user.email);
      }
    }

    res.json(response);

  } catch (error) {
    console.error('Password reset request error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process password reset request'
    });
  }
});

app.post('/api/verify-reset-token', async (req, res) => {
  try {
    const { email, token } = req.body;
    
    if (!email || !token) {
      return res.status(400).json({
        success: false,
        message: 'Email and token are required'
      });
    }

    const cleanEmail = email.trim();
    const cleanToken = token.trim();

    const user = await Customer.findOne({ email: cleanEmail });
    if (!user) {
      console.log(`User not found for email: ${cleanEmail}`);
      return res.status(400).json({
        success: false,
        message: 'Invalid request'
      });
    }

    const tokenDoc = await Token.findOne({ 
      userId: user._id,
      token: cleanToken,
      purpose: 'password_reset',
      expiresAt: { $gt: new Date() }
    });

    if (!tokenDoc) {
      console.log(`Invalid or expired token for user ${user._id}: ${cleanToken}`);
      const expiredToken = await Token.findOne({
        userId: user._id,
        token: cleanToken,
        purpose: 'password_reset'
      });
      
      if (expiredToken) {
        console.log('Found expired token, deleting it');
        await Token.deleteOne({ _id: expiredToken._id });
        return res.status(400).json({
          success: false,
          message: 'Verification code has expired. Please request a new one.'
        });
      }
      
      return res.status(400).json({
        success: false,
        message: 'Invalid verification code'
      });
    }

    console.log(`Valid token found for user ${user._id}`);

    res.json({
      success: true,
      message: 'Verification successful',
      resetToken: tokenDoc.token
    });

  } catch (error) {
    console.error('Token verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to verify code'
    });
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, token, newPassword, confirmPassword } = req.body;
    
    if (!email || !token || !newPassword || !confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }

    const cleanEmail = email.trim();
    const cleanToken = token.trim();
    const cleanNewPassword = newPassword.trim();
    const cleanConfirmPassword = confirmPassword.trim();

    if (cleanNewPassword !== cleanConfirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match'
      });
    }

    if (cleanNewPassword.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters'
      });
    }

    const user = await Customer.findOne({ email: cleanEmail });
    if (!user) {
      console.log(`User not found during password reset: ${cleanEmail}`);
      return res.status(400).json({
        success: false,
        message: 'Invalid request'
      });
    }

    const tokenDoc = await Token.findOne({ 
      userId: user._id,
      token: cleanToken,
      purpose: 'password_reset',
      expiresAt: { $gt: new Date() }
    });

    if (!tokenDoc) {
      console.log(`Invalid or expired token during password reset for user ${user._id}`);
      return res.status(400).json({
        success: false,
        message: 'Session expired. Please start the reset process again.'
      });
    }

    console.log(`Resetting password for user ${user._id}`);

    user.password = cleanNewPassword;
    await user.save();

    await Token.deleteOne({ _id: tokenDoc._id });

    await sendEmail({
      to: user.email,
      subject: 'Your Password Has Been Reset',
      html: `
        <h2>Password Reset Successful</h2>
        <p>Your Fonte Lenders password has been successfully reset.</p>
        <p>If you didn't make this change, please contact support immediately.</p>
      `
    });

    res.json({
      success: true,
      message: 'Password reset successful'
    });

  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reset password'
    });
  }
});

app.post('/api/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token is required'
      });
    }

    const tokenDoc = await Token.findOne({ token: refreshToken }).populate('userId');
    if (!tokenDoc) {
      return res.status(401).json({
        success: false,
        message: 'Invalid refresh token'
      });
    }

    if (tokenDoc.expiresAt < new Date()) {
      await Token.deleteOne({ _id: tokenDoc._id });
      return res.status(401).json({
        success: false,
        message: 'Refresh token expired'
      });
    }

    const newToken = jwt.sign(
      { 
        id: tokenDoc.userId._id,
        phone: tokenDoc.userId.phoneNumber,
        customerId: tokenDoc.userId.customerId 
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
    );

    const newRefreshToken = crypto.randomBytes(40).toString('hex');
    const newExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    
    await Token.create({
      userId: tokenDoc.userId._id,
      token: newRefreshToken,
      expiresAt: newExpiresAt
    });

    await Token.deleteOne({ _id: tokenDoc._id });

    res.json({
      success: true,
      token: newToken,
      refreshToken: newRefreshToken
    });

  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to refresh token'
    });
  }
});

// ==================== LOAN APPLICATION ENDPOINT ====================
app.post('/api/submit-loan', authenticate, async (req, res) => {
  try {
    const { 
      amount, 
      guarantorName, 
      guarantorId, 
      guarantorPhone,
      signature,
      loanPurpose
    } = req.body;

    if (!amount || !guarantorName || !guarantorId || !guarantorPhone || !signature) {
      return res.status(400).json({
        success: false,
        message: 'All required fields must be provided'
      });
    }

    if (isNaN(amount)) {
      return res.status(400).json({
        success: false,
        message: 'Amount must be a valid number'
      });
    }

    const numericAmount = parseFloat(amount);
    if (numericAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Amount must be greater than 0'
      });
    }

    const customer = await Customer.findById(req.user._id)
      .select('+customerId +fullName +phoneNumber +email +maxLoanLimit +currentLoanBalance');
    
    if (!customer) {
      return res.status(404).json({
        success: false,
        message: 'Customer not found'
      });
    }

    const availableLimit = customer.maxLoanLimit - customer.currentLoanBalance;
    if (numericAmount > availableLimit) {
      return res.status(400).json({
        success: false,
        message: `Loan limit exceeded. Your available limit is KES ${availableLimit.toLocaleString()}`,
        availableLimit
      });
    }

    let customerVerification, guarantorVerification;
    let verificationError = null;
    
    try {
      [customerVerification, guarantorVerification] = await Promise.all([
        verifyIDWithJenga(customer.customerId, customer.fullName),
        verifyIDWithJenga(guarantorId, guarantorName)
      ]);
    } catch (error) {
      console.error('Verification error:', error);
      verificationError = error;
      
      if (process.env.ENABLE_FALLBACK_VERIFICATION === 'true') {
        customerVerification = {
          success: true,
          verifiedBy: 'fallback',
          message: 'Verification pending manual review',
          fallback: true,
          timestamp: new Date().toISOString()
        };
        guarantorVerification = {
          success: true,
          verifiedBy: 'fallback',
          message: 'Verification pending manual review',
          fallback: true,
          timestamp: new Date().toISOString()
        };
      } else {
        return res.status(503).json({
          success: false,
          message: 'ID verification service unavailable',
          details: error.message
        });
      }
    }

    if (!customerVerification.success || !guarantorVerification.success) {
      return res.status(400).json({
        success: false,
        message: 'Verification failed',
        customerVerified: customerVerification.success,
        guarantorVerified: guarantorVerification.success,
        requiresManualVerification: customerVerification.fallback || guarantorVerification.fallback
      });
    }

    const application = new LoanApplication({
      customerId: customer.customerId,
      userId: customer._id,
      fullName: customer.fullName,
      phoneNumber: customer.phoneNumber,
      email: customer.email,
      amount: numericAmount,
      purpose: loanPurpose || 'Personal Loan',
      signature,
      guarantor: {
        name: guarantorName,
        idNumber: guarantorId,
        phoneNumber: guarantorPhone,
        relationship: 'Personal'
      },
      verificationStatus: customerVerification.fallback ? 'pending' : 'verified',
      status: 'pending',
      verificationData: {
        customer: customerVerification,
        guarantor: guarantorVerification,
        verificationMethod: customerVerification.fallback ? 'fallback' : 'jenga',
        verificationError: verificationError ? verificationError.message : null
      }
    });

    await application.save();

    sendLoanApplicationNotifications(customer, application, availableLimit, customerVerification);

    return res.status(201).json({
      success: true,
      message: customerVerification.fallback 
        ? 'Application submitted (pending manual verification)' 
        : 'Loan application submitted successfully',
      applicationId: application._id,
      verification: {
        customer: customerVerification,
        guarantor: guarantorVerification
      },
      requiresManualVerification: customerVerification.fallback
    });

  } catch (error) {
    console.error('Loan submission error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error submitting application',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ==================== PAYMENT PREFERENCES ====================
app.put('/api/user/payment-preferences', authenticate, async (req, res) => {
  try {
    const { mpesaNumber } = req.body;
    
    const cleanPhone = mpesaNumber.replace(/\D/g, '').trim();
    if (!cleanPhone || (cleanPhone.length !== 12 && cleanPhone.length !== 10 && cleanPhone.length !== 9)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid M-Pesa number format'
      });
    }

    const updateData = {
      'paymentPreferences.mode': 'M-Pesa Paybill',
      'paymentPreferences.paybillDetails': {
        paybillNumber: '522533',
        accountNumber: '7883032'
      },
      'paymentPreferences.mpesaNumber': cleanPhone
    };

    const updatedUser = await Customer.findByIdAndUpdate(
      req.user._id,
      { $set: updateData },
      { new: true, select: '-password' }
    );

    res.json({
      success: true,
      message: 'Payment preferences updated',
      paymentPreferences: updatedUser.paymentPreferences
    });

  } catch (error) {
    console.error('Payment preferences error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update payment preferences'
    });
  }
});

// ==================== HELPER FUNCTIONS ====================
async function sendLoanApplicationNotifications(customer, application, availableLimit, verification) {
  try {
    await sendEmail({
      to: process.env.ADMIN_EMAIL,
      subject: 'New Loan Application Submitted',
      html: generateAdminNotificationEmail(customer, application, availableLimit)
    });

    if (customer.email) {
      await sendEmail({
        to: customer.email,
        subject: 'Your Loan Application Has Been Received',
        html: generateCustomerConfirmationEmail(customer, application, verification)
      });
    }

    if (process.env.SMS_SERVICE_ENABLED === 'true') {
      await sendSMSNotification(customer.phoneNumber, application);
    }
  } catch (error) {
    console.error('Notification error:', error);
  }
}

async function sendPaymentConfirmation(userId, amount) {
  try {
    const user = await Customer.findById(userId);
    if (!user?.email) return;

    await sendEmail({
      to: user.email,
      subject: 'Payment Confirmation',
      html: `
        <div style="max-width: 600px; margin: 20px auto; padding: 30px; background: #f8f9fa; border-radius: 10px;">
          <h2 style="color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">
            Payment Received
          </h2>
          
          <p>Dear ${user.fullName},</p>
          
          <div style="background: white; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3 style="color: #3498db; margin-top: 0;">
              Payment Details
            </h3>
            <p>Amount: <strong>KES ${amount.toLocaleString()}</strong></p>
            <p>Method: M-Pesa Paybill</p>
            <p>Business Number: 522533</p>
            <p>Account Number: 7883032</p>
          </div>
          
          <p style="margin-top: 30px; color: #7f8c8d;">
            Thank you for your payment!<br>
            Fonte Lenders Team
          </p>
        </div>
      `
    });
  } catch (error) {
    console.error('Payment confirmation error:', error);
  }
}

function generateAdminNotificationEmail(customer, application, availableLimit) {
  return `
    <div style="max-width: 600px; margin: 20px auto; padding: 30px; background: #f8f9fa; border-radius: 10px;">
      <h2 style="color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">
        New Loan Application
      </h2>
      
      <div style="background: white; padding: 20px; border-radius: 8px; margin-top: 20px;">
        <h3 style="color: #3498db; margin-top: 0;">Customer Details</h3>
        <p><strong>Name:</strong> ${customer.fullName}</p>
        <p><strong>Phone:</strong> ${customer.phoneNumber || 'N/A'}</p>
        <p><strong>ID Number:</strong> ${customer.customerId}</p>
        <p><strong>Email:</strong> ${customer.email || 'N/A'}</p>
        
        <h3 style="color: #3498db; margin-top: 25px;">Loan Request</h3>
        <p><strong>Amount:</strong> KES ${application.amount.toLocaleString()}</p>
        <p><strong>Purpose:</strong> ${application.purpose || 'Not specified'}</p>
        <p><strong>Remaining Limit:</strong> KES ${availableLimit.toLocaleString()}</p>
        
        <h3 style="color: #3498db; margin-top: 25px;">Guarantor Information</h3>
        <p><strong>Name:</strong> ${application.guarantor.name}</p>
        <p><strong>ID Number:</strong> ${application.guarantor.idNumber}</p>
        <p><strong>Phone:</strong> ${application.guarantor.phoneNumber}</p>
        <p><strong>Relationship:</strong> ${application.guarantor.relationship}</p>
        
        <h3 style="color: #3498db; margin-top: 25px;">Verification Status</h3>
        <p><strong>Customer:</strong> ${application.verificationData.customer.status} 
          (${application.verificationData.customer.fallback ? 'Manual' : 'Auto'})</p>
        <p><strong>Guarantor:</strong> ${application.verificationData.guarantor.status}
          (${application.verificationData.guarantor.fallback ? 'Manual' : 'Auto'})</p>
      </div>
      
      <p style="margin-top: 30px; color: #7f8c8d;">
        Application ID: ${application._id}<br>
        Submitted: ${application.createdAt.toLocaleString()}
      </p>
    </div>
  `;
}

function generateCustomerConfirmationEmail(customer, application, verification) {
  return `
    <div style="max-width: 600px; margin: 20px auto; padding: 30px; background: #f8f9fa; border-radius: 10px;">
      <h2 style="color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">
        Application Received
      </h2>
      
      <p>Dear ${customer.fullName},</p>
      
      <div style="background: white; padding: 20px; border-radius: 8px; margin-top: 20px;">
        <h3 style="color: #3498db; margin-top: 0;">
          Application #${application._id.toString().slice(-6).toUpperCase()}
        </h3>
        
        <p>We've received your loan request for <strong>KES ${application.amount.toLocaleString()}</strong>.</p>
        
        <h4 style="color: #2c3e50; margin-top: 20px;">Details</h4>
        <p><strong>Purpose:</strong> ${application.purpose || 'Personal Loan'}</p>
        <p><strong>Submitted:</strong> ${new Date().toLocaleDateString()}</p>
        
        <div style="margin-top: 25px; padding: 15px; background: #fff9e6; border-radius: 5px;">
          <p style="color: #856404; margin: 0;">
            ${verification.fallback 
              ? 'Your application is undergoing manual verification'
              : 'Your application is being processed automatically'}
          </p>
        </div>
      </div>
      
      <p style="margin-top: 30px; color: #7f8c8d;">
        We'll notify you once your application is reviewed.<br>
        Fonte Lenders Team
      </p>
    </div>
  `;
}

function generateLoanStatusEmail(application, status, adminNotes) {
  return `
    <div style="max-width: 600px; margin: 20px auto; padding: 30px; background: #f8f9fa; border-radius: 10px;">
      <h2 style="color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">
        Loan Application Update
      </h2>
      
      <p>Dear ${application.userId.fullName},</p>
      
      <div style="background: white; padding: 20px; border-radius: 8px; margin-top: 20px;">
        <h3 style="color: #3498db; margin-top: 0;">
          Application #${application._id.toString().slice(-6).toUpperCase()}
        </h3>
        
        <p style="font-size: 1.1em;">
          Status: <strong style="color: ${status === 'approved' ? '#27ae60' : '#e74c3c'}">${status.toUpperCase()}</strong>
        </p>
        
        ${status === 'approved' ? `
          <div style="margin-top: 20px;">
            <h4 style="color: #2c3e50;">Loan Details</h4>
            <p>Amount: KES ${application.amount.toLocaleString()}</p>
            <p>Total Amount (with interest): KES ${application.totalAmount.toLocaleString()}</p>
            <p>Due Date: ${new Date(application.dueDate).toLocaleDateString()}</p>
            
            <h4 style="color: #2c3e50; margin-top: 20px;">Repayment Schedule</h4>
            <ul style="list-style: none; padding: 0;">
              ${application.repaymentSchedule.map((payment, index) => `
                <li style="padding: 8px 0; border-bottom: 1px solid #eee;">
                  Payment ${index + 1}: 
                  KES ${payment.amount.toLocaleString()} due 
                  ${new Date(payment.dueDate).toLocaleDateString()}
                </li>
              `).join('')}
            </ul>
          </div>
        ` : `
          <div style="margin-top: 20px;">
            <h4 style="color: #2c3e50;">Rejection Reason</h4>
            <p>${adminNotes || 'Please contact our support team for more details.'}</p>
          </div>
        `}
      </div>
      
      <p style="margin-top: 30px; color: #7f8c8d;">
        Best regards,<br>
        Fonte Lenders Team
      </p>
    </div>
  `;
}

async function sendSMSNotification(phoneNumber, application) {
  console.log(`SMS notification would be sent to ${phoneNumber} for application ${application._id}`);
}

// ==================== ERROR HANDLER ====================
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    code: 'SERVER_ERROR',
    message: 'Internal server error',
    systemError: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ==================== ADMIN INITIALIZATION ====================
async function createInitialAdmin() {
  try {
    const adminCount = await Admin.countDocuments();
    if (adminCount === 0) {
      const hashedPassword = await bcrypt.hash('adminpassword', 12);
      await Admin.create({
        username: 'admin',
        password: hashedPassword,
        role: 'superadmin'
      });
      console.log('✅ Initial admin user created');
      console.log('Username: admin');
      console.log('Password: adminpassword');
    } else {
      console.log('ℹ️ Admin user already exists');
    }
  } catch (error) {
    console.error('❌ Failed to create initial admin:', error);
  }
}

// ==================== SERVER STARTUP ====================
const startServer = async () => {
  try {
    const dbConnected = await connectWithRetry();
    if (!dbConnected) {
      throw new Error('Failed to connect to database after retries');
    }

    await createInitialAdmin();

    server.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📊 MongoDB state: ${mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'}`);
    });

    process.on('SIGTERM', () => {
      console.log('🛑 SIGTERM received. Shutting down gracefully...');
      server.close(() => {
        mongoose.connection.close(false, () => {
          console.log('🚪 Server and MongoDB connection closed');
          process.exit(0);
        });
      });
    });

  } catch (error) {
    console.error('🚨 Failed to start server:', error);
    process.exit(1);
  }
};

startServer();