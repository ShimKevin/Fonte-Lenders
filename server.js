require('dotenv').config();
const { body, validationResult } = require('express-validator');
const dateUtils = require('./shared/dateUtils.js');
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
    
    // Send immediate overdue update if needed
    LoanApplication.findOne({
      userId,
      status: 'defaulted'
    }).then(loan => {
      if (loan) {
        const now = new Date();
        const daysOverdue = Math.floor((now - loan.dueDate) / (1000 * 60 * 60 * 24));
        if (daysOverdue > (loan.overdueDays || 0)) {
          socket.emit('overdueUpdate', {
            loanId: loan._id,
            userId: loan.userId,
            overdueDays: daysOverdue,
            overdueFees: loan.principal * 0.06 * daysOverdue,
            totalAmount: loan.totalAmount
          });
        }
      }
    });
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

  // ==================== PAYMENT REJECTION HANDLER ====================
  socket.on('paymentRejected', (data) => {
    console.log(`❌ Payment rejected for user ${data.userId}: ${data.reason}`);
    io.to(`user_${data.userId}`).emit('paymentRejected', {
      paymentId: data.paymentId,
      amount: data.amount,
      reason: data.reason
    });
  });

  // ==================== OVERDUE UPDATE HANDLER ====================
  socket.on('overdueUpdate', (data) => {
    console.log(`⚠️ Overdue update for loan ${data.loanId} (User: ${data.userId}): ${data.overdueDays} days overdue`);
    // Update both admin and customer views
    io.to(`user_${data.userId}`).emit('overdueUpdate', {
      loanId: data.loanId,
      overdueDays: data.overdueDays,
      overdueFees: data.overdueFees,
      totalAmount: data.totalAmount
    });
    io.to('adminRoom').emit('overdueUpdate', {
      loanId: data.loanId,
      userId: data.userId,
      overdueDays: data.overdueDays,
      overdueFees: data.overdueFees,
      totalAmount: data.totalAmount
    });
  });
});

// ==================== LOAN STATUS UPDATE JOB INTEGRATION ====================
async function updateOverdueLoansAndNotify() {
  try {
    const now = new Date();
    const updatedLoans = await LoanApplication.find({
      status: 'active',
      dueDate: { $lt: now }
    });

    updatedLoans.forEach(loan => {
      const daysOverdue = Math.floor((now - loan.dueDate) / (1000 * 60 * 60 * 24));
      const overdueFees = loan.principal * 0.06 * daysOverdue;
      const totalAmount = (loan.principal + (loan.interestAmount || 0) + overdueFees);

      // Emit to both user and admin rooms
      io.to(`user_${loan.userId}`).emit('overdueUpdate', {
        loanId: loan._id,
        overdueDays: daysOverdue,
        overdueFees: overdueFees,
        totalAmount: totalAmount
      });

      io.to('adminRoom').emit('overdueUpdate', {
        loanId: loan._id,
        userId: loan.userId,
        overdueDays: daysOverdue,
        overdueFees: overdueFees,
        totalAmount: totalAmount
      });
    });

    console.log(`🔔 Notified ${updatedLoans.length} overdue loans`);
  } catch (error) {
    console.error('❌ Error in overdue loan notification:', error);
  }
}

// Run this periodically (e.g., in your loan status update job)
// setInterval(updateOverdueLoansAndNotify, 24 * 60 * 60 * 1000); // Daily

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
const adminActivityLogSchema = new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true },
  action: { type: String, required: true },
  targetId: mongoose.Schema.Types.ObjectId,
  details: Object,
  ipAddress: String
}, { timestamps: true });

const AdminActivityLog = mongoose.model('AdminActivityLog', adminActivityLogSchema);

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
  rejectionReason: String,
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
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'active', 'completed', 'defaulted'],
    default: 'pending' 
  },
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
    paidAmount: { type: Number, default: 0 },
    status: { 
      type: String, 
      enum: ['pending', 'paid', 'overdue', 'partial'],
      default: 'pending' 
    },
    paidAt: Date
  }],
  totalAmount: { type: Number }, // Total amount including interest and overdue fees
  overdueDays: { type: Number, default: 0 }, // Number of days overdue
  overdueFees: { type: Number, default: 0 }, // Total overdue fees (6% of principal per day, max 6 days)
  lastOverdueCalculation: Date, // When overdue was last calculated
  principal: { type: Number }, // Explicitly track principal amount
  interestRate: { type: Number }, // Track the interest rate
  interestAmount: { type: Number }, // Track calculated interest amount
  lastStatusUpdate: Date // Track when status was last updated
}, { timestamps: true });

// Add indexes for frequent queries
loanApplicationSchema.index({ userId: 1, status: 1 });
loanApplicationSchema.index({ status: 1, dueDate: 1 });

// Pre-save hook for automatic overdue calculation
loanApplicationSchema.pre('save', function(next) {
  // Update status timestamp if status changed
  if (this.isModified('status') || this.isNew) {
    this.lastStatusUpdate = new Date();
  }

  // Calculate overdue status and fees for active loans
  if (this.status === 'active' && this.dueDate && new Date(this.dueDate) < new Date()) {
    const now = new Date();
    const dueDate = new Date(this.dueDate);
    const daysOverdue = Math.floor((now - dueDate) / (1000 * 60 * 60 * 24));
    
    // Cap penalty calculation at 6 days
    const penaltyDays = Math.min(daysOverdue, 6);
    
    // Only recalculate if daysOverdue increased or never calculated before
    if (daysOverdue > this.overdueDays || !this.lastOverdueCalculation) {
      this.overdueFees = this.principal * 0.06 * penaltyDays;
      this.overdueDays = daysOverdue;
      this.lastOverdueCalculation = now;
      this.totalAmount = this.principal + (this.interestAmount || 0) + this.overdueFees;
      
      // Update status to defaulted if overdue (but keep tracking days beyond cap)
      if (daysOverdue > 0 && this.status !== 'defaulted') {
        this.status = 'defaulted';
        this.lastStatusUpdate = now;
      }
    }
  }
  
  // Mark as completed if fully paid
  if (this.status === 'active' && this.amountPaid >= this.totalAmount) {
    this.status = 'completed';
    this.lastStatusUpdate = new Date();
    this.overdueDays = 0;
    this.overdueFees = 0;
  }

  next();
});

// Static method for batch updating loan statuses
loanApplicationSchema.statics.updateLoanStatuses = async function() {
  const now = new Date();
  
  try {
    // 1. Update overdue loans (capped at 6 days for penalties)
    await this.updateMany(
      {
        status: { $in: ['active', 'defaulted'] },
        dueDate: { $lt: now },
        $or: [
          { lastOverdueCalculation: { $lt: new Date(now.setHours(0, 0, 0, 0)) } },
          { lastOverdueCalculation: { $exists: false } }
        ]
      },
      [{
        $set: {
          overdueDays: { 
            $ceil: {
              $divide: [
                { $subtract: [now, '$dueDate'] },
                1000 * 60 * 60 * 24 // Convert ms to days
              ]
            }
          },
          overdueFees: { 
            $multiply: [
              '$principal',
              0.06,
              {
                $min: [
                  {
                    $ceil: {
                      $divide: [
                        { $subtract: [now, '$dueDate'] },
                        1000 * 60 * 60 * 24 // Convert ms to days
                      ]
                    }
                  },
                  6 // Cap at 6 days
                ]
              }
            ]
          },
          lastOverdueCalculation: now,
          status: {
            $cond: {
              if: { $gt: ['$overdueDays', 0] },
              then: 'defaulted',
              else: '$status'
            }
          },
          totalAmount: {
            $add: [
              '$principal',
              '$interestAmount',
              {
                $multiply: [
                  '$principal',
                  0.06,
                  {
                    $min: [
                      {
                        $ceil: {
                          $divide: [
                            { $subtract: [now, '$dueDate'] },
                            1000 * 60 * 60 * 24
                          ]
                        }
                      },
                      6
                    ]
                  }
                ]
              }
            ]
          }
        }
      }]
    );

    // 2. Mark loans as completed if fully paid
    await this.updateMany({
      status: { $in: ['active', 'defaulted'] },
      $expr: { $gte: ['$amountPaid', '$totalAmount'] }
    }, {
      $set: { 
        status: 'completed',
        lastStatusUpdate: now,
        overdueDays: 0,
        overdueFees: 0
      }
    });

    console.log('✅ Loan status updates completed successfully');
    return true;
  } catch (error) {
    console.error('❌ Loan status update job failed:', error);
    throw error;
  }
};

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

// ==================== STATIC FILES ====================
// Serve all static files from public directory with cache control
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, path) => {
    // No cache for HTML files
    if (path.endsWith('.html')) {
      res.set('Cache-Control', 'no-store');
    }
    // Cache other assets for 1 day
    else {
      res.set('Cache-Control', 'public, max-age=86400');
    }
  }
}));

// ==================== ROUTES ====================
// Admin route handlers
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ==================== MIDDLEWARE ====================
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, etc)
    if (!origin) return callback(null, true);
    
    const allowedDomains = [
      'http://localhost:3000',
      'http://localhost:3000/admin',
      'https://fonte-lenders.com',
      'https://fonte-lenders.onrender.com'
    ];

    // Check if the origin is either an exact match or a subdomain
    if (
      allowedDomains.includes(origin) ||
      origin.endsWith('.fonte-lenders.com')
    ) {
      return callback(null, true);
    }

    console.warn(`CORS blocked for origin: ${origin}`);
    callback(new Error(`Origin ${origin} not allowed by CORS`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-refresh-token'],
  exposedHeaders: ['Content-Length', 'Authorization', 'X-Request-ID']
}));

// Custom response formatter
app.use((req, res, next) => {
  res.jsonResponse = (data, status = 200) => {
    res.status(status).json({
      success: status >= 200 && status < 300,
      ...data
    });
  };
  next();
});

// Token verification middleware
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

// Loan validation middleware
app.use('/api/admin/loans', [
  body('amount').optional().isFloat({ min: 0 }).withMessage('Amount must be a positive number'),
  body('overdueFees').optional().isFloat({ min: 0 }).withMessage('Fees must be a positive number'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false,
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        errors: errors.array()
      });
    }
    next();
  }
]);

// Rate limiter
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

// Token refresh endpoint
app.post('/api/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({ 
        success: false,
        code: 'REFRESH_TOKEN_REQUIRED'
      });
    }

    const tokenDoc = await Token.findOne({ 
      token: refreshToken,
      expiresAt: { $gt: new Date() }
    }).populate('userId');

    if (!tokenDoc) {
      return res.status(401).json({
        success: false,
        code: 'INVALID_REFRESH_TOKEN'
      });
    }

    const newToken = jwt.sign(
      { id: tokenDoc.userId._id },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    // Update refresh token expiry
    tokenDoc.expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await tokenDoc.save();

    res.json({
      success: true,
      token: newToken,
      refreshToken: tokenDoc.token
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      success: false,
      code: 'REFRESH_FAILED'
    });
  }
});

// Authentication middlewares
const authenticate = async (req, res, next) => {
  if (!req.authenticatedUser) {
    const error = req.tokenError || new Error('Missing authentication');
    return handleAuthError(error, res);
  }

  try {
    const user = await Customer.findById(req.authenticatedUser)
      .select('-password')
      .lean();
    
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

  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      ignoreExpiration: false,
      algorithms: ['HS256']
    });
    
    const admin = await Admin.findById(decoded.id)
      .select('-password')
      .lean();
    
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
      code: 'AUTH_FAILED',
      message: 'Session expired. Please log in again.'
    };

    if (error.name === 'TokenExpiredError') {
      response.code = 'TOKEN_EXPIRED';
    } else if (error.name === 'JsonWebTokenError') {
      response.code = 'INVALID_TOKEN';
    }

    return res.status(401).json(response);
  }
};

const handleAuthError = (error, res) => {
  console.error('❌ Authentication error:', error.name, '-', error.message);
  
  const errorResponse = {
    success: false,
    code: 'AUTH_FAILED',
    message: 'Authentication failed'
  };

  if (error.name === 'TokenExpiredError') {
    errorResponse.code = 'TOKEN_EXPIRED';
    errorResponse.message = 'Session expired. Please log in again.';
  } else if (error.name === 'JsonWebTokenError') {
    errorResponse.code = 'INVALID_TOKEN';
  }

  return res.status(401).json(errorResponse);
};

app.use(loginRateLimiter);

// ==================== EMAIL SERVICE ====================
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: process.env.EMAIL_PORT || 587,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS // Note: Fixed typo from EMAIL_Pass to EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false // For self-signed certificates
  }
});

async function sendEmail(options) {
  try {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      console.warn('Email credentials not configured - skipping email send');
      return false;
    }

    const mailOptions = {
      from: `"Fonte Lenders" <${process.env.EMAIL_USER}>`,
      ...options
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent:', info.messageId);
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
      LoanApplication.countDocuments({ status: 'defaulted' }),
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

// ==================== ENHANCED CUSTOMER SEARCH ENDPOINT ====================
app.get('/api/admin/customers', authenticateAdmin, async (req, res) => {
    try {
        const { search, page = 1, limit = 20, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;
        
        // Input validation
        const numericPage = Math.max(1, parseInt(page));
        const numericLimit = Math.min(Math.max(1, parseInt(limit)), 100); // Cap at 100 items per page
        const sortDirection = sortOrder === 'asc' ? 1 : -1;
        
        // Build search filter with regex for partial matching
        const filter = search ? {
            $or: [
                { customerId: { $regex: escapeRegex(search), $options: 'i' } },
                { fullName: { $regex: escapeRegex(search), $options: 'i' } },
                { phoneNumber: { $regex: escapeRegex(search), $options: 'i' } },
                { email: { $regex: escapeRegex(search), $options: 'i' } }
            ]
        } : {};

        // Add verification status filter if provided
        if (req.query.verificationStatus) {
            filter.verificationStatus = req.query.verificationStatus;
        }

        // Add active loan filter if provided
        if (req.query.hasActiveLoan === 'true') {
            filter.activeLoan = { $exists: true, $ne: null };
        } else if (req.query.hasActiveLoan === 'false') {
            filter.activeLoan = null;
        }

        // Execute query with pagination
        const [customers, total] = await Promise.all([
            Customer.find(filter)
                .select('-password -__v')
                .populate({
                    path: 'activeLoan',
                    select: 'amount status dueDate'
                })
                .sort({ [sortBy]: sortDirection })
                .skip((numericPage - 1) * numericLimit)
                .limit(numericLimit)
                .lean(),
            
            Customer.countDocuments(filter)
        ]);

        res.json({
            success: true,
            data: customers || [],
            pagination: {
                page: numericPage,
                limit: numericLimit,
                total,
                pages: Math.ceil(total / numericLimit)
            },
            filters: {
                searchTerm: search || '',
                verificationStatus: req.query.verificationStatus || 'all',
                hasActiveLoan: req.query.hasActiveLoan || 'all'
            }
        });

    } catch (error) {
        console.error('Customer search error:', error);
        res.status(500).json({ 
            success: false, 
            code: 'SERVER_ERROR',
            message: 'Failed to retrieve customer data',
            systemError: process.env.NODE_ENV === 'development' ? error.message : undefined,
            timestamp: new Date().toISOString()
        });
    }
});

// Helper function to escape regex special characters
function escapeRegex(text) {
    return text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
}

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

// ==================== DELETE USER ENDPOINT ====================
app.delete('/api/admin/customers/:id', authenticateAdmin, async (req, res) => {
  try {
    const customerId = req.params.id;

    // 1. Check if customer exists
    const customer = await Customer.findById(customerId);
    if (!customer) {
      return res.status(404).json({
        success: false,
        message: 'Customer not found'
      });
    }

    // 2. Check for active loans
    const activeLoan = await LoanApplication.findOne({
      userId: customerId,
      status: { $in: ['active', 'pending'] }
    });

    if (activeLoan) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete customer with active or pending loans'
      });
    }

    // 3. Start transaction for data consistency
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Delete related data
      await Payment.deleteMany({ userId: customerId }).session(session);
      await LoanApplication.deleteMany({ userId: customerId }).session(session);
      await Token.deleteMany({ userId: customerId }).session(session);
      
      // Delete customer
      await Customer.findByIdAndDelete(customerId).session(session);

      // Commit transaction
      await session.commitTransaction();
      session.endSession();

      res.json({
        success: true,
        message: 'Customer and all related data deleted successfully'
      });

    } catch (transactionError) {
      // Rollback on error
      await session.abortTransaction();
      session.endSession();
      throw transactionError;
    }

  } catch (error) {
    console.error('User deletion error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete user',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ==================== UPDATE CUSTOMER LIMIT ENDPOINT ====================
app.put('/api/admin/customers/:id/limit', authenticateAdmin, async (req, res) => {
  try {
    const { newLimit } = req.body;
    
    // Enhanced validation
    if (typeof newLimit !== 'number' || newLimit < 0 || !Number.isFinite(newLimit)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Valid loan limit (non-negative finite number) is required' 
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
    customer.maxLoanLimit = newLimit;
    const updatedCustomer = await customer.save();

    // Notify user with enhanced details
    io.to(`user_${customer._id}`).emit('loanLimitUpdate', {
      newLimit: customer.maxLoanLimit,
      previousLimit,
      updatedAt: new Date(),
      message: 'Your loan limit has been updated'
    });

    // Notify admin with comprehensive details
    io.to('adminRoom').emit('customerUpdate', {
      customerId: customer._id,
      fullName: customer.fullName,
      email: customer.email,
      phoneNumber: customer.phoneNumber,
      updateType: 'loanLimit',
      previousLimit,
      newLimit: customer.maxLoanLimit,
      updatedBy: req.admin._id, // Assuming admin info is available
      updatedAt: new Date()
    });

    res.json({ 
      success: true, 
      message: 'Loan limit updated successfully',
      newLimit: customer.maxLoanLimit,
      customer: {
        _id: updatedCustomer._id,
        fullName: updatedCustomer.fullName,
        email: updatedCustomer.email,
        maxLoanLimit: updatedCustomer.maxLoanLimit
        // Exclude sensitive fields
      }
    });
  } catch (error) {
    console.error('Update loan limit error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to update loan limit',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Add middleware for loan application filtering
app.use('/api/admin/loan-applications', async (req, res, next) => {
  if (req.method === 'GET' && req.query.status === 'active') {
    // Ensure we're not filtering out valid active loans
    req.query.activeOnly = true;
  }
  next();
});

app.get('/api/admin/loan-applications', authenticateAdmin, async (req, res) => {
    try {
        const { status, page = 1, limit = 20, rejected } = req.query;
        
        // Build the query object
        const query = {};
        
        // Handle status filter
        if (status && typeof status === 'string') {
            if (status.includes(',')) {
                // When multiple statuses are requested (like active,defaulted)
                const statuses = status.split(',');
                query.status = { $in: statuses };
                
                // Automatically exclude rejected unless explicitly requested
                if (!statuses.includes('rejected') && rejected !== 'true') {
                    query.status.$ne = 'rejected';
                }
            } else {
                // Single status requested
                query.status = status;
                
                // For active/defaulted views, automatically exclude rejected
                if ((status === 'active' || status === 'defaulted') && rejected !== 'true') {
                    query.status = { $eq: status, $ne: 'rejected' };
                }
            }
        } else if (rejected !== 'true') {
            // Default case: exclude rejected when no specific status requested
            // and not explicitly asking for rejected loans
            query.status = { $ne: 'rejected' };
        }
        
        // Fetch applications with pagination
        const applications = await LoanApplication.find(query)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit))
            .lean();

        const count = await LoanApplication.countDocuments(query);

        res.json({
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
        res.status(500).json({
            success: false,
            message: 'Failed to fetch loan applications',
            code: 'LOAN_APPLICATIONS_FETCH_ERROR',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
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

// ==================== ENHANCED LOAN APPROVAL ENDPOINT ====================
app.patch('/api/admin/loan-applications/:id/approve', authenticateAdmin, async (req, res) => {
  const session = await mongoose.startSession();
  const startTime = Date.now();
  
  try {
    await session.withTransaction(async () => {
      const { interestRate, repaymentPeriod, adminNotes } = req.body;
      
      // Enhanced validation with range checks
      if (typeof interestRate === 'undefined' || typeof repaymentPeriod === 'undefined') {
        throw {
          status: 400,
          code: 'MISSING_REQUIRED_FIELDS',
          message: 'Both interest rate and repayment period are required',
          fields: ['interestRate', 'repaymentPeriod']
        };
      }

      const numericInterestRate = parseFloat(interestRate);
      const numericRepaymentPeriod = parseInt(repaymentPeriod);

      if (isNaN(numericInterestRate)) {
        throw {
          status: 400,
          code: 'INVALID_INTEREST_RATE',
          message: 'Interest rate must be a valid number',
          field: 'interestRate'
        };
      }

      if (numericInterestRate < 5 || numericInterestRate > 30) {
        throw {
          status: 400,
          code: 'INTEREST_RATE_OUT_OF_RANGE',
          message: 'Interest rate must be between 5% and 30%',
          field: 'interestRate',
          min: 5,
          max: 30
        };
      }

      if (isNaN(numericRepaymentPeriod)) {
        throw {
          status: 400,
          code: 'INVALID_REPAYMENT_PERIOD',
          message: 'Repayment period must be a valid number',
          field: 'repaymentPeriod'
        };
      }

      if (numericRepaymentPeriod < 7 || numericRepaymentPeriod > 90) {
        throw {
          status: 400,
          code: 'REPAYMENT_PERIOD_OUT_OF_RANGE',
          message: 'Repayment period must be between 7 and 90 days',
          field: 'repaymentPeriod',
          min: 7,
          max: 90
        };
      }

      // Find loan with transaction safety
      const loan = await LoanApplication.findById(req.params.id)
        .populate('userId', 'fullName phoneNumber email maxLoanLimit currentLoanBalance creditScore')
        .session(session);

      if (!loan) {
        throw {
          status: 404,
          code: 'LOAN_NOT_FOUND',
          message: 'Loan application not found'
        };
      }

      // Status validation with detailed message
      if (loan.status !== 'pending') {
        throw {
          status: 400,
          code: 'INVALID_LOAN_STATUS',
          message: `Cannot approve loan with status: ${loan.status}`,
          currentStatus: loan.status,
          requiredStatus: 'pending'
        };
      }

      // Calculate loan terms with precision
      const principal = parseFloat(loan.amount.toFixed(2));
      const interestAmount = parseFloat((principal * (numericInterestRate / 100)).toFixed(2));
      const totalAmount = parseFloat((principal + interestAmount).toFixed(2));
      
      // Set due date with timezone consideration
      const dueDate = new Date();
      dueDate.setUTCHours(23, 59, 59, 999); // End of day
      dueDate.setUTCDate(dueDate.getUTCDate() + numericRepaymentPeriod);

      // Enhanced repayment schedule with metadata
      const repaymentSchedule = [{
        dueDate: dueDate,
        amount: totalAmount,
        paidAmount: 0,
        status: 'pending',
        paidAt: null,
        isOverdue: false,
        daysOverdue: 0,
        penaltyApplied: 0
      }];

      // Update loan with additional tracking fields
      const customer = loan.userId;
      const availableLimit = parseFloat((customer.maxLoanLimit - customer.currentLoanBalance).toFixed(2));
      
      // Enhanced credit limit check with detailed response
      if (totalAmount > availableLimit) {
        throw {
          status: 400,
          code: 'CREDIT_LIMIT_EXCEEDED',
          message: 'Loan amount exceeds available credit limit',
          details: {
            requestedAmount: totalAmount,
            availableLimit: availableLimit,
            difference: parseFloat((totalAmount - availableLimit).toFixed(2)),
            currentBalance: customer.currentLoanBalance,
            maxLimit: customer.maxLoanLimit
          }
        };
      }

      // Prepare loan updates
      Object.assign(loan, {
        status: 'active',
        principal: principal,
        interestRate: numericInterestRate,
        interestAmount: interestAmount,
        totalAmount: totalAmount,
        dueDate: dueDate,
        repaymentSchedule: repaymentSchedule,
        approvedAt: new Date(),
        approvedBy: req.admin._id,
        adminNotes: adminNotes,
        markedDefault: false,
        overdueDays: 0,
        overdueFees: 0,
        lastStatusUpdate: new Date(),
        lastOverdueCalculation: null,
        creditScoreAtApproval: customer.creditScore
      });

      // Update customer with transaction
      customer.currentLoanBalance = parseFloat((customer.currentLoanBalance + totalAmount).toFixed(2));
      customer.activeLoan = loan._id;
      customer.lastLoanApprovalDate = new Date();

      // Atomic save operations
      await Promise.all([
        loan.save({ session }),
        customer.save({ session }),
        AdminActivityLog.create([{
          adminId: req.admin._id,
          action: 'LOAN_APPROVAL',
          targetId: loan._id,
          details: {
            amount: totalAmount,
            interestRate: numericInterestRate,
            repaymentPeriod: numericRepaymentPeriod,
            adminNotes: adminNotes
          },
          ipAddress: req.ip,
          userAgent: req.headers['user-agent']
        }], { session })
      ]);

      // Prepare comprehensive response
      const responseData = {
        loanId: loan._id,
        customer: {
          id: customer._id,
          name: customer.fullName,
          phone: customer.phoneNumber,
          email: customer.email
        },
        terms: {
          principal: principal,
          interestRate: numericInterestRate,
          interestAmount: interestAmount,
          totalAmount: totalAmount,
          dueDate: dueDate,
          repaymentPeriod: numericRepaymentPeriod
        },
        timestamps: {
          approvedAt: loan.approvedAt,
          createdAt: loan.createdAt
        },
        processingTime: Date.now() - startTime
      };

      // Async notifications (won't block response)
      setImmediate(async () => {
        try {
          // Real-time notifications
          io.to('adminRoom').emit('loanApproved', {
            ...responseData,
            adminName: req.admin.username
          });

          io.to(`user_${customer._id}`).emit('loanApproved', responseData);

          // Send email if configured
          if (customer.email && process.env.SEND_EMAILS === 'true') {
            await sendEmail({
              to: customer.email,
              subject: `Loan Approved - KES ${principal.toLocaleString()}`,
              html: generateLoanApprovalEmail(customer, loan, responseData)
            });
          }

          // Audit logging
          await SystemAuditLog.create({
            event: 'LOAN_APPROVED',
            entityType: 'LOAN',
            entityId: loan._id,
            performedBy: req.admin._id,
            metadata: responseData,
            ipAddress: req.ip
          });
        } catch (asyncError) {
          console.error('Async approval tasks error:', asyncError);
          // Log to error tracking system if available
        }
      });

      // Success response
      res.json({
        success: true,
        message: 'Loan approved successfully',
        data: responseData,
        metadata: {
          serverTime: new Date(),
          processingTime: `${responseData.processingTime}ms`
        }
      });
    });
  } catch (error) {
    // Handle transaction errors
    if (session.inTransaction()) {
      await session.abortTransaction();
    }

    // Handle custom error objects
    if (error.status) {
      return res.status(error.status).json({
        success: false,
        code: error.code,
        message: error.message,
        ...(error.details && { details: error.details }),
        ...(error.field && { field: error.field }),
        ...(error.min !== undefined && { min: error.min }),
        ...(error.max !== undefined && { max: error.max })
      });
    }

    console.error('Loan approval error:', error);
    
    // Enhanced error classification
    const errorType = error.name === 'ValidationError' ? 'VALIDATION_ERROR' :
                     error.name === 'MongoError' ? 'DATABASE_ERROR' :
                     'PROCESSING_ERROR';
    
    res.status(500).json({
      success: false,
      code: errorType,
      message: 'Failed to process loan approval',
      systemError: process.env.NODE_ENV === 'development' ? error.message : undefined,
      timestamp: new Date()
    });
  } finally {
    await session.endSession();
  }
});

// ==================== UPDATED PAYMENT APPROVAL LOGIC ====================
app.patch('/api/admin/payments/:id/approve', authenticateAdmin, async (req, res) => {
  const session = await mongoose.startSession();
  const startTime = Date.now();
  
  try {
    await session.withTransaction(async () => {
      const payment = await Payment.findById(req.params.id)
        .populate('userId')
        .populate('loanId')
        .session(session);
      
      if (!payment) {
        throw {
          status: 404,
          code: 'PAYMENT_NOT_FOUND',
          message: 'Payment not found'
        };
      }

      const loan = payment.loanId;
      const customer = payment.userId;
      const paymentAmount = payment.amount;
      
      // Update loan amount paid
      loan.amountPaid = (loan.amountPaid || 0) + paymentAmount;
      
      // Apply payment to installments
      let remainingAmount = paymentAmount;
      for (const installment of loan.repaymentSchedule) {
        if (['pending', 'partial', 'overdue'].includes(installment.status)) {
          const installmentDue = installment.amount - (installment.paidAmount || 0);
          const amountToApply = Math.min(remainingAmount, installmentDue);
          
          installment.paidAmount = (installment.paidAmount || 0) + amountToApply;
          installment.paidAt = new Date();
          
          // Update status
          if (installment.paidAmount >= installment.amount) {
            installment.status = 'paid';
          } else if (amountToApply > 0) {
            installment.status = 'partial';
          }
          
          remainingAmount -= amountToApply;
          
          if (remainingAmount <= 0) break;
        }
      }
      
      // Check if loan is fully paid
      const totalPaid = loan.amountPaid || 0;
      const totalDue = loan.totalAmount || 0;
      
      if (totalPaid >= totalDue) {
        loan.status = 'completed';
        customer.activeLoan = null;
      } else {
        // Check if any installments are overdue
        const now = new Date();
        const hasOverdue = loan.repaymentSchedule.some(installment => 
          installment.status !== 'paid' && 
          new Date(installment.dueDate) < now
        );
        
        if (hasOverdue) {
          loan.status = 'overdue';
        } else {
          loan.status = 'active';
        }
      }
      
      // Update customer balance
      customer.currentLoanBalance = Math.max(0, customer.currentLoanBalance - paymentAmount);
      
      // Update payment status
      payment.status = 'approved';
      payment.completedAt = new Date();
      payment.approvedBy = req.admin.username;
      
      await Promise.all([
        loan.save({ session }),
        customer.save({ session }),
        payment.save({ session }),
        AdminActivityLog.create([{
          adminId: req.admin._id,
          action: 'PAYMENT_APPROVAL',
          targetId: payment._id,
          details: {
            amount: paymentAmount,
            loanId: loan._id,
            customerId: customer._id
          },
          ipAddress: req.ip,
          userAgent: req.headers['user-agent']
        }], { session })
      ]);

      const responseData = {
        userId: customer._id,
        loanId: loan._id,
        amount: paymentAmount,
        newBalance: customer.currentLoanBalance,
        loanStatus: loan.status,
        processingTime: Date.now() - startTime
      };

      // Async notifications
      setImmediate(() => {
        try {
          io.to(`user_${customer._id}`).emit('paymentApproved', responseData);
          io.to('adminRoom').emit('paymentProcessed', {
            ...responseData,
            adminName: req.admin.username
          });
        } catch (socketError) {
          console.error('Socket notification error:', socketError);
        }
      });

      res.json({ 
        success: true,
        data: responseData,
        metadata: {
          serverTime: new Date(),
          processingTime: `${responseData.processingTime}ms`
        }
      });
    });
  } catch (error) {
    // Handle transaction errors
    if (session.inTransaction()) {
      await session.abortTransaction();
    }

    // Handle custom error objects
    if (error.status) {
      return res.status(error.status).json({
        success: false,
        code: error.code,
        message: error.message
      });
    }

    console.error('Payment approval error:', error);
    res.status(500).json({
      success: false,
      code: 'PAYMENT_APPROVAL_FAILED',
      message: 'Failed to approve payment',
      systemError: process.env.NODE_ENV === 'development' ? error.message : undefined,
      timestamp: new Date()
    });
  } finally {
    await session.endSession();
  }
});

// Helper function for approval email
function generateLoanApprovalEmail(customer, loan, loanDetails) {
  return `
    <div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif;">
      <h2 style="color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">
        Loan Approval Notification
      </h2>
      
      <p>Dear ${customer.fullName},</p>
      
      <p>We are pleased to inform you that your loan application has been approved.</p>
      
      <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3 style="color: #3498db; margin-top: 0;">Loan Details</h3>
        
        <table style="width: 100%; border-collapse: collapse;">
          <tr>
            <td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">Loan ID</td>
            <td style="padding: 8px; border: 1px solid #ddd;">${loan._id.toString().slice(-8).toUpperCase()}</td>
          </tr>
          <tr>
            <td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">Principal Amount</td>
            <td style="padding: 8px; border: 1px solid #ddd;">KES ${loanDetails.terms.principal.toLocaleString()}</td>
          </tr>
          <tr>
            <td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">Interest Rate</td>
            <td style="padding: 8px; border: 1px solid #ddd;">${loanDetails.terms.interestRate}%</td>
          </tr>
          <tr>
            <td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">Total Repayable</td>
            <td style="padding: 8px; border: 1px solid #ddd;">KES ${loanDetails.terms.totalAmount.toLocaleString()}</td>
          </tr>
          <tr>
            <td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">Due Date</td>
            <td style="padding: 8px; border: 1px solid #ddd;">${new Date(loanDetails.terms.dueDate).toLocaleDateString()}</td>
          </tr>
        </table>
      </div>
      
      <p><strong>Repayment Instructions:</strong></p>
      <p>Please make payments to:</p>
      <ul>
        <li>Paybill: 522533</li>
        <li>Account: 7883032</li>
      </ul>
      
      <p style="margin-top: 30px;">Thank you for choosing Fonte Lenders.</p>
    </div>
  `;
}
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
    loan.lastStatusUpdate = new Date();

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

app.get('/api/verify-days-calculation/:loanId', authenticateAdmin, async (req, res) => {
    try {
        const loan = await LoanApplication.findById(req.params.id);
        if (!loan) return res.status(404).json({ error: 'Loan not found' });

        // STANDARDIZED CALCULATION
        const serverCalculation = calculateDaysRemaining(loan.dueDate);
        
        res.json({
            success: true,
            loanId: loan._id,
            dueDate: loan.dueDate,
            serverCalculation,
            serverTime: new Date(),
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
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
    
    // Get total remaining amount (including interest and overdue fees)
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

// ==================== PAYMENT STATUS MANAGEMENT ====================
app.patch('/api/admin/payments/:id/status', authenticateAdmin, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const { status, reason } = req.body;
    const startTime = Date.now();
    
    // Validate input
    if (!['approved', 'rejected'].includes(status)) {
      await session.abortTransaction();
      return res.status(400).json({ 
        success: false, 
        code: 'INVALID_STATUS',
        message: 'Invalid status value' 
      });
    }

    // Additional validation for rejections
    if (status === 'rejected') {
      if (!reason || reason.trim().length < 5) {
        await session.abortTransaction();
        return res.status(400).json({ 
          success: false, 
          code: 'INVALID_REASON',
          message: 'Rejection reason must be at least 5 characters' 
        });
      }
    }

    // Find payment with session
    const payment = await Payment.findById(req.params.id)
      .populate('userId', 'fullName phoneNumber email currentLoanBalance activeLoan')
      .populate('loanId', 'amount amountPaid totalAmount status repaymentSchedule lastStatusUpdate')
      .session(session);

    if (!payment) {
      await session.abortTransaction();
      return res.status(404).json({ 
        success: false, 
        code: 'PAYMENT_NOT_FOUND',
        message: 'Payment not found' 
      });
    }

    // Check current payment status
    if (payment.status !== 'pending') {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        code: 'INVALID_PAYMENT_STATUS',
        message: `Payment status is already "${payment.status}"`,
        currentStatus: payment.status
      });
    }

    // Process approval
    if (status === 'approved') {
      try {
        const loan = payment.loanId;
        const customer = payment.userId;
        const paymentAmount = payment.amount;

        // Update loan amount paid
        loan.amountPaid = (loan.amountPaid || 0) + paymentAmount;
        
        // Apply payment to installments
        let remainingAmount = paymentAmount;
        for (const installment of loan.repaymentSchedule) {
          if (['pending', 'partial'].includes(installment.status)) {
            const amountDue = installment.amount - (installment.paidAmount || 0);
            const amountToApply = Math.min(remainingAmount, amountDue);
            
            installment.paidAmount = (installment.paidAmount || 0) + amountToApply;
            installment.paidAt = new Date();
            
            if (installment.paidAmount >= installment.amount) {
              installment.status = 'paid';
            } else if (amountToApply > 0) {
              installment.status = 'partial';
            }
            
            remainingAmount -= amountToApply;
            if (remainingAmount <= 0) break;
          }
        }
        
        // Check if loan is fully paid
        const isLoanCompleted = loan.amountPaid >= loan.totalAmount;
        if (isLoanCompleted) {
          loan.status = 'completed';
          loan.lastStatusUpdate = new Date();
          customer.activeLoan = null;
        }
        
        // Update customer balance
        customer.currentLoanBalance = Math.max(0, customer.currentLoanBalance - paymentAmount);
        
        // Update payment status
        payment.status = 'approved';
        payment.completedAt = new Date();
        payment.approvedBy = req.admin.username;
        
        // Save all changes in transaction
        await Promise.all([
          loan.save({ session }),
          customer.save({ session }),
          payment.save({ session })
        ]);
        
        await session.commitTransaction();
        
        // Prepare response
        const responseData = {
          paymentId: payment._id,
          amount: paymentAmount,
          newBalance: customer.currentLoanBalance,
          loanId: loan._id,
          isFullyPaid: isLoanCompleted,
          adminName: req.admin.username,
          userId: customer._id
        };

        // Send notifications (non-blocking)
        setImmediate(() => {
          try {
            io.to(`user_${customer._id}`).emit('paymentApproved', responseData);
            if (isLoanCompleted) {
              io.to(`user_${customer._id}`).emit('loanCompleted', {
                loanId: loan._id,
                amountPaid: paymentAmount
              });
            }
          } catch (socketError) {
            console.error('Socket notification failed:', socketError);
          }
        });

        return res.json({
          success: true,
          message: 'Payment approved successfully',
          data: responseData
        });

      } catch (error) {
        await session.abortTransaction();
        throw error;
      }
    } 
    // Process rejection
    else {
      try {
        payment.status = 'rejected';
        payment.rejectionReason = reason;
        payment.rejectedAt = new Date();
        payment.rejectedBy = req.admin.username;
        
        await payment.save({ session });
        await session.commitTransaction();
        
        const responseData = {
          paymentId: payment._id,
          amount: payment.amount,
          reason: reason,
          adminName: req.admin.username,
          userId: payment.userId._id
        };

        setImmediate(() => {
          try {
            io.to(`user_${payment.userId._id}`).emit('paymentRejected', responseData);
          } catch (socketError) {
            console.error('Socket notification failed:', socketError);
          }
        });

        return res.json({
          success: true,
          message: 'Payment rejected successfully',
          data: responseData
        });
      } catch (error) {
        await session.abortTransaction();
        throw error;
      }
    }
  } catch (error) {
    console.error('Payment status update error:', error);
    
    // Ensure session is properly ended
    if (session.inTransaction()) {
      await session.abortTransaction();
    }

    let errorMessage = 'Failed to update payment status';
    let statusCode = 500;
    
    if (error.code === 251) { // MongoDB transaction error
      errorMessage = 'Transaction error occurred. Please try again.';
      statusCode = 503; // Service Unavailable
    }

    res.status(statusCode).json({
      success: false,
      code: error.codeName || 'PAYMENT_UPDATE_FAILED',
      message: errorMessage,
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  } finally {
    await session.endSession();
  }
});

app.get('/api/admin/pending-payments', authenticateAdmin, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;
        
        const [payments, count] = await Promise.all([
            Payment.find({ status: 'pending' })
                .populate('userId', 'fullName phoneNumber')
                .populate('loanId', 'amount amountPaid')
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit),
                
            Payment.countDocuments({ status: 'pending' })
        ]);
        
        res.json({
            success: true,
            payments,
            totalPages: Math.ceil(count / limit),
            currentPage: page
        });
        
    } catch (error) {
        console.error('Failed to fetch pending payments:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch pending payments',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Record manual payment
app.post('/api/admin/loans/:id/record-payment', authenticateAdmin, async (req, res) => {
  try {
    const { amount, reference } = req.body;
    const loanId = req.params.id;
    
    // Find the loan
    const loan = await LoanApplication.findById(loanId);
    if (!loan) {
      return res.status(404).json({ success: false, message: 'Loan not found' });
    }
    
    // Create payment record
    const payment = new Payment({
      userId: loan.userId,
      loanId: loan._id,
      amount,
      reference: reference || `MANUAL-${Date.now()}`,
      paymentMethod: 'Manual',
      status: 'approved'
    });
    
    // Update loan status
    loan.amountPaid = (loan.amountPaid || 0) + amount;
    if (loan.amountPaid >= loan.totalAmount) {
      loan.status = 'completed';
      loan.lastStatusUpdate = new Date();
      
      // Update customer
      await Customer.findByIdAndUpdate(loan.userId, {
        $set: { activeLoan: null },
        $inc: { currentLoanBalance: -amount }
      });
    } else {
      await Customer.findByIdAndUpdate(loan.userId, {
        $inc: { currentLoanBalance: -amount }
      });
    }
    
    // Save changes
    await Promise.all([payment.save(), loan.save()]);
    
    res.json({ 
      success: true,
      message: `Payment of KES ${amount} recorded`,
      newBalance: loan.totalAmount - loan.amountPaid
    });
    
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Download loan documents
app.get('/api/admin/loans/:id/documents', authenticateAdmin, async (req, res) => {
  try {
    const loan = await LoanApplication.findById(req.params.id);
    if (!loan) {
      return res.status(404).json({ success: false, message: 'Loan not found' });
    }
    
    // In a real implementation, this would fetch from storage
    const documents = [
      { name: 'Loan Agreement', url: `/api/documents/${loan._id}/agreement` },
      { name: 'Repayment Schedule', url: `/api/documents/${loan._id}/schedule` }
    ];
    
    res.json({ success: true, documents });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Generate reports
app.get('/api/admin/reports/:type', authenticateAdmin, async (req, res) => {
  try {
    const { type } = req.params;
    const { startDate, endDate } = req.query;
    
    // In a real implementation, this would query the database
    const reportData = {
      title: `${type.charAt(0).toUpperCase() + type.slice(1)} Report`,
      startDate,
      endDate,
      totalLoans: 15,
      newCustomers: 8,
      repaymentsReceived: 120000,
      defaultRate: 5.2,
      dailyActivity: [
        { date: '2023-06-01', newLoans: 3, repayments: 30000, defaults: 0 },
        { date: '2023-06-02', newLoans: 2, repayments: 25000, defaults: 1 }
      ]
    };
    
    res.json({ 
      success: true,
      data: reportData
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
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
    loan.lastStatusUpdate = new Date();
    
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
    console.log('Fetching profile for user:', req.user._id);
    
    const user = await Customer.findById(req.user._id)
      .select('-password -__v')
      .populate({
        path: 'activeLoan',
        match: { $or: [{ status: 'active' }, { status: 'defaulted' }] },
        select: 'amount amountPaid dueDate repaymentSchedule status totalAmount principal interestRate overdueDays overdueFees lastOverdueCalculation purpose'
      })
      .lean();

    if (!user) {
      console.log('User not found:', req.user._id);
      return res.status(404).json({ 
        success: false, 
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    // Calculate days overdue if loan is defaulted
    if (user.activeLoan?.status === 'defaulted') {
      const now = new Date();
      const dueDate = new Date(user.activeLoan.dueDate);
      const daysOverdue = Math.floor((now - dueDate) / (1000 * 60 * 60 * 24));
      
      if (daysOverdue > (user.activeLoan.overdueDays || 0)) {
        const overdueFees = user.activeLoan.principal * 0.06 * daysOverdue;
        user.activeLoan.overdueDays = daysOverdue;
        user.activeLoan.overdueFees = overdueFees;
        user.activeLoan.totalAmount = user.activeLoan.principal + (user.activeLoan.interestAmount || 0) + overdueFees;
        
        await LoanApplication.updateOne(
          { _id: user.activeLoan._id },
          { 
            overdueDays: daysOverdue,
            overdueFees: overdueFees,
            totalAmount: user.activeLoan.totalAmount,
            lastOverdueCalculation: new Date()
          }
        );
      }
    }

    // Get payment history and pending payments
    const [paymentHistory, pendingPayments] = await Promise.all([
      Payment.find({ userId: user._id })
        .sort({ createdAt: -1 })
        .limit(5)
        .lean(),
      Payment.find({
        userId: user._id,
        status: 'pending'
      }).lean()
    ]);

    // Calculate available limit
    const availableLimit = Math.max(0, (user.maxLoanLimit || 0) - (user.currentLoanBalance || 0));

    // Prepare loan details if active loan exists
    let loanDetails = null;
    if (user.activeLoan) {
      const now = new Date();
      const dueDate = new Date(user.activeLoan.dueDate);
      const daysRemaining = Math.ceil((dueDate - now) / (1000 * 60 * 60 * 24));
      const totalPaid = user.activeLoan.amountPaid || 0;
      const progress = user.activeLoan.totalAmount > 0 
        ? (totalPaid / user.activeLoan.totalAmount) * 100 
        : 0;
      
      loanDetails = {
        amount: user.activeLoan.amount,
        principal: user.activeLoan.principal,
        interestRate: user.activeLoan.interestRate,
        interestAmount: user.activeLoan.interestAmount,
        totalAmount: user.activeLoan.totalAmount,
        amountPaid: totalPaid,
        amountRemaining: user.activeLoan.totalAmount - totalPaid,
        progress: Math.round(progress * 100) / 100,
        purpose: user.activeLoan.purpose,
        status: user.activeLoan.status,
        dueDate: user.activeLoan.dueDate,
        daysRemaining: Math.max(daysRemaining, 0),
        overdueDays: user.activeLoan.overdueDays || 0,
        overdueFees: user.activeLoan.overdueFees || 0,
        lastPayment: user.activeLoan.repaymentSchedule?.slice(-1)[0] || null
      };
    }

    // Standardized response format
    const response = {
      success: true,
      user: {
        ...user,
        _id: user._id.toString(),
        maxLoanLimit: user.maxLoanLimit || 0,
        currentLoanBalance: user.currentLoanBalance || 0,
        availableLimit,
        verificationStatus: user.verificationStatus || 'pending'
      },
      activeLoan: loanDetails,
      paymentHistory: paymentHistory || [],
      pendingPayments: pendingPayments || []
    };

    console.log('Profile response prepared for:', user._id, {
      hasActiveLoan: !!user.activeLoan,
      paymentCount: paymentHistory.length,
      pendingPayments: pendingPayments.length
    });

    res.json(response);

  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to load profile',
      code: 'PROFILE_FETCH_ERROR',
      systemError: process.env.NODE_ENV === 'development' ? error.message : undefined
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
// ==================== ENHANCED ERROR HANDLER ====================
app.use((err, req, res, next) => {
  // Log the full error in development, sanitized version in production
  if (process.env.NODE_ENV === 'development') {
    console.error('\x1b[31m', '=== ERROR DETAILS ==='); // Red color for errors
    console.error(err);
    console.error('Stack:', err.stack);
    console.error('\x1b[0m'); // Reset color
  } else {
    console.error(`[${new Date().toISOString()}] Error: ${err.message}`);
  }

  // Handle specific error types
  if (err instanceof mongoose.Error.TransactionError) {
    return res.status(500).json({
      success: false,
      code: 'TRANSACTION_ERROR',
      message: 'Database transaction failed',
      systemError: process.env.NODE_ENV === 'development' ? err.message : undefined,
      timestamp: new Date().toISOString(),
      requestId: req.id || null
    });
  }

  if (err instanceof mongoose.Error.ValidationError) {
    const errors = {};
    Object.keys(err.errors).forEach(key => {
      errors[key] = err.errors[key].message;
    });

    return res.status(400).json({
      success: false,
      code: 'VALIDATION_ERROR',
      message: 'Validation failed',
      errors,
      timestamp: new Date().toISOString()
    });
  }

  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({
      success: false,
      code: 'AUTHENTICATION_ERROR',
      message: 'Authentication failed',
      timestamp: new Date().toISOString()
    });
  }

  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({
      success: false,
      code: 'FILE_TOO_LARGE',
      message: 'File size exceeds the limit',
      maxSize: process.env.MAX_FILE_SIZE || '5MB',
      timestamp: new Date().toISOString()
    });
  }

  // Handle JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      code: 'INVALID_TOKEN',
      message: 'Invalid authentication token',
      timestamp: new Date().toISOString()
    });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      code: 'TOKEN_EXPIRED',
      message: 'Authentication token has expired',
      timestamp: new Date().toISOString()
    });
  }

  // Default error handler
  const statusCode = err.statusCode || 500;
  const errorResponse = {
    success: false,
    code: err.code || 'SERVER_ERROR',
    message: err.message || 'Internal server error',
    timestamp: new Date().toISOString(),
    requestId: req.id || null
  };

  // Only include stack trace in development
  if (process.env.NODE_ENV === 'development') {
    errorResponse.stack = err.stack;
  }

  // Include additional details for 500 errors
  if (statusCode === 500) {
    errorResponse.message = 'Internal server error'; // Override specific message for production
    if (process.env.NODE_ENV !== 'production') {
      errorResponse.systemError = err.message;
    }
    
    // Log critical errors to external service
    if (process.env.ERROR_REPORTING_SERVICE === 'true') {
      logErrorToService(err, req);
    }
  }

  res.status(statusCode).json(errorResponse);
});

// Helper function to log errors to external service
function logErrorToService(err, req) {
  const errorData = {
    timestamp: new Date().toISOString(),
    message: err.message,
    stack: err.stack,
    code: err.code,
    request: {
      method: req.method,
      url: req.originalUrl,
      params: req.params,
      query: req.query,
      headers: sanitizeHeaders(req.headers),
      ip: req.ip
    },
    environment: process.env.NODE_ENV
  };

  // In production, you would send this to an error tracking service
  if (process.env.NODE_ENV === 'production') {
    // Example: Sentry.captureException(errorData);
    console.error('Error report:', JSON.stringify(errorData, null, 2));
  }
}

function sanitizeHeaders(headers) {
  const sensitiveFields = ['authorization', 'cookie', 'token'];
  const sanitized = {...headers};
  
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '***REDACTED***';
    }
  });
  
  return sanitized;
}

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

// ==================== LOAN STATUS UPDATE JOB ====================
const updateLoanStatusesJob = async () => {
  try {
    await LoanApplication.updateLoanStatuses();
  } catch (error) {
    console.error('Loan status update job failed:', error);
  }
};

// Run every hour
setInterval(updateLoanStatusesJob, 60 * 60 * 1000);
// Also run immediately on startup
updateLoanStatusesJob();

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