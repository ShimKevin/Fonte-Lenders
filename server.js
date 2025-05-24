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

const app = express();
const PORT = process.env.PORT || 3001;

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
    // First check if we're in development mode and should use mock verification
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

    // Verify the domain is reachable first
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
        timeout: 10000 // 10 second timeout
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
    
    // Enhanced error handling
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
    
    // Fallback verification for other errors
    if (process.env.ENABLE_FALLBACK_VERIFICATION === 'true') {
      console.log('Attempting fallback verification...');
      return {
        success: true, // Mark as success but flag as fallback
        verifiedBy: 'fallback',
        message: 'Verification pending manual review',
        fallback: true,
        timestamp: new Date().toISOString()
      };
    }
    
    throw error; // Re-throw if no fallback is enabled
  }
}

// ==================== CONFIGURATION ====================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://fonte-lenders.onrender.com'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.static(path.join(__dirname, 'public')));

// Enhanced JSON response middleware
app.use((req, res, next) => {
  res.jsonResponse = (data, status = 200) => {
    res.status(status).json({
      success: status >= 200 && status < 300,
      ...data
    });
  };
  next();
});

// ==================== MIDDLEWARE ====================
const loginAttempts = new Map();

// Enhanced rate limiting middleware for login attempts
const loginRateLimiter = (req, res, next) => {
  if (req.path === '/api/login' && req.method === 'POST') {
    const key = `${req.ip}-${req.body.phone}`;
    const now = Date.now();
    
    if (loginAttempts.has(key)) {
      const lastAttempt = loginAttempts.get(key);
      if (now - lastAttempt < 2000) { // 2 second cooldown
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

// Silent authentication middleware (for optional auth routes)
const silentAuth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      req.authFailed = true;
      return next();
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await Customer.findById(decoded.id).select('-password').lean();
    
    if (!user) {
      req.authFailed = true;
      return next();
    }

    // Check token expiration (7 days)
    if (decoded.iat < Math.floor(Date.now() / 1000) - (60 * 60 * 24 * 7)) {
      req.authFailed = true;
      return next();
    }

    req.user = user;
    next();
  } catch (error) {
    req.authFailed = true;
    next();
  }
};

// Main authentication middleware (for protected routes)
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ 
        success: false, 
        code: 'NO_TOKEN',
        redirect: '/login?error=no_token'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await Customer.findById(decoded.id).select('-password').lean();
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        code: 'USER_NOT_FOUND',
        redirect: '/login?error=user_not_found'
      });
    }

    // Check token expiration (7 days)
    if (decoded.iat < Math.floor(Date.now() / 1000) - (60 * 60 * 24 * 7)) {
      return res.status(401).json({
        success: false,
        code: 'SESSION_EXPIRED',
        redirect: '/login?error=session_expired'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    
    let errorResponse = {
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
  }
};

// Admin authentication middleware
const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ 
        success: false, 
        code: 'NO_TOKEN',
        redirect: '/admin/login?error=no_token'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.id).select('-password').lean();
    
    if (!admin) {
      return res.status(401).json({ 
        success: false, 
        code: 'ADMIN_NOT_FOUND',
        redirect: '/admin/login?error=admin_not_found'
      });
    }

    // Additional admin-specific checks
    if (admin.role !== 'superadmin' && req.method !== 'GET') {
      return res.status(403).json({
        success: false,
        code: 'FORBIDDEN',
        redirect: '/admin/dashboard?error=insufficient_privileges'
      });
    }

    // Check token expiration (7 days)
    if (decoded.iat < Math.floor(Date.now() / 1000) - (60 * 60 * 24 * 7)) {
      return res.status(401).json({
        success: false,
        code: 'SESSION_EXPIRED',
        redirect: '/admin/login?error=session_expired'
      });
    }

    req.admin = admin;
    next();
  } catch (error) {
    console.error('Admin authentication error:', error);
    
    let errorResponse = {
      success: false,
      code: 'ADMIN_AUTH_FAILED',
      redirect: '/admin/login?error=auth_failed'
    };

    if (error.name === 'TokenExpiredError') {
      errorResponse.code = 'ADMIN_SESSION_EXPIRED';
      errorResponse.redirect = '/admin/login?error=session_expired';
    } else if (error.name === 'JsonWebTokenError') {
      errorResponse.code = 'INVALID_TOKEN';
      errorResponse.redirect = '/admin/login?error=invalid_token';
    }

    return res.status(401).json(errorResponse);
  }
};

// Token refresh middleware
const refreshTokenMiddleware = async (req, res, next) => {
  try {
    const refreshToken = req.headers['x-refresh-token'];
    if (!refreshToken) return next();

    const tokenDoc = await Token.findOne({ token: refreshToken }).populate('userId');
    if (!tokenDoc || tokenDoc.expiresAt < new Date()) {
      await Token.deleteOne({ _id: tokenDoc?._id });
      return next();
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

    res.set('X-New-Token', newToken);
    next();
  } catch (error) {
    console.error('Token refresh error:', error);
    next();
  }
};

// Apply middleware in your app
app.use(loginRateLimiter); // Apply to all routes

// ==================== MODELS ====================
const loanApplicationSchema = new mongoose.Schema({
  customerId: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'Customer', required: true },
  fullName: { type: String, required: true },
  phoneNumber: { type: String, required: true },
  email: String,
  amount: { type: Number, required: true, min: 1000, max: 300000 },
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
  rejectedAt: Date
}, { timestamps: true });

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
  lastLogin: Date
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

customerSchema.methods.debugPassword = async function(candidatePassword) {
  const match = await bcrypt.compare(candidatePassword, this.password);
  console.log('Password comparison:', {
    storedHash: this.password,
    candidate: candidatePassword,
    match: match
  });
  return match;
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

const LoanApplication = mongoose.model('LoanApplication', loanApplicationSchema);
const Customer = mongoose.model('Customer', customerSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Token = mongoose.model('Token', tokenSchema);

// Example route using the improved Jenga integration
app.post('/api/verify-id', async (req, res) => {
  try {
    const { idNumber, fullName } = req.body;
    
    const verification = await verifyIDWithJenga(idNumber, fullName);
    
    res.json({
      success: verification.success,
      verifiedBy: verification.verifiedBy,
      message: verification.message,
      timestamp: verification.timestamp
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Verification service error'
    });
  }
});

// Health check endpoint
app.get('/api/jenga-status', async (req, res) => {
  const status = await getJengaStatus();
  res.json(status);
});

// For protected routes
app.get('/api/user/profile', authenticate, (req, res) => {
  res.json({ success: true, user: req.user });
});

// For admin routes
app.get('/api/admin/dashboard', authenticateAdmin, (req, res) => {
  res.json({ success: true, admin: req.admin });
});

// For routes with optional authentication
app.get('/api/public/content', silentAuth, (req, res) => {
  const response = { success: true, public: true };
  if (req.user) response.user = req.user;
  res.json(response);
});

// For token refresh
app.post('/api/refresh-token', refreshTokenMiddleware, (req, res) => {
  res.json({ success: true });
});

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

// ==================== ROUTES ====================

// Admin Page Routes
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

    // Trim all string inputs
    const cleanPassword = password.trim();
    const cleanPhone = phone.replace(/\D/g, '').trim();
    const cleanEmail = email ? email.trim() : null;
    const cleanFullName = fullName.trim();
    const cleanIdNumber = idNumber.trim();

    // Input validation
    if (!cleanFullName || !cleanIdNumber || !phone || !cleanPassword) {
      return res.jsonResponse({
        success: false,
        message: 'All required fields must be provided',
        missingFields: [
          ...(!cleanFullName ? ['fullName'] : []),
          ...(!cleanIdNumber ? ['idNumber'] : []),
          ...(!phone ? ['phone'] : []),
          ...(!cleanPassword ? ['password'] : [])
        ]
      }, 400);
    }

    if (cleanPassword.length < 6) {
      return res.jsonResponse({
        success: false,
        message: 'Password must be at least 6 characters',
        code: 'PASSWORD_TOO_SHORT'
      }, 400);
    }

    // Check for existing user
    const existingUser = await Customer.findOne({ 
      $or: [
        { customerId: cleanIdNumber }, 
        { phoneNumber: cleanPhone }
      ] 
    });
    
    if (existingUser) {
      return res.jsonResponse({
        success: false,
        message: 'User already exists with this ID or phone number',
        code: 'USER_EXISTS'
      }, 400);
    }

    // Create new customer - the pre-save hook will handle hashing
    const newCustomer = new Customer({
      fullName: cleanFullName,
      customerId: cleanIdNumber,
      phoneNumber: cleanPhone,
      email: cleanEmail,
      password: cleanPassword, // Will be hashed by pre-save hook
      verificationStatus: 'pending'
    });

    await newCustomer.save();

    // Debug log to verify password was hashed
    console.log('New user created with hashed password:', {
      userId: newCustomer._id,
      passwordHash: newCustomer.password
    });

    // Generate tokens
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

    // Prepare response data
    const userData = newCustomer.toObject();
    delete userData.password;

    // Send welcome email if email was provided
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

    // Successful response
    res.jsonResponse({
      success: true,
      message: 'Registration successful',
      token,
      refreshToken,
      user: userData
    }, 201);

  } catch (error) {
    console.error('Registration error:', error);
    res.jsonResponse({
      success: false,
      message: 'Registration failed. Please try again.',
      code: 'REGISTRATION_FAILED',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    }, 500);
  }
});

app.post('/api/login', async (req, res) => {
  try {
    console.log('Login request body:', req.body);
    
    const { phone, password } = req.body;
    const cleanPhone = phone.replace(/\D/g, '').trim();
    const cleanPassword = password.trim();

    // Find user and explicitly include password field
    const user = await Customer.findOne({
      $or: [
        { phoneNumber: cleanPhone },
        { phoneNumber: `254${cleanPhone.substring(cleanPhone.length - 9)}` },
        { phoneNumber: `0${cleanPhone.substring(cleanPhone.length - 9)}` }
      ]
    }).select('+password'); // This is crucial

    if (!user) {
      console.log('User not found for phone:', cleanPhone);
      return res.jsonResponse({
        success: false,
        message: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      }, 401);
    }

    console.log('Found user:', {
      id: user._id,
      phone: user.phoneNumber,
      storedHash: user.password // Now this will show the actual hash
    });

    // Compare passwords
    const isMatch = await user.comparePassword(cleanPassword);
    if (!isMatch) {
      console.log('Password does not match');
      return res.jsonResponse({
        success: false,
        message: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      }, 401);
    }

    // Rest of your login success logic...
    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      { 
        id: user._id,
        phone: user.phoneNumber,
        customerId: user.customerId 
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
    );

    const refreshToken = crypto.randomBytes(40).toString('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    
    await Token.create({
      userId: user._id,
      token: refreshToken,
      expiresAt
    });

    const userData = user.toObject();
    delete userData.password;

    res.jsonResponse({
      success: true,
      token,
      refreshToken,
      user: userData,
      message: 'Login successful'
    });

  } catch (error) {
    console.error('Login error:', error);
    res.jsonResponse({
      success: false,
      message: 'Login failed. Please try again.',
      code: 'LOGIN_FAILED'
    }, 500);
  }
});

// ==================== PASSWORD RESET ENDPOINTS (FIXED) ====================

app.post('/api/request-password-reset', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.jsonResponse({
        success: false,
        message: 'Email is required',
        code: 'EMAIL_REQUIRED'
      }, 400);
    }

    const cleanEmail = email.trim();
    const user = await Customer.findOne({ email: cleanEmail });
    
    // Always return success to prevent email enumeration
    const response = {
      success: true,
      message: 'If this email is registered, you will receive a reset code shortly.'
    };

    if (user) {
      // Generate a 6-digit token
      const token = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes expiry

      // Delete any existing password reset tokens for this user
      await Token.deleteMany({ 
        userId: user._id,
        purpose: 'password_reset'
      });

      // Create new token
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

      // Send email with token
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

    res.jsonResponse(response);

  } catch (error) {
    console.error('Password reset request error:', error);
    res.jsonResponse({
      success: false,
      message: 'Failed to process password reset request',
      code: 'RESET_REQUEST_FAILED'
    }, 500);
  }
});

app.post('/api/verify-reset-token', async (req, res) => {
  try {
    const { email, token } = req.body;
    
    if (!email || !token) {
      return res.jsonResponse({
        success: false,
        message: 'Email and token are required',
        code: 'MISSING_FIELDS'
      }, 400);
    }

    const cleanEmail = email.trim();
    const cleanToken = token.trim();

    const user = await Customer.findOne({ email: cleanEmail });
    if (!user) {
      console.log(`User not found for email: ${cleanEmail}`);
      return res.jsonResponse({
        success: false,
        message: 'Invalid request',
        code: 'INVALID_REQUEST'
      }, 400);
    }

    // Find token that's not expired
    const tokenDoc = await Token.findOne({ 
      userId: user._id,
      token: cleanToken,
      purpose: 'password_reset',
      expiresAt: { $gt: new Date() } // Only find tokens that haven't expired
    });

    if (!tokenDoc) {
      console.log(`Invalid or expired token for user ${user._id}: ${cleanToken}`);
      // Check if there's an expired token
      const expiredToken = await Token.findOne({
        userId: user._id,
        token: cleanToken,
        purpose: 'password_reset'
      });
      
      if (expiredToken) {
        console.log('Found expired token, deleting it');
        await Token.deleteOne({ _id: expiredToken._id });
        return res.jsonResponse({
          success: false,
          message: 'Verification code has expired. Please request a new one.',
          code: 'TOKEN_EXPIRED'
        }, 400);
      }
      
      return res.jsonResponse({
        success: false,
        message: 'Invalid verification code',
        code: 'INVALID_TOKEN'
      }, 400);
    }

    console.log(`Valid token found for user ${user._id}`);

    res.jsonResponse({
      success: true,
      message: 'Verification successful',
      resetToken: tokenDoc.token // Return the same token for the next step
    });

  } catch (error) {
    console.error('Token verification error:', error);
    res.jsonResponse({
      success: false,
      message: 'Failed to verify code',
      code: 'TOKEN_VERIFICATION_FAILED'
    }, 500);
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, token, newPassword, confirmPassword } = req.body;
    
    if (!email || !token || !newPassword || !confirmPassword) {
      return res.jsonResponse({
        success: false,
        message: 'All fields are required',
        code: 'MISSING_FIELDS'
      }, 400);
    }

    const cleanEmail = email.trim();
    const cleanToken = token.trim();
    const cleanNewPassword = newPassword.trim();
    const cleanConfirmPassword = confirmPassword.trim();

    if (cleanNewPassword !== cleanConfirmPassword) {
      return res.jsonResponse({
        success: false,
        message: 'Passwords do not match',
        code: 'PASSWORD_MISMATCH'
      }, 400);
    }

    if (cleanNewPassword.length < 8) {
      return res.jsonResponse({
        success: false,
        message: 'Password must be at least 8 characters',
        code: 'PASSWORD_TOO_SHORT'
      }, 400);
    }

    const user = await Customer.findOne({ email: cleanEmail });
    if (!user) {
      console.log(`User not found during password reset: ${cleanEmail}`);
      return res.jsonResponse({
        success: false,
        message: 'Invalid request',
        code: 'INVALID_REQUEST'
      }, 400);
    }

    // Find token that's not expired
    const tokenDoc = await Token.findOne({ 
      userId: user._id,
      token: cleanToken,
      purpose: 'password_reset',
      expiresAt: { $gt: new Date() }
    });

    if (!tokenDoc) {
      console.log(`Invalid or expired token during password reset for user ${user._id}`);
      return res.jsonResponse({
        success: false,
        message: 'Session expired. Please start the reset process again.',
        code: 'SESSION_EXPIRED'
      }, 400);
    }

    console.log(`Resetting password for user ${user._id}`);

    // Set the new password - pre-save hook will hash it
    user.password = cleanNewPassword;
    await user.save();

    // Delete the used token
    await Token.deleteOne({ _id: tokenDoc._id });

    // Send confirmation email
    await sendEmail({
      to: user.email,
      subject: 'Your Password Has Been Reset',
      html: `
        <h2>Password Reset Successful</h2>
        <p>Your Fonte Lenders password has been successfully reset.</p>
        <p>If you didn't make this change, please contact support immediately.</p>
      `
    });

    res.jsonResponse({
      success: true,
      message: 'Password reset successful'
    });

  } catch (error) {
    console.error('Password reset error:', error);
    res.jsonResponse({
      success: false,
      message: 'Failed to reset password',
      code: 'PASSWORD_RESET_FAILED'
    }, 500);
  }
});

app.post('/api/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.jsonResponse({
        success: false,
        message: 'Refresh token is required',
        code: 'MISSING_REFRESH_TOKEN'
      }, 400);
    }

    const tokenDoc = await Token.findOne({ token: refreshToken }).populate('userId');
    if (!tokenDoc) {
      return res.jsonResponse({
        success: false,
        message: 'Invalid refresh token',
        code: 'INVALID_REFRESH_TOKEN'
      }, 401);
    }

    if (tokenDoc.expiresAt < new Date()) {
      await Token.deleteOne({ _id: tokenDoc._id });
      return res.jsonResponse({
        success: false,
        message: 'Refresh token expired',
        code: 'REFRESH_TOKEN_EXPIRED'
      }, 401);
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

    res.jsonResponse({
      success: true,
      token: newToken,
      refreshToken: newRefreshToken
    });

  } catch (error) {
    console.error('Token refresh error:', error);
    res.jsonResponse({
      success: false,
      message: 'Failed to refresh token',
      code: 'TOKEN_REFRESH_FAILED'
    }, 500);
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

    // Input validation
    const requiredFields = { 
      amount, 
      guarantorName, 
      guarantorId, 
      guarantorPhone,
      signature 
    };
    
    const missingFields = Object.entries(requiredFields)
      .filter(([key, value]) => !value)
      .map(([key]) => key);

    if (missingFields.length > 0) {
      return res.jsonResponse({
        success: false,
        message: 'Missing required fields',
        missingFields,
        code: 'MISSING_REQUIRED_FIELDS'
      }, 400);
    }

    // Validate amount is a number
    if (isNaN(amount)) {
      return res.jsonResponse({
        success: false,
        message: 'Amount must be a valid number',
        code: 'INVALID_AMOUNT'
      }, 400);
    }

    const numericAmount = parseFloat(amount);
    if (numericAmount <= 0) {
      return res.jsonResponse({
        success: false,
        message: 'Amount must be greater than 0',
        code: 'INVALID_AMOUNT'
      }, 400);
    }

    // Get customer with financial details
    const customer = await Customer.findById(req.user._id)
      .select('+customerId +fullName +phoneNumber +email +maxLoanLimit +currentLoanBalance');
    
    if (!customer) {
      return res.jsonResponse({
        success: false,
        message: 'Customer not found',
        code: 'CUSTOMER_NOT_FOUND'
      }, 404);
    }

    // Check loan limits
    const availableLimit = customer.maxLoanLimit - customer.currentLoanBalance;
    if (numericAmount > availableLimit) {
      return res.jsonResponse({
        success: false,
        message: 'Loan limit exceeded',
        details: `Your available limit is KES ${availableLimit.toLocaleString()}`,
        availableLimit,
        code: 'LOAN_LIMIT_EXCEEDED'
      }, 400);
    }

    // Verify customer and guarantor IDs with enhanced error handling
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
      
      // If fallback is enabled, create verifications with fallback status
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
        return res.jsonResponse({
          success: false,
          message: 'ID verification service unavailable',
          details: error.message,
          code: 'VERIFICATION_SERVICE_UNAVAILABLE'
        }, 503);
      }
    }

    // Check verification results
    if (!customerVerification.success || !guarantorVerification.success) {
      return res.jsonResponse({
        success: false,
        message: 'Verification failed',
        customerVerified: customerVerification.success,
        guarantorVerified: guarantorVerification.success,
        requiresManualVerification: customerVerification.fallback || guarantorVerification.fallback,
        code: 'VERIFICATION_FAILED'
      }, 400);
    }

    // Create loan application
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

    // Send notifications (async - don't wait for completion)
    sendLoanApplicationNotifications(customer, application, availableLimit, customerVerification);

    return res.jsonResponse({
      success: true,
      message: customerVerification.fallback 
        ? 'Application submitted (pending manual verification)' 
        : 'Loan application submitted successfully',
      applicationId: application._id,
      verification: {
        customer: customerVerification,
        guarantor: guarantorVerification
      },
      requiresManualVerification: customerVerification.fallback,
      code: 'LOAN_APPLICATION_SUBMITTED'
    }, 201);

  } catch (error) {
    console.error('Loan submission error:', error);
    return res.jsonResponse({
      success: false,
      message: 'Error submitting application',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      code: 'LOAN_SUBMISSION_ERROR'
    }, 500);
  }
});

// Helper function for sending notifications
async function sendLoanApplicationNotifications(customer, application, availableLimit, verification) {
  try {
    // Send admin notification
    await sendEmail({
      to: process.env.ADMIN_EMAIL,
      subject: 'New Loan Application Submitted',
      html: generateAdminNotificationEmail(customer, application, availableLimit)
    });

    // Send customer confirmation if email exists
    if (customer.email) {
      await sendEmail({
        to: customer.email,
        subject: 'Your Loan Application Has Been Received',
        html: generateCustomerConfirmationEmail(customer, application, verification)
      });
    }

    // Optionally send SMS notification if configured
    if (process.env.SMS_SERVICE_ENABLED === 'true') {
      await sendSMSNotification(customer.phoneNumber, application);
    }
  } catch (error) {
    console.error('Notification error:', error);
    // Don't throw - notifications are non-critical
  }
}

// SMS notification function (placeholder)
async function sendSMSNotification(phoneNumber, application) {
  // Implement your SMS service integration here
  console.log(`SMS notification would be sent to ${phoneNumber} for application ${application._id}`);
}

// Email template generators
function generateAdminNotificationEmail(customer, application, availableLimit) {
  return `
    <h2>New Loan Application Received</h2>
    
    <h3>Customer Details</h3>
    <p><strong>Name:</strong> ${customer.fullName}</p>
    <p><strong>Phone:</strong> ${customer.phoneNumber || 'Not provided'}</p>
    <p><strong>ID Number:</strong> ${customer.customerId || 'Not provided'}</p>
    <p><strong>Email:</strong> ${customer.email || 'Not provided'}</p>
    
    <h3>Loan Details</h3>
    <p><strong>Amount:</strong> KES ${application.amount.toLocaleString()}</p>
    <p><strong>Purpose:</strong> ${application.purpose || 'Not specified'}</p>
    <p><strong>Available Limit:</strong> KES ${availableLimit.toLocaleString()}</p>
    
    <h3>Guarantor Details</h3>
    <p><strong>Name:</strong> ${application.guarantor.name}</p>
    <p><strong>ID Number:</strong> ${application.guarantor.idNumber}</p>
    <p><strong>Phone:</strong> ${application.guarantor.phoneNumber}</p>
    <p><strong>Relationship:</strong> ${application.guarantor.relationship}</p>
    
    <h3>Verification Status</h3>
    <p><strong>Customer:</strong> ${application.verificationData.customer.status} 
       (${application.verificationData.customer.fallback ? 'Fallback' : 'Automated'})</p>
    <p><strong>Guarantor:</strong> ${application.verificationData.guarantor.status}
       (${application.verificationData.guarantor.fallback ? 'Fallback' : 'Automated'})</p>
    
    <p><strong>Application ID:</strong> ${application._id}</p>
    <p><strong>Submitted:</strong> ${application.createdAt.toLocaleString()}</p>
  `;
}

function generateCustomerConfirmationEmail(customer, application, verification) {
  return `
    <h2>Dear ${customer.fullName},</h2>
    <p>We have received your loan application for <strong>KES ${application.amount.toLocaleString()}</strong>.</p>
    
    <h3>Application Summary</h3>
    <p><strong>Application ID:</strong> ${application._id}</p>
    <p><strong>Purpose:</strong> ${application.purpose || 'Personal Loan'}</p>
    <p><strong>Date Submitted:</strong> ${new Date().toLocaleString()}</p>
    
    ${verification.fallback 
      ? '<p>Note: Fonte Lenders are conducting a review of your application.</p>'
      : '<p>Your application is being processed within 24 hours.</p>'}
    
    <p>Thank you for choosing Fonte Lenders Services.</p>
  `;
}

// ==================== ERROR HANDLER ====================
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.jsonResponse({
    message: err.message || 'Internal Server Error'
  }, 500);
});

// ==================== SERVER STARTUP ====================
const startServer = async () => {
  try {
    const dbConnected = await connectWithRetry();
    if (!dbConnected) {
      throw new Error('Failed to connect to database after retries');
    }

    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📊 MongoDB state: ${mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'}`);
    });

    // Graceful shutdown
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

// ==================== PASSWORD MIGRATION SCRIPT ====================
async function migratePasswords() {
  try {
    console.log('Starting password migration...');
    await mongoose.connect(MONGODB_URI, mongooseOptions);
    
    const customers = await Customer.find();
    let updatedCount = 0;

    for (const customer of customers) {
      // Skip already hashed passwords
      if (customer.password.startsWith('$2a$') || customer.password.startsWith('$2b$')) {
        continue;
      }

      try {
        // Temporarily disable the pre-save hook
        Customer.schema.pre('save', function(next) { next(); });
        
        const salt = await bcrypt.genSalt(12);
        customer.password = await bcrypt.hash(customer.password, salt);
        await customer.save();
        
        console.log(`✅ Updated password for ${customer.email || customer.phoneNumber}`);
        updatedCount++;
      } catch (err) {
        console.error(`❌ Error updating ${customer.email || customer.phoneNumber}:`, err);
      }
    }

    console.log(`\nMigration complete. Updated ${updatedCount} records.`);
    process.exit(0);
  } catch (error) {
    console.error('Migration error:', error);
    process.exit(1);
  }
}

// Uncomment to run migration (run once then comment out again)
// migratePasswords();

// ==================== START THE SERVER ====================
startServer();