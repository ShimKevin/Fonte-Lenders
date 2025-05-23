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

// ==================== CONFIGURATION ====================
app.use(express.json());
app.use(bodyParser.json({ 
  limit: '10mb',
  strict: true
}));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(cors({
  origin: [
    'http://localhost:3000'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.static(path.join(__dirname, 'public'), { 
  index: false
}));

// Enhanced JSON response middleware
app.use((req, res, next) => {
  res.jsonResponse = (data, status = 200) => {
    res.setHeader('Content-Type', 'application/json');
    res.status(status).json(data);
  };
  next();
});

// ==================== PRODUCTION-READY DATABASE CONNECTION ====================
const MONGODB_URI = process.env.MONGODB_URI || 
  "mongodb+srv://kevinshimanjala:FonteLenders%40254@cluster0.g2bzscn.mongodb.net/fonte_lenders?retryWrites=true&w=majority&appName=Cluster0";

mongoose.set('strictQuery', true);

// Enhanced connection with error handling and monitoring
const connectDB = async () => {
  const connectionOptions = {
    serverSelectionTimeoutMS: 10000,  // Increased from 5000
    socketTimeoutMS: 45000,          // Increased from 30000
    connectTimeoutMS: 30000,
    retryWrites: true,
    retryReads: true,
    maxPoolSize: 15                  // Increased pool size
  };

  try {
    await mongoose.connect(MONGODB_URI, connectionOptions);
    console.log('✅ MongoDB Atlas connected');
    
    // Verify connection with a ping
    await mongoose.connection.db.admin().ping();
    console.log('🗄️ Database ping successful');
  } catch (err) {
    console.error('❌ MongoDB connection error:', err.message);
    
    // Detailed error analysis
    if (err.name === 'MongoServerError') {
      console.log('🔐 Authentication failed. Please check:');
      console.log('- Password is correct and URL encoded');
      console.log('- User has proper permissions in Atlas');
    } else if (err.message.includes('ECONNREFUSED')) {
      console.log('🌐 Network connection refused. Check:');
      console.log('- IP is whitelisted in Atlas');
      console.log('- No firewall blocking connections');
    }
    
    process.exit(1); // Exit with error in production
  }
};

// Initialize connection
connectDB();

// Event listeners for connection monitoring
mongoose.connection.on('disconnected', () => {
  console.warn('⚠️ MongoDB disconnected');
  // Implement automatic reconnection if needed
  setTimeout(() => connectDB(), 5000);
});

mongoose.connection.on('reconnected', () => {
  console.log('🔁 MongoDB reconnected');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB connection error:', err.message);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  await mongoose.connection.close();
  console.log('⏏️ MongoDB connection closed due to app termination');
  process.exit(0);
});

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
  expiresAt: { type: Date, required: true, index: { expires: '7d' } }
});

// Password hashing and comparison methods
adminSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

customerSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

customerSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
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

adminSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const LoanApplication = mongoose.model('LoanApplication', loanApplicationSchema);
const Customer = mongoose.model('Customer', customerSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Token = mongoose.model('Token', tokenSchema);

// ==================== JENGA API INTEGRATION ====================
let jengaTokenCache = {
  token: null,
  expires: 0
};

async function getJengaToken() {
  if (jengaTokenCache.token && Date.now() < jengaTokenCache.expires) {
    return jengaTokenCache.token;
  }

  try {
    const credentials = Buffer.from(`${process.env.JENGA_USERNAME}:${process.env.JENGA_API_KEY}`).toString('base64');
    
    const response = await axios.post(
      `${process.env.JENGA_BASE_URL}/identity/v2/token`,
      { merchantCode: process.env.JENGA_MERCHANT_CODE },
      {
        headers: {
          'Authorization': `Basic ${credentials}`,
          'Content-Type': 'application/json'
        },
        timeout: 10000
      }
    );

    jengaTokenCache = {
      token: response.data.access_token,
      expires: Date.now() + 3500000
    };

    return jengaTokenCache.token;
  } catch (error) {
    console.error('Jenga token error:', error.message);
    throw new Error('Jenga API service unavailable. Using fallback verification.');
  }
}

async function verifyIDWithJenga(idNumber, fullName) {
  try {
    const token = await getJengaToken();
    const [firstName, ...lastNameParts] = fullName.split(' ');
    const lastName = lastNameParts.join(' ') || ' ';

    const response = await axios.post(
      `${process.env.JENGA_BASE_URL}/identity/v2/verify`,
      {
        identityDocument: {
          documentType: "NATIONAL_ID",
          documentNumber: idNumber,
          firstName: firstName,
          lastName: lastName
        }
      },
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        timeout: 10000
      }
    );

    return {
      success: response.data.verified,
      message: response.data.message || 'Verification completed',
      data: response.data,
      verifiedBy: 'JengaAPI'
    };
  } catch (error) {
    console.error('Jenga verification error:', error.message);
    
    const isValid = idNumber.length >= 6;
    return {
      success: isValid,
      message: isValid 
        ? 'Basic verification completed (Jenga service unavailable)' 
        : 'ID verification failed',
      verifiedBy: 'Fallback',
      fallback: true
    };
  }
}

// ==================== MIDDLEWARE ====================
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.jsonResponse({ 
        success: false, 
        message: 'No token provided',
        code: 'NO_TOKEN'
      }, 401);
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await Customer.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.jsonResponse({ 
        success: false, 
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      }, 401);
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    
    if (error.name === 'TokenExpiredError') {
      return res.jsonResponse({ 
        success: false, 
        message: 'Session expired. Please log in again.',
        code: 'TOKEN_EXPIRED'
      }, 401);
    }
    
    res.jsonResponse({ 
      success: false, 
      message: 'Invalid token',
      code: 'INVALID_TOKEN'
    }, 401);
  }
};

const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.jsonResponse({ 
        success: false, 
        message: 'No token provided',
        code: 'NO_TOKEN'
      }, 401);
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.id).select('-password');
    
    if (!admin) {
      return res.jsonResponse({ 
        success: false, 
        message: 'Admin not found',
        code: 'ADMIN_NOT_FOUND'
      }, 401);
    }

    req.admin = admin;
    next();
  } catch (error) {
    console.error('Admin authentication error:', error);
    res.jsonResponse({ 
      success: false, 
      message: 'Invalid admin token',
      code: 'INVALID_ADMIN_TOKEN'
    }, 401);
  }
};

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

// ---------- CUSTOMER AUTHENTICATION ----------
app.post('/api/register', async (req, res) => {
  try {
    const { fullName, idNumber, phone, email, password } = req.body;

    if (!fullName || !idNumber || !phone || !password) {
      return res.jsonResponse({
        success: false,
        message: 'All required fields must be provided',
        missingFields: [
          ...(!fullName ? ['fullName'] : []),
          ...(!idNumber ? ['idNumber'] : []),
          ...(!phone ? ['phone'] : []),
          ...(!password ? ['password'] : [])
        ]
      }, 400);
    }

    if (password.length < 6) {
      return res.jsonResponse({
        success: false,
        message: 'Password must be at least 6 characters',
        code: 'PASSWORD_TOO_SHORT'
      }, 400);
    }

    const normalizedPhone = phone.replace(/\D/g, '');

    const existingUser = await Customer.findOne({ 
      $or: [
        { customerId: idNumber }, 
        { phoneNumber: normalizedPhone }
      ] 
    });
    
    if (existingUser) {
      return res.jsonResponse({
        success: false,
        message: 'User already exists with this ID or phone number',
        code: 'USER_EXISTS'
      }, 400);
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newCustomer = new Customer({
      fullName,
      customerId: idNumber,
      phoneNumber: normalizedPhone,
      email: email || null,
      password: hashedPassword,
      verificationStatus: 'pending'
    });

    await newCustomer.save();

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

    if (email) {
      await sendEmail({
        to: email,
        subject: 'Welcome to Fonte Lenders',
        html: `<h2>Welcome, ${fullName}!</h2>
               <p>Your registration with Fonte Lenders is complete.</p>
               <p>You can now apply for loans through our platform.</p>`
      });
    }

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
      code: 'REGISTRATION_FAILED'
    }, 500);
  }
});

app.post('/api/login', async (req, res) => {
  try {
    console.log('Login request body:', req.body); // Debug log
    
    if (!req.body || typeof req.body !== 'object') {
      return res.jsonResponse({
        success: false,
        message: 'Invalid request format',
        code: 'INVALID_REQUEST'
      }, 400);
    }

    const { phone, password } = req.body;

    if (!phone || !password) {
      return res.jsonResponse({
        success: false,
        message: 'Phone and password are required',
        code: 'MISSING_CREDENTIALS'
      }, 400);
    }

    // Normalize phone number (remove all non-digit characters)
    const cleanPhone = phone.replace(/\D/g, '');
    
    // Generate all possible phone formats
    const possiblePhones = [
      cleanPhone, // Original format
      cleanPhone.startsWith('254') ? `0${cleanPhone.substring(3)}` : null, // Convert 254 to 0
      cleanPhone.startsWith('0') ? `254${cleanPhone.substring(1)}` : null, // Convert 0 to 254
      cleanPhone.startsWith('254') ? cleanPhone.substring(3) : null // Just the local number
    ].filter(Boolean);

    console.log('Searching for user with phone formats:', possiblePhones);

    // Find user with any matching phone format
    const user = await Customer.findOne({
      phoneNumber: { $in: possiblePhones }
    }).select('+password');

    if (!user) {
      console.log('User not found for any phone format');
      return res.jsonResponse({
        success: false,
        message: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      }, 401);
    }

    // Debug password comparison
    const isMatch = await user.debugPassword(password);
    if (!isMatch) {
      console.log('Password does not match');
      // Additional debug: Check if password needs to be reset
      const shouldReset = await bcrypt.compare('test123', user.password);
      console.log('Test password match:', shouldReset);
      
      return res.jsonResponse({
        success: false,
        message: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      }, 401);
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate tokens
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

// Temporary password reset endpoint (remove in production)
app.post('/api/reset-password', async (req, res) => {
  try {
    const { phone, newPassword } = req.body;
    const user = await Customer.findOne({ phoneNumber: phone }).select('+password');
    
    if (!user) {
      return res.jsonResponse({
        success: false,
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      }, 404);
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    
    res.jsonResponse({
      success: true,
      message: 'Password reset successfully'
    });
  } catch (error) {
    console.error('Password reset error:', error);
    res.jsonResponse({
      success: false,
      message: 'Password reset failed',
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

    const customer = await Customer.findById(req.user._id)
      .select('+customerId +fullName +phoneNumber +email +maxLoanLimit +currentLoanBalance');
    
    if (!customer) {
      return res.jsonResponse({
        success: false,
        message: 'Customer not found',
        code: 'CUSTOMER_NOT_FOUND'
      }, 404);
    }

    const availableLimit = customer.maxLoanLimit - customer.currentLoanBalance;
    if (amount > availableLimit) {
      return res.jsonResponse({
        success: false,
        message: 'Loan limit exceeded',
        details: `Your available limit is KES ${availableLimit.toLocaleString()}`,
        availableLimit,
        code: 'LOAN_LIMIT_EXCEEDED'
      }, 400);
    }

    const [customerVerification, guarantorVerification] = await Promise.all([
      verifyIDWithJenga(customer.customerId, customer.fullName),
      verifyIDWithJenga(guarantorId, guarantorName)
    ]);

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

    const application = new LoanApplication({
      customerId: customer.customerId,
      userId: customer._id,
      fullName: customer.fullName,
      phoneNumber: customer.phoneNumber,
      email: customer.email,
      amount,
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
        verificationMethod: customerVerification.fallback ? 'fallback' : 'jenga'
      }
    });

    await application.save();

    const sendNotifications = async () => {
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
            html: generateCustomerConfirmationEmail(customer, application, customerVerification)
          });
        }
      } catch (emailError) {
        console.error('Notification email error:', emailError);
      }
    };

    sendNotifications();

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

// ==================== MONGODB CONNECTION ====================
const mongooseOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 10000,
  socketTimeoutMS: 45000,
  connectTimeoutMS: 30000,
  retryWrites: true,
  retryReads: true,
  w: 'majority',
  maxPoolSize: 15,
  heartbeatFrequencyMS: 10000
};

// Connection function that can be called for initial connection and reconnections
async function connectDB() {
  try {
    console.log('⌛ Attempting MongoDB connection...');
    console.log(`Connecting to: ${process.env.MONGODB_URI?.replace(/:[^@]+@/, ':********@')}`);
    
    await mongoose.connect(process.env.MONGODB_URI, mongooseOptions);
    console.log('✅ MongoDB connected successfully');

    // Verify connection
    if (!await testDatabaseConnection()) {
      throw new Error('Database verification failed');
    }

    // Initialize admin if needed
    await initializeAdmin();
    
    return true;
  } catch (err) {
    console.error('❌ MongoDB connection failed:', err.message);
    return false;
  }
}

// Add this admin initialization function
async function initializeAdmin() {
  try {
    const adminCount = await mongoose.connection.db.collection('admins').countDocuments();
    if (adminCount === 0 && process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
      await mongoose.connection.db.collection('admins').insertOne({
        username: process.env.ADMIN_USERNAME,
        password: hashedPassword,
        role: 'superadmin',
        createdAt: new Date(),
        updatedAt: new Date()
      });
      console.log('✅ Initial admin account created');
    }
  } catch (err) {
    console.error('❌ Admin initialization error:', err);
  }
}

async function testDatabaseConnection() {
  try {
    // Wait for connection to be established
    await new Promise(resolve => mongoose.connection.once('connected', resolve));
    
    // Verify connection with a ping command
    const pingResult = await mongoose.connection.db.command({ ping: 1 });
    console.log('🗄️ Database ping successful:', pingResult.ok === 1 ? 'OK' : 'Failed');
    return pingResult.ok === 1;
  } catch (err) {
    console.error('❌ Database verification failed:', err);
    
    if (err.name === 'MongoServerError') {
      console.log('🔐 Authentication failed. Please check:');
      console.log('- Password is correct and URL encoded');
      console.log('- User has proper permissions in Atlas');
    } else if (err.message.includes('ECONNREFUSED')) {
      console.log('🌐 Network connection refused. Check:');
      console.log('- IP is whitelisted in Atlas');
      console.log('- No firewall blocking connections');
    }
    
    return false;
  }
}

async function startServer() {
  try {
    // First attempt to connect
    if (!await connectDB()) {
      throw new Error('Initial database connection failed');
    }

    // Start server
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
    });

    server.on('error', (err) => {
      console.error('❌ Server error:', err);
      process.exit(1);
    });

    // Graceful shutdown
    process.on('SIGINT', async () => {
      console.log('\n🛑 Received shutdown signal');
      await mongoose.connection.close();
      console.log('⏏️ MongoDB connection closed');
      server.close(() => {
        console.log('🚪 HTTP server closed');
        process.exit(0);
      });
    });

  } catch (err) {
    console.error('❌ Fatal startup error:', err.message);
    console.error('Stack trace:', err.stack);
    process.exit(1);
  }
}

// MongoDB connection event listeners
mongoose.connection.on('connected', () => {
  console.log('📊 MongoDB connection established');
});

mongoose.connection.on('disconnected', () => {
  console.warn('⚠️ MongoDB disconnected - attempting to reconnect in 5 seconds...');
  setTimeout(connectDB, 5000);
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB connection error:', err);
  // For certain errors, you might want to attempt reconnection immediately
  if (err.name === 'MongoNetworkError') {
    console.log('🔄 Network error detected - attempting reconnect...');
    setTimeout(connectDB, 1000);
  }
});

// Start the server
startServer();