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
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'), { 
  index: false // Disable automatic index.html serving
}));

// ==================== DATABASE CONNECTION ====================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://fonteAppUser:secureAppPass123@localhost:27017/fonte_lenders?authSource=fonte_lenders';

mongoose.set('strictQuery', true);

mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 5000,
  retryWrites: true,
  retryReads: true,
  socketTimeoutMS: 30000,
  connectTimeoutMS: 10000,
  maxPoolSize: 10
})
.then(() => console.log('✅ MongoDB connected securely'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err.message);
  process.exit(1);
});

mongoose.connection.on('disconnected', () => {
  console.warn('⚠️ MongoDB disconnected');
});

mongoose.connection.on('reconnected', () => {
  console.log('🔁 MongoDB reconnected');
});

// ==================== MODELS ====================
const loanApplicationSchema = new mongoose.Schema({
  customerId: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'Customer', required: true },
  fullName: { type: String, required: true },
  phoneNumber: { type: String, required: true },
  email: String,
  amount: { type: Number, required: true, min: 1000, max: 300000 },
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
  expiresAt: { type: Date, required: true, index: { expires: '7d' } } // Auto-delete after 7 days
});

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
        timeout: 10000 // 10 second timeout
      }
    );

    jengaTokenCache = {
      token: response.data.access_token,
      expires: Date.now() + 3500000 // 58 minutes
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
        timeout: 10000 // 10 second timeout
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
    
    // Fallback verification - basic checks
    const isValid = idNumber.length >= 6; // Basic length validation
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
      return res.status(401).json({ 
        success: false, 
        message: 'No token provided',
        code: 'NO_TOKEN'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await Customer.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        message: 'Session expired. Please log in again.',
        code: 'TOKEN_EXPIRED'
      });
    }
    
    res.status(401).json({ 
      success: false, 
      message: 'Invalid token',
      code: 'INVALID_TOKEN'
    });
  }
};

const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ 
        success: false, 
        message: 'No token provided' 
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.id).select('-password');
    
    if (!admin) {
      return res.status(401).json({ 
        success: false, 
        message: 'Admin not found' 
      });
    }

    req.admin = admin;
    next();
  } catch (error) {
    console.error('Admin authentication error:', error);
    res.status(401).json({ 
      success: false, 
      message: 'Invalid admin token' 
    });
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
  try {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'), (err) => {
      if (err) {
        console.error('Admin panel delivery error:', err);
        res.status(404).send('Admin panel not found');
      }
    });
  } catch (err) {
    console.error('Admin route error:', err);
    res.status(500).send('Server error');
  }
});

app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ---------- CUSTOMER AUTHENTICATION ----------
app.post('/api/register', async (req, res) => {
  try {
    const { fullName, idNumber, phone, email, password } = req.body;

    if (!fullName || !idNumber || !phone || !password) {
      return res.status(400).json({
        success: false,
        message: 'All required fields must be provided'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters'
      });
    }

    // Normalize phone number by removing non-digit characters
    const normalizedPhone = phone.replace(/\D/g, '');

    const existingUser = await Customer.findOne({ 
      $or: [
        { customerId: idNumber }, 
        { phoneNumber: normalizedPhone }
      ] 
    });
    
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User already exists with this ID or phone number'
      });
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

    // Generate refresh token
    const refreshToken = crypto.randomBytes(40).toString('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    
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
      message: 'Registration failed. Please try again.'
    });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { phone, password } = req.body;

    if (!phone || !password) {
      return res.status(400).json({ 
        success: false,
        message: 'Phone and password are required' 
      });
    }

    // Normalize phone number by removing non-digit characters and ensure it starts with country code
    let normalizedPhone = phone.replace(/\D/g, '');
    
    // If number starts with 0, convert to 254 (Kenyan format)
    if (normalizedPhone.startsWith('0')) {
      normalizedPhone = '254' + normalizedPhone.substring(1);
    }
    // If number starts with 7 (without country code), add 254
    else if (normalizedPhone.length === 9 && normalizedPhone.startsWith('7')) {
      normalizedPhone = '254' + normalizedPhone;
    }

    console.log('Attempting login with phone:', normalizedPhone); // Debug log

    const customer = await Customer.findOne({ 
      $or: [
        { phoneNumber: normalizedPhone },
        { phoneNumber: '0' + normalizedPhone.substring(3) }, // Try with 0 prefix
        { phoneNumber: normalizedPhone.substring(3) } // Try without country code
      ]
    }).select('+password');

    if (!customer) {
      console.log('No customer found with phone:', normalizedPhone); // Debug log
      return res.status(401).json({ 
        success: false,
        message: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    console.log('Found customer:', customer.phoneNumber); // Debug log

    const isMatch = await customer.comparePassword(password);
    if (!isMatch) {
      console.log('Password mismatch for customer:', customer.phoneNumber); // Debug log
      return res.status(401).json({ 
        success: false,
        message: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    customer.lastLogin = new Date();
    await customer.save();

    const token = jwt.sign(
      { 
        id: customer._id,
        phone: customer.phoneNumber,
        customerId: customer.customerId 
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
    );

    // Generate refresh token
    const refreshToken = crypto.randomBytes(40).toString('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    
    await Token.create({
      userId: customer._id,
      token: refreshToken,
      expiresAt
    });

    const userData = customer.toObject();
    delete userData.password;

    console.log('Login successful for:', customer.phoneNumber); // Debug log

    res.json({ 
      success: true, 
      token, 
      refreshToken,
      user: userData,
      message: 'Login successful' 
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed. Please try again.'
    });
  }
});

// Refresh Token Endpoint
app.post('/api/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token is required'
      });
    }

    // Verify refresh token
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

    // Generate new access token
    const newToken = jwt.sign(
      { 
        id: tokenDoc.userId._id,
        phone: tokenDoc.userId.phoneNumber,
        customerId: tokenDoc.userId.customerId 
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
    );

    // Generate new refresh token
    const newRefreshToken = crypto.randomBytes(40).toString('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    
    await Token.create({
      userId: tokenDoc.userId._id,
      token: newRefreshToken,
      expiresAt
    });

    // Delete old refresh token
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

    // Validate required fields
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
      return res.status(400).json({
        success: false,
        message: 'Missing required fields',
        missingFields,
        details: 'Please complete all required fields'
      });
    }

    const customer = await Customer.findById(req.user._id)
      .select('+customerId +fullName +phoneNumber +email +maxLoanLimit +currentLoanBalance');
    
    if (!customer) {
      return res.status(404).json({
        success: false,
        message: 'Customer not found',
        details: 'Your account could not be found'
      });
    }

    const availableLimit = customer.maxLoanLimit - customer.currentLoanBalance;
    if (amount > availableLimit) {
      return res.status(400).json({
        success: false,
        message: 'Loan limit exceeded',
        details: `Your available limit is KES ${availableLimit.toLocaleString()}`,
        availableLimit
      });
    }

    const [customerVerification, guarantorVerification] = await Promise.all([
      verifyIDWithJenga(customer.customerId, customer.fullName),
      verifyIDWithJenga(guarantorId, guarantorName)
    ]);

    if (!customerVerification.success || !guarantorVerification.success) {
      return res.status(400).json({
        success: false,
        message: 'Verification failed',
        customerVerified: customerVerification.success,
        guarantorVerified: guarantorVerification.success,
        requiresManualVerification: customerVerification.fallback || guarantorVerification.fallback
      });
    }

    // Create loan application with nested guarantor structure
    const application = new LoanApplication({
      customer: customer._id,
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

    // Send notifications
    const sendNotifications = async () => {
      try {
        // Admin notification
        await sendEmail({
          to: process.env.ADMIN_EMAIL,
          subject: 'New Loan Application Submitted',
          html: generateAdminNotificationEmail(customer, application, availableLimit)
        });

        // Customer notification
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

    sendNotifications(); // Don't await to speed up response

    // Success response
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

// ==================== SERVER INITIALIZATION ====================
const PORT = process.env.PORT || 3000;

// Initialize admin account after successful connection
async function initializeAdmin() {
  try {
    const adminCount = await Admin.countDocuments();
    if (adminCount === 0 && process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
      const admin = new Admin({
        username: process.env.ADMIN_USERNAME,
        password: process.env.ADMIN_PASSWORD,
        role: 'superadmin'
      });
      await admin.save();
      console.log('✅ Initial admin account created');
    } else if (adminCount > 0) {
      console.log('ℹ️ Admin account already exists');
    } else {
      console.log('⚠️ No admin credentials provided in .env');
    }
  } catch (err) {
    console.error('❌ Admin initialization error:', err);
  }
}

// Connect to MongoDB and start server
async function startServer() {
  try {
    await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      retryWrites: true,
      retryReads: true,
      socketTimeoutMS: 30000,
      connectTimeoutMS: 10000,
      maxPoolSize: 10
    });
    
    console.log('✅ MongoDB connected securely');
    await initializeAdmin();
    
    // Add explicit route for root path
    app.get('/', (req, res) => {
      res.sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
        if (err) {
          console.error('Error serving index.html:', err);
          res.status(404).send('Page not found');
        }
      });
    });

    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
  }
}

// Start the server
startServer();

// Error handling
process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});