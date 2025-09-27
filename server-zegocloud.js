// Hi Chat Backend Server with ZEGOCLOUD Integration
// Enhanced server with token generation for production deployment

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const morgan = require('morgan');
require('dotenv').config();

const app = express();

// ========================================
// 🔧 MIDDLEWARE SETUP
// ========================================

// Enable compression
app.use(compression());

// Logging
app.use(morgan('combined'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static files
app.use('/uploads', express.static('uploads'));

// ========================================
// 🔑 ZEGOCLOUD CONFIGURATION
// ========================================

const ZEGOCLOUD_CONFIG = {
  APP_ID: parseInt(process.env.ZEGO_APP_ID) || 640953410,
  SERVER_SECRET: process.env.ZEGO_SERVER_SECRET || '3127e2f085cf98a0118601e8f6ad13e7',
  TOKEN_EXPIRY: 24 * 60 * 60 // 24 hours in seconds
};

// ========================================
// 🗄️ DATABASE CONNECTION
// ========================================

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://ChatAppData:CHATAPPDATA@chatappdata.ua6pnti.mongodb.net/?retryWrites=true&w=majority&appName=ChatAppData';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('✅ Connected to MongoDB');
})
.catch((error) => {
  console.error('❌ MongoDB connection error:', error);
  process.exit(1);
});

// ========================================
// 📊 DATABASE MODELS
// ========================================

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  profilePic: { type: String, default: '' },
  isOnline: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },
  zegoUserId: { type: String, unique: true }, // ZEGOCLOUD user ID
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Group Schema
const groupSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, default: '' },
  profilePic: { type: String, default: '' },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  admins: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  zegoGroupId: { type: String, unique: true }, // ZEGOCLOUD group ID
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Message Schema (for backup/history)
const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  group: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' },
  content: { type: String, required: true },
  messageType: { type: String, enum: ['text', 'image', 'file', 'audio'], default: 'text' },
  zegoMessageId: { type: String }, // ZEGOCLOUD message ID
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Group = mongoose.model('Group', groupSchema);
const Message = mongoose.model('Message', messageSchema);

// ========================================
// 🔐 AUTHENTICATION MIDDLEWARE
// ========================================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ========================================
// 🎯 ZEGOCLOUD TOKEN GENERATION
// ========================================

function generateZegoToken(appId, userId, serverSecret, effectiveTimeInSeconds) {
  const currentTime = Math.floor(Date.now() / 1000);
  const expiredTime = currentTime + effectiveTimeInSeconds;
  
  // Create payload
  const payload = {
    iss: appId,
    exp: expiredTime,
    iat: currentTime,
    aud: 'zego',
    jti: Math.random().toString(36).substring(2, 15),
    user_id: userId
  };
  
  // Create header
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };
  
  // Encode header and payload
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  
  // Create signature
  const signature = crypto
    .createHmac('sha256', serverSecret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// ========================================
// 🌐 API ROUTES
// ========================================

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    zegocloud: {
      configured: !!(ZEGOCLOUD_CONFIG.APP_ID && ZEGOCLOUD_CONFIG.SERVER_SECRET),
      appId: ZEGOCLOUD_CONFIG.APP_ID
    }
  });
});

// ZEGOCLOUD Token Generation
app.post('/api/getZegoToken', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'userId is required' });
    }
    
    // Verify user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Generate ZEGOCLOUD user ID if not exists
    if (!user.zegoUserId) {
      user.zegoUserId = `zego_${user._id}`;
      await user.save();
    }
    
    // Generate token
    const token = generateZegoToken(
      ZEGOCLOUD_CONFIG.APP_ID,
      user.zegoUserId,
      ZEGOCLOUD_CONFIG.SERVER_SECRET,
      ZEGOCLOUD_CONFIG.TOKEN_EXPIRY
    );
    
    console.log(`🎫 Generated ZEGOCLOUD token for user: ${user.username} (${user.zegoUserId})`);
    
    res.json({
      token: token,
      userId: user.zegoUserId,
      expiresIn: ZEGOCLOUD_CONFIG.TOKEN_EXPIRY,
      user: {
        id: user._id,
        name: user.name,
        username: user.username
      }
    });
    
  } catch (error) {
    console.error('❌ Token generation error:', error);
    res.status(500).json({ error: 'Token generation failed' });
  }
});

// User Registration
app.post('/api/register', async (req, res) => {
  try {
    const { name, username, email, password, role = 'user' } = req.body;
    
    // Validation
    if (!name || !username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Check if user exists
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const user = new User({
      name,
      username,
      email,
      password: hashedPassword,
      role,
      zegoUserId: `zego_${new mongoose.Types.ObjectId()}`
    });
    
    await user.save();
    
    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
    
    console.log(`✅ User registered: ${username}`);
    
    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        username: user.username,
        email: user.email,
        role: user.role,
        zegoUserId: user.zegoUserId
      }
    });
    
  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    // Find user
    const user = await User.findOne({
      $or: [{ username }, { email: username }]
    });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update online status
    user.isOnline = true;
    user.lastSeen = new Date();
    await user.save();
    
    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
    
    console.log(`✅ User logged in: ${username}`);
    
    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        username: user.username,
        email: user.email,
        role: user.role,
        profilePic: user.profilePic,
        zegoUserId: user.zegoUserId
      }
    });
    
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get All Users
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({}, '-password').sort({ name: 1 });
    res.json(users);
  } catch (error) {
    console.error('❌ Get users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get Current User
app.get('/api/user/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId, '-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('❌ Get current user error:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// Create Group
app.post('/api/groups', authenticateToken, async (req, res) => {
  try {
    const { name, description, members = [] } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Group name is required' });
    }
    
    const group = new Group({
      name,
      description,
      members: [...members, req.user.userId],
      admins: [req.user.userId],
      createdBy: req.user.userId,
      zegoGroupId: `group_${new mongoose.Types.ObjectId()}`
    });
    
    await group.save();
    await group.populate('members', 'name username profilePic');
    
    console.log(`✅ Group created: ${name} by ${req.user.username}`);
    
    res.status(201).json({
      message: 'Group created successfully',
      group
    });
    
  } catch (error) {
    console.error('❌ Create group error:', error);
    res.status(500).json({ error: 'Failed to create group' });
  }
});

// Get User Groups
app.get('/api/groups', authenticateToken, async (req, res) => {
  try {
    const groups = await Group.find({
      members: req.user.userId
    }).populate('members', 'name username profilePic');
    
    res.json(groups);
  } catch (error) {
    console.error('❌ Get groups error:', error);
    res.status(500).json({ error: 'Failed to fetch groups' });
  }
});

// ========================================
// 🚀 SERVER STARTUP
// ========================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`
🚀 Hi Chat Backend Server Started
📡 Port: ${PORT}
🗄️  Database: ${MONGODB_URI}
🎯 ZEGOCLOUD: ${ZEGOCLOUD_CONFIG.APP_ID ? 'Configured' : 'Not Configured'}
🌍 Environment: ${process.env.NODE_ENV || 'development'}
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully');
  mongoose.connection.close(() => {
    console.log('✅ Database connection closed');
    process.exit(0);
  });
});

module.exports = app;
