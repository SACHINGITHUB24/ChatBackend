//Hi Chat Backend Completed

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v2: cloudinary } = require('cloudinary');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const morgan = require('morgan');
const axios = require("axios");
const { Readable } = require("stream");
require('dotenv').config();

const app = express();

// ========================================
// 🔧 MIDDLEWARE SETUP
// ========================================

app.use(compression());
app.use(morgan('combined'));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number.MAX_SAFE_INTEGER,
  message: 'Too many requests from this IP, please try again later.'
});

app.use('/api/', limiter);

app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/uploads', express.static('uploads'));

// ========================================
// 📁 CLOUDINARY CONFIGURATION (Removed fallbacks, MUST USE ENV)
// ========================================

// cloudinary.config({
//   cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
//   api_key: process.env.CLOUDINARY_API_KEY,
//   api_secret: process.env.CLOUDINARY_API_SECRET,
// });

// // Check if critical Cloudinary settings are missing
// if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
//     console.warn('⚠️ WARNING: CLOUDINARY ENVIRONMENT VARIABLES ARE NOT FULLY SET. Uploads will fail until configured.');
// } else {
//     console.log('✅ Cloudinary configured:', cloudinary.config().cloud_name);
// }

// // ========================================
// // 📁 FILE UPLOAD CONFIGURATION
// // ========================================

// const cloudinaryStorage = new CloudinaryStorage({
//   cloudinary: cloudinary,
//   params: async (req, file) => {
//     let resourceType = 'auto';
//     if (file.mimetype.startsWith('video/')) resourceType = 'video';
//     else if (file.mimetype.startsWith('image/')) resourceType = 'image';
//     else resourceType = 'raw';

//     // Use a specific, clear folder structure in Cloudinary
//     let folder = 'HiChat'; 
//     if (file.fieldname === 'file') {
//         if (file.mimetype.startsWith('image/')) folder = 'HiChat/images';
//         else if (file.mimetype.startsWith('video/')) folder = 'HiChat/videos';
//         else if (file.mimetype.includes('pdf') || file.mimetype.includes('document') || file.mimetype.includes('text')) {
//              folder = 'HiChat/documents';
//         }
//     } else {
//         // Fallback for other file fields if any (e.g., if you later add an audio field)
//         folder = 'HiChat/others';
//     }

//     return {
//       folder: folder,
//       resource_type: resourceType,
//       allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'mp4', 'mov', 'avi', 'webm', 'pdf', 'doc', 'docx', 'txt'],
//       public_id: `${Date.now()}-${file.originalname.split('.')[0]}`,
//     };
//   }
// });

// const cloudinaryUpload = multer({
//   storage: cloudinaryStorage,
//   limits: { fileSize: 100 * 1024 * 1024, files: 10 },
//   fileFilter: (req, file, cb) => {
//     // List of allowed MIME types (preferred method)
//     const allowedMimes = [
//       'image/jpeg', 'image/jpg', 'image/png', 'image/gif',
//       'video/mp4', 'video/quicktime', 'video/x-msvideo', 'video/webm',
//       'application/pdf', 'application/msword',
//       'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
//       'text/plain'
//     ];

//     // List of allowed extensions (fallback for generic octet-stream)
//     const allowedExts = [
//         '.jpg', '.jpeg', '.png', '.gif', 
//         '.mp4', '.mov', '.avi', '.webm', 
//         '.pdf', '.doc', '.docx', '.txt'
//     ];
    
//     // 1. Check if the MIME type is explicitly allowed
//     if (allowedMimes.includes(file.mimetype)) {
//       cb(null, true);
//     } 
//     // 2. Check for the generic binary type (application/octet-stream) and use extension fallback
//     else if (file.mimetype === 'application/octet-stream' || file.mimetype === 'application/x-empty') {
//         const ext = path.extname(file.originalname || '').toLowerCase();
        
//         if (allowedExts.includes(ext)) {
//             console.log(`⚠️ Octet-stream or generic file detected for: ${file.originalname}. Allowing based on extension: ${ext}`);
//             cb(null, true);
//         } else {
//             // Reject if the extension is also unsupported
//             cb(new Error(`Invalid file type: ${file.mimetype}. Rejected due to unknown or missing extension: ${ext}`));
//         }
//     }
//     // 3. Reject all other unsupported MIME types
//     else {
//       cb(new Error(`Invalid file type: ${file.mimetype}`));
//     }
//   }
// });

// // Local storage fallback
// const uploadsDir = path.join(__dirname, 'uploads');
// if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

// const localStorage = multer.diskStorage({
//   destination: (req, file, cb) => cb(null, uploadsDir),
//   filename: (req, file, cb) => cb(null, `${file.fieldname}-${Date.now()}-${Math.round(Math.random() * 1e9)}${path.extname(file.originalname)}`)
// });

// const uploadLocal = multer({ storage: localStorage, limits: { fileSize: 50 * 1024 * 1024 } });








// ========================================
// 🌩️ CLOUDINARY CONFIGURATION
// ========================================

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Check Cloudinary ENV
if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
  console.warn('⚠️ WARNING: CLOUDINARY ENVIRONMENT VARIABLES ARE NOT FULLY SET. Uploads will fail until configured.');
} else {
  console.log('✅ Cloudinary configured for:', cloudinary.config().cloud_name);
}

// ========================================
// 📁 FILE UPLOAD CONFIGURATION
// ========================================

const cloudinaryStorage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => {
    let resourceType = 'auto';
    if (file.mimetype.startsWith('video/')) resourceType = 'video';
    else if (file.mimetype.startsWith('image/')) resourceType = 'image';
    else if (file.mimetype.startsWith('audio/')) resourceType = 'video'; // Cloudinary treats audio under video
    else resourceType = 'raw';

    // Determine folder dynamically
    let folder = 'HiChat';

    if (file.fieldname === 'profilePic') folder = 'HiChat/profile_pics';
    else if (file.mimetype.startsWith('image/')) folder = 'HiChat/images';
    else if (file.mimetype.startsWith('video/')) folder = 'HiChat/videos';
    else if (file.mimetype.startsWith('audio/')) folder = 'HiChat/audio';
    else if (
      file.mimetype.includes('pdf') ||
      file.mimetype.includes('word') ||
      file.mimetype.includes('excel') ||
      file.mimetype.includes('csv') ||
      file.mimetype.includes('text') ||
      file.mimetype.includes('powerpoint')
    ) folder = 'HiChat/documents';
    else if (file.mimetype.includes('json') || file.mimetype.includes('javascript') || file.mimetype.includes('html')) {
      folder = 'HiChat/code_files';
    } else {
      folder = 'HiChat/others';
    }

    return {
      folder,
      resource_type: resourceType,
      allowed_formats: [
        // Images
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp', 'heic', 'svg',
        // Videos
        'mp4', 'mov', 'avi', 'mkv', 'webm', 'flv', 'wmv',
        // Audio
        'mp3', 'wav', 'm4a', 'aac', 'ogg',
        // Documents
        'pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'txt', 'csv', 'rtf',
        // Code / Config
        'json', 'js', 'ts', 'html', 'css', 'xml', 'yml', 'yaml', 'md',
        // Others
        'zip', 'rar'
      ],
      public_id: `${Date.now()}-${file.originalname.split('.')[0]}`,
    };
  },
});

// ========================================
// 🚀 MULTER UPLOAD WITH ADVANCED FILTERS
// ========================================

const allowedMimes = [
  // Images
  'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/webp', 'image/heic', 'image/svg+xml',
  // Videos
  'video/mp4', 'video/quicktime', 'video/x-msvideo', 'video/x-matroska', 'video/webm', 'video/x-flv', 'video/x-ms-wmv',
  // Audio
  'audio/mpeg', 'audio/wav', 'audio/x-m4a', 'audio/aac', 'audio/ogg',
  // Documents
  'application/pdf', 'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'text/plain', 'text/csv', 'application/rtf',
  // Code / Config
  'application/json', 'application/javascript', 'text/html', 'text/css', 'application/xml', 'text/markdown',
  // Others
  'application/zip', 'application/x-rar-compressed'
];

const allowedExts = [
  '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', '.heic', '.svg',
  '.mp4', '.mov', '.avi', '.mkv', '.webm', '.flv', '.wmv',
  '.mp3', '.wav', '.m4a', '.aac', '.ogg',
  '.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.txt', '.csv', '.rtf',
  '.json', '.js', '.ts', '.html', '.css', '.xml', '.yml', '.yaml', '.md',
  '.zip', '.rar'
];

const cloudinaryUpload = multer({
  storage: cloudinaryStorage,
  limits: { fileSize: 200 * 1024 * 1024, files: 10 }, // Increased limit for videos
  fileFilter: (req, file, cb) => {
    if (allowedMimes.includes(file.mimetype)) cb(null, true);
    else if (file.mimetype === 'application/octet-stream' || file.mimetype === 'application/x-empty') {
      const ext = path.extname(file.originalname || '').toLowerCase();
      if (allowedExts.includes(ext)) {
        console.log(`⚠️ Octet-stream detected for: ${file.originalname}. Allowing based on extension: ${ext}`);
        cb(null, true);
      } else cb(new Error(`Invalid file type (octet-stream) - ${ext} not allowed.`));
    } else cb(new Error(`Invalid file type: ${file.mimetype}`));
  },
});

// ========================================
// 💾 LOCAL STORAGE FALLBACK (optional)
// ========================================

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const localStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, `${file.fieldname}-${Date.now()}-${Math.round(Math.random() * 1e9)}${path.extname(file.originalname)}`)
});

const uploadLocal = multer({
  storage: localStorage,
  limits: { fileSize: 100 * 1024 * 1024 },
});


// ========================================
// 🔑 ZEGOCLOUD CONFIGURATION (Removed fallbacks, MUST USE ENV)
// ========================================

const ZEGOCLOUD_CONFIG = {
  APP_ID: parseInt(process.env.ZEGO_APP_ID),
  SERVER_SECRET: process.env.ZEGO_SERVER_SECRET,
  TOKEN_EXPIRY: 24 * 60 * 60
};

// ========================================
// 🗄️ DATABASE CONNECTION
// ========================================

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/hichat';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch((error) => {
  console.error('❌ MongoDB connection error:', error);
  process.exit(1);
});

// ========================================
// 📊 DATABASE MODELS
// ========================================

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  profilePic: { type: String, default: '' },
  isOnline: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },
  zegoUserId: { type: String, unique: true, sparse: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },

    //This is Backup Testing 
  lastBackup: {
  url: String,
  date: Date,
}
});

const groupSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, default: '' },
  profilePic: { type: String, default: '' },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  admins: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  zegoGroupId: { type: String, unique: true, sparse: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  group: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' },
  content: { type: String, default: '' },
  messageType: { type: String, enum: ['text', 'image', 'file', 'audio', 'video'], default: 'text' },
  fileUrl: { type: String },
  fileName: { type: String },
  fileSize: { type: Number },
  zegoMessageId: { type: String },
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
  
  const payload = {
    iss: appId,
    exp: expiredTime,
    iat: currentTime,
    aud: 'zego',
    jti: Math.random().toString(36).substring(2, 15),
    user_id: userId
  };
  
  const header = { alg: 'HS256', typ: 'JWT' };
  
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  
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
    cloudinary: {
      configured: !!(cloudinary.config().cloud_name), // Check if env var is set
      cloudName: cloudinary.config().cloud_name
    },
    zegocloud: {
      configured: !!(ZEGOCLOUD_CONFIG.APP_ID && ZEGOCLOUD_CONFIG.SERVER_SECRET),
      appId: ZEGOCLOUD_CONFIG.APP_ID
    }
  });
});

// ZEGOCLOUD Token Generation
app.post('/api/getZegoToken', async (req, res) => {
  try {
    if (!ZEGOCLOUD_CONFIG.APP_ID || !ZEGOCLOUD_CONFIG.SERVER_SECRET) {
      return res.status(500).json({ error: 'ZEGOCLOUD credentials missing from environment variables.' });
    }

    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId is required' });

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (!user.zegoUserId) {
      user.zegoUserId = `zego_${user._id}`;
      await user.save();
    }

    const effectiveTimeInSeconds = (24 * 60 * 60) - 30;
    const token = generateZegoToken(
      ZEGOCLOUD_CONFIG.APP_ID,
      user.zegoUserId,
      ZEGOCLOUD_CONFIG.SERVER_SECRET,
      effectiveTimeInSeconds
    );

    const expiresAt = Date.now() + (effectiveTimeInSeconds * 1000);

    console.log(`🎫 Zego token generated for ${user.username}`);

    return res.json({
      token,
      appId: ZEGOCLOUD_CONFIG.APP_ID,
      userId: user.zegoUserId,
      expiresIn: effectiveTimeInSeconds,
      expiresAt
    });
  } catch (err) {
    console.error('❌ Token generation error:', err);
    return res.status(500).json({ error: 'Failed to generate token' });
  }
});

// Refresh Token
app.post('/api/refreshZegoToken', async (req, res) => {
  try {
    if (!ZEGOCLOUD_CONFIG.APP_ID || !ZEGOCLOUD_CONFIG.SERVER_SECRET) {
      return res.status(500).json({ error: 'ZEGOCLOUD credentials missing from environment variables.' });
    }
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId is required' });

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const effectiveTimeInSeconds = (24 * 60 * 60) - 30;
    const token = generateZegoToken(
      ZEGOCLOUD_CONFIG.APP_ID,
      user.zegoUserId,
      ZEGOCLOUD_CONFIG.SERVER_SECRET,
      effectiveTimeInSeconds
    );

    return res.json({
      token,
      expiresIn: effectiveTimeInSeconds,
      userId: user.zegoUserId
    });
  } catch (err) {
    console.error('❌ Refresh token error:', err);
    res.status(500).json({ error: 'Failed to refresh token' });
  }
});

// --- NEW CHAT/GROUP ROUTES ADDED TO FIX 404 ERROR ---

// Fetch all users (for DMs, excluding current user)
// app.get('/api/users', authenticateToken, async (req, res) => {
//     try {
//         const users = await User.find({ _id: { $ne: req.user.userId } }).select('-password');
//         res.json(users);
//     } catch (err) {
//         console.error('❌ Error fetching users:', err);
//         res.status(500).json({ error: 'Failed to fetch users' });
//     }
// });









// Fetch all groups a user belongs to
// app.get('/api/groups', authenticateToken, async (req, res) => {
//     try {
//         const groups = await Group.find({ members: req.user.userId }).populate('createdBy', 'username');
//         res.json(groups);
//     } catch (err) {
//         console.error('❌ Error fetching groups:', err);
//         res.status(500).json({ error: 'Failed to fetch groups' });
//     }
// });

// Get messages for a specific group (FIXES THE 404 FOR /api/groups/:groupId/messages)
// app.get('/api/groups/:groupId/messages', authenticateToken, async (req, res) => {
//   try {
//     const { groupId } = req.params;
//     const limit = parseInt(req.query.limit) || 50;
//     const offset = parseInt(req.query.offset) || 0;

//     // Check if group exists first
//     const group = await Group.findById(groupId);
//     if (!group) {
//         return res.status(404).json({ error: 'Group not found.' });
//     }
    
//     // Check if user is a member of the group
//     if (!group.members.includes(req.user.userId)) {
//         // NOTE: Depending on your security model, you might allow non-members to read history, but typically only members can.
//         // For now, we'll allow reading if the group exists.
//         // If strict security is needed: return res.status(403).json({ error: 'Not authorized to view this group\'s messages.' });
//     }


//     const messages = await Message.find({ group: groupId })
//       .sort({ timestamp: -1 }) // Sort by newest first
//       .limit(limit)
//       .skip(offset)
//       .populate('sender', 'username profilePic zegoUserId')
//       .exec();
      
//     // Reverse the order for the client to display oldest at the top (standard chat view)
//     res.json(messages.reverse()); 

//   } catch (err) {
//     // If the groupId format is invalid (e.g., not a valid MongoDB ObjectId), Mongoose will throw a CastError.
//     // We catch that here and return a 404 or 400.
//     if (err.name === 'CastError') {
//          return res.status(400).json({ error: 'Invalid group ID format.' });
//     }
//     console.error('❌ Error fetching group messages:', err);
//     res.status(500).json({ error: 'Failed to fetch group messages' });
//   }
// });


// --- END NEW CHAT/GROUP ROUTES ---


// ========================================
// 🚨 MULTER/CLOUDINARY ERROR HANDLER (CRITICAL DEBUG TOOL)
// ========================================
const uploadErrorHandler = (err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        // Multer specific error (e.g., file size limit, too many files)
        console.error('❌ Multer Error:', err.code, err.message);
        return res.status(400).json({ 
            success: false, 
            error: `Upload failed (Multer): ${err.message}` 
        });
    } else if (err) {
        // Generic error (This is where Cloudinary API errors usually land)
        // Check for specific API key error to provide clearer feedback
        if (err.http_code === 401 && err.message.includes('Invalid api_key')) {
             console.error('❌ CLOUDINARY AUTH FAILED: Check CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET in environment variables.');
             return res.status(500).json({
                 success: false,
                 error: 'Cloudinary Authentication Failed. Please check server environment configuration.'
             });
        }
        
        console.error('❌ Cloudinary Upload Failed:', err.message, err.stack);
        return res.status(500).json({ 
            success: false, 
            error: `Cloudinary/Server error: ${err.message}` 
        });
    }
    next();
};

// ========================================
// 📁 FILE UPLOAD ENDPOINTS - PRODUCTION READY
// ========================================

// Profile Picture Upload (Cloudinary)
app.post('/api/cloudinary/profile', authenticateToken, cloudinaryUpload.single('file'), uploadErrorHandler, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        success: false,
        error: 'No file uploaded' 
      });
    }

    const userId = req.body.userId || req.user.userId;
    
    // Update user profile picture in database
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        profilePic: req.file.path,
        updatedAt: new Date()
      },
      { new: true, select: '-password' }
    );

    if (!updatedUser) {
      return res.status(404).json({ 
        success: false,
        error: 'User not found' 
      });
    }

    console.log(`✅ Profile picture updated: ${updatedUser.username} -> ${req.file.path}`);

    res.json({
      success: true,
      message: 'Profile picture updated successfully',
      url: req.file.path,
      publicId: req.file.filename,
      user: updatedUser
    });
  } catch (err) {
    console.error('❌ Profile upload error (Post-Cloudinary):', err);
    res.status(500).json({ 
      success: false,
      error: err.message 
    });
  }
});

// Chat Media Upload (Images, Videos, Documents)
app.post('/api/cloudinary/chat', authenticateToken, cloudinaryUpload.single('file'), uploadErrorHandler, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        success: false,
        error: 'No file uploaded' 
      });
    }

    console.log(`✅ Chat file uploaded: ${req.file.originalname} -> ${req.file.path}`);

    // Determine message type based on file mimetype
    let messageType = 'file';
    if (req.file.mimetype.startsWith('image/')) {
      messageType = 'image';
    } else if (req.file.mimetype.startsWith('video/')) {
      messageType = 'video';
    } else if (req.file.mimetype.startsWith('audio/')) {
      messageType = 'audio';
    }

    res.json({
      success: true,
      message: 'File uploaded successfully',
      url: req.file.path,
      publicId: req.file.filename,
      resourceType: req.file.resource_type || 'auto',
      originalName: req.file.originalname,
      size: req.file.size,
      messageType: messageType,
      mimetype: req.file.mimetype
    });
  } catch (err) {
    console.error('❌ Chat upload error (Post-Cloudinary):', err);
    res.status(500).json({ 
      success: false,
      error: err.message 
    });
  }
});

// Multiple Files Upload
app.post('/api/cloudinary/multiple', authenticateToken, cloudinaryUpload.array('files', 10), uploadErrorHandler, async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ 
        success: false,
        error: 'No files uploaded' 
      });
    }

    const uploadedFiles = req.files.map(f => {
      let messageType = 'file';
      if (f.mimetype.startsWith('image/')) messageType = 'image';
      else if (f.mimetype.startsWith('video/')) messageType = 'video';
      else if (f.mimetype.startsWith('audio/')) messageType = 'audio';

      return {
        url: f.path,
        publicId: f.filename,
        resourceType: f.resource_type || 'auto',
        originalName: f.originalname,
        size: f.size,
        messageType: messageType,
        mimetype: f.mimetype
      };
    });

    console.log(`✅ ${uploadedFiles.length} files uploaded successfully`);

    res.json({ 
      success: true, 
      message: `${uploadedFiles.length} files uploaded successfully`,
      files: uploadedFiles 
    });
  } catch (err) {
    console.error('❌ Multiple upload error (Post-Cloudinary):', err);
    res.status(500).json({ 
      success: false,
      error: err.message 
    });
  }
});

// Cloudinary Upload (Replacing the local /api/upload endpoint)
app.post('/api/upload', authenticateToken, cloudinaryUpload.single('file'), uploadErrorHandler, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        success: false,
        error: 'No file uploaded' 
      });
    }

    console.log(`✅ File uploaded via /api/upload (Cloudinary): ${req.file.originalname} -> ${req.file.path}`);

    const { type = 'general', userId } = req.body;
    
    // Determine message type based on file mimetype
    let messageType = 'file';
    if (req.file.mimetype.startsWith('image/')) {
      messageType = 'image';
      // If it's a profile upload, update the user profilePic
      if (type === 'profile') {
        const updatedUser = await User.findByIdAndUpdate(
          userId || req.user.userId,
          { profilePic: req.file.path, updatedAt: new Date() },
          { new: true, select: '-password' }
        );
        if (!updatedUser) {
           console.warn('⚠️ Could not update user profilePic for ID:', userId || req.user.userId);
        }
      }
    } else if (req.file.mimetype.startsWith('video/')) {
      messageType = 'video';
    } else if (req.file.mimetype.startsWith('audio/')) {
      messageType = 'audio';
    }

    res.json({
      success: true,
      message: 'File uploaded successfully to Cloudinary',
      // Ensure you return the 'fileUrl' key which the front-end might expect from the old local upload
      fileUrl: req.file.path, 
      filename: req.file.filename,
      originalName: req.file.originalname,
      size: req.file.size,
      type: type,
      messageType: messageType
    });
  } catch (err) {
    console.error('❌ Cloudinary Upload (via /api/upload) error (Post-Cloudinary):', err);
    res.status(500).json({ 
      success: false,
      error: 'File upload failed to Cloudinary: ' + err.message
    });
  }
});





// ========================================
// 👤 USER ROUTES
// ========================================

app.post('/api/register', async (req, res) => {
  try {
    const { name, username, email, password, role = 'user' } = req.body;
    
    if (!name || !username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({
      name,
      username,
      email,
      password: hashedPassword,
      role,
      zegoUserId: `zego_${new mongoose.Types.ObjectId()}`
    });
    
    await user.save();
    
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

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    const user = await User.findOne({
      $or: [{ username }, { email: username }]
    });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    user.isOnline = true;
    user.lastSeen = new Date();
    await user.save();
    
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

app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find(
      { _id: { $ne: req.user.userId } },
      'name username email profilePic isOnline lastSeen role createdAt'
    ).sort({ name: 1 });
    
    res.json(users);
  } catch (error) {
    console.error('❌ Get users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.put('/api/user/online-status', authenticateToken, async (req, res) => {
  try {
    const { isOnline, lastSeen } = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.user.userId,
      { 
        isOnline: isOnline,
        lastSeen: lastSeen ? new Date(lastSeen) : new Date(),
        updatedAt: new Date()
      },
      { new: true, select: '-password' }
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      message: 'Online status updated',
      isOnline: user.isOnline,
      lastSeen: user.lastSeen
    });
  } catch (error) {
    console.error('❌ Online status update error:', error);
    res.status(500).json({ error: 'Failed to update online status' });
  }
});

// ========================================
// 👥 GROUP ROUTES
// ========================================

// app.post('/api/groups', authenticateToken, async (req, res) => {
//   try {
//     const { name, description, members = [] } = req.body;
    
//     if (!name) {
//       return res.status(400).json({ error: 'Group name is required' });
//     }
    
//     const group = new Group({
//       name,
//       description,
//       members: [...new Set([...members, req.user.userId])],
//       admins: [req.user.userId],
//       createdBy: req.user.userId,
//       zegoGroupId: `group_${new mongoose.Types.ObjectId()}`
//     });
    
//     await group.save();
//     await group.populate('members', 'name username profilePic');
    
//     console.log(`✅ Group created: ${name}`);
    
//     res.status(201).json({
//       message: 'Group created successfully',
//       group
//     });
//   } catch (error) {
//     console.error('❌ Create group error:', error);
//     res.status(500).json({ error: 'Failed to create group' });
//   }
// });

// app.get('/api/groups', authenticateToken, async (req, res) => {
//   try {
//     const groups = await Group.find({
//       members: req.user.userId
//     }).populate('members', 'name username profilePic isOnline lastSeen')
//       .populate('admins', 'name username');
    
//     res.json(groups);
//   } catch (error) {
//     console.error('❌ Get groups error:', error);
//     res.status(500).json({ error: 'Failed to fetch groups' });
//   }
// });





// ========================================
// 👥 COMPLETE GROUP ROUTES - COPY & PASTE THIS ENTIRE SECTION
// ========================================
// DELETE ALL OTHER GROUP ROUTES AND REPLACE WITH THIS

// CREATE GROUP - Enhanced with validation
app.post('/api/groups', authenticateToken, async (req, res) => {
  try {
    const { name, description, members = [], profilePic } = req.body;
    
    console.log('📝 Creating group:', { name, members, userId: req.user.userId });
    
    if (!name || name.trim() === '') {
      return res.status(400).json({ error: 'Group name is required' });
    }
    
    // Validate that all member IDs exist
    const memberIds = [...new Set([...members, req.user.userId])];
    console.log('👥 Validating members:', memberIds);
    
    const validMembers = await User.find({ _id: { $in: memberIds } });
    
    if (validMembers.length !== memberIds.length) {
      console.error('❌ Invalid members detected');
      return res.status(400).json({ error: 'One or more member IDs are invalid' });
    }
    
    const group = new Group({
      name: name.trim(),
      description: description || '',
      profilePic: profilePic || '',
      members: memberIds,
      admins: [req.user.userId],
      createdBy: req.user.userId,
      zegoGroupId: `group_${new mongoose.Types.ObjectId()}`,
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    const savedGroup = await group.save();
    console.log('💾 Group saved to DB:', savedGroup._id);
    
    await savedGroup.populate('members', 'name username profilePic isOnline');
    await savedGroup.populate('admins', 'name username');
    await savedGroup.populate('createdBy', 'name username');
    
    console.log(`✅ Group created successfully: ${name} (ID: ${savedGroup._id})`);
    
    res.status(201).json({
      message: 'Group created successfully',
      group: savedGroup
    });
  } catch (error) {
    console.error('❌ Create group error:', error);
    res.status(500).json({ 
      error: 'Failed to create group',
      details: error.message 
    });
  }
});

// GET ALL GROUPS - User's groups (RETURNS ARRAY DIRECTLY)
app.get('/api/groups', authenticateToken, async (req, res) => {
  try {
    console.log('📋 Fetching groups for user:', req.user.userId);
    
    const groups = await Group.find({
      members: req.user.userId
    })
    .populate('members', 'name username profilePic isOnline lastSeen')
    .populate('admins', 'name username')
    .populate('createdBy', 'name username')
    .sort({ updatedAt: -1 })
    .lean();
    
    console.log(`✅ Fetched ${groups.length} groups for user: ${req.user.userId}`);
    console.log('Groups:', groups.map(g => ({ id: g._id, name: g.name })));
    
    // Return array directly (not wrapped in object)
    res.json(groups);
  } catch (error) {
    console.error('❌ Get groups error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch groups',
      details: error.message 
    });
  }
});

// GET SINGLE GROUP - Group details
app.get('/api/groups/:groupId', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    
    console.log('🔍 Fetching group:', groupId);
    
    // Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(groupId)) {
      console.error('❌ Invalid group ID format:', groupId);
      return res.status(400).json({ 
        error: 'Invalid group ID format' 
      });
    }
    
    const group = await Group.findById(groupId)
      .populate('members', 'name username profilePic isOnline lastSeen')
      .populate('admins', 'name username')
      .populate('createdBy', 'name username');
    
    if (!group) {
      console.error('❌ Group not found:', groupId);
      return res.status(404).json({ 
        error: 'Group not found' 
      });
    }
    
    // Check if user is a member
    const isMember = group.members.some(m => m._id.toString() === req.user.userId);
    if (!isMember) {
      console.error('❌ User not a member:', req.user.userId);
      return res.status(403).json({ 
        error: 'You are not a member of this group' 
      });
    }
    
    console.log('✅ Group fetched successfully:', group.name);
    
    res.json(group);
  } catch (error) {
    console.error('❌ Get group error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch group',
      details: error.message 
    });
  }
});

// GET GROUP MESSAGES - Fixed version
app.get('/api/groups/:groupId/messages', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    console.log(`📨 Fetching messages for group: ${groupId}`);

    // Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(groupId)) {
      console.error('❌ Invalid group ID format:', groupId);
      return res.status(400).json({ 
        error: 'Invalid group ID format' 
      });
    }

    // Check if group exists
    const group = await Group.findById(groupId);
    if (!group) {
      console.error('❌ Group not found:', groupId);
      return res.status(404).json({ 
        error: 'Group not found' 
      });
    }
    
    // Check if user is a member of the group
    const isMember = group.members.some(m => m.toString() === req.user.userId);
    if (!isMember) {
      console.error('❌ User not a member:', req.user.userId);
      return res.status(403).json({ 
        error: 'You are not a member of this group' 
      });
    }

    const messages = await Message.find({ group: groupId })
      .sort({ timestamp: -1 })
      .limit(limit)
      .skip(offset)
      .populate('sender', 'name username profilePic zegoUserId')
      .lean();
      
    console.log(`✅ Fetched ${messages.length} messages for group: ${groupId}`);

    // Return array directly (oldest first for display)
    res.json(messages.reverse());

  } catch (err) {
    console.error('❌ Error fetching group messages:', err);
    res.status(500).json({ 
      error: 'Failed to fetch group messages',
      details: err.message 
    });
  }
});

// UPDATE GROUP - Edit group details
app.put('/api/groups/:groupId', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { name, description, profilePic } = req.body;
    
    console.log('✏️ Updating group:', groupId);
    
    // Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(groupId)) {
      return res.status(400).json({ 
        error: 'Invalid group ID format' 
      });
    }
    
    const group = await Group.findById(groupId);
    
    if (!group) {
      return res.status(404).json({ 
        error: 'Group not found' 
      });
    }
    
    // Check if user is admin
    const isAdmin = group.admins.some(a => a.toString() === req.user.userId);
    if (!isAdmin) {
      return res.status(403).json({ 
        error: 'Only group admins can update group details' 
      });
    }
    
    const updates = {};
    if (name && name.trim() !== '') updates.name = name.trim();
    if (description !== undefined) updates.description = description;
    if (profilePic !== undefined) updates.profilePic = profilePic;
    updates.updatedAt = new Date();
    
    const updatedGroup = await Group.findByIdAndUpdate(
      groupId,
      updates,
      { new: true }
    )
    .populate('members', 'name username profilePic isOnline')
    .populate('admins', 'name username')
    .populate('createdBy', 'name username');
    
    console.log(`✅ Group updated: ${updatedGroup.name}`);
    
    res.json({
      message: 'Group updated successfully',
      group: updatedGroup
    });
  } catch (error) {
    console.error('❌ Update group error:', error);
    res.status(500).json({ 
      error: 'Failed to update group',
      details: error.message 
    });
  }
});

// ADD MEMBER TO GROUP
app.post('/api/groups/:groupId/members', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { userId } = req.body;
    
    console.log('➕ Adding member to group:', { groupId, userId });
    
    if (!userId) {
      return res.status(400).json({ 
        error: 'User ID is required' 
      });
    }
    
    // Validate ObjectId formats
    if (!mongoose.Types.ObjectId.isValid(groupId) || !mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ 
        error: 'Invalid ID format' 
      });
    }
    
    const group = await Group.findById(groupId);
    
    if (!group) {
      return res.status(404).json({ 
        error: 'Group not found' 
      });
    }
    
    // Check if requester is admin
    const isAdmin = group.admins.some(a => a.toString() === req.user.userId);
    if (!isAdmin) {
      return res.status(403).json({ 
        error: 'Only group admins can add members' 
      });
    }
    
    // Check if user exists
    const userToAdd = await User.findById(userId);
    if (!userToAdd) {
      return res.status(404).json({ 
        error: 'User not found' 
      });
    }
    
    // Check if already a member
    const isMember = group.members.some(m => m.toString() === userId);
    if (isMember) {
      return res.status(400).json({ 
        error: 'User is already a member' 
      });
    }
    
    group.members.push(userId);
    group.updatedAt = new Date();
    await group.save();
    await group.populate('members', 'name username profilePic isOnline');
    
    console.log(`✅ Member added to group: ${userToAdd.username} -> ${group.name}`);
    
    res.json({
      message: 'Member added successfully',
      group: group
    });
  } catch (error) {
    console.error('❌ Add member error:', error);
    res.status(500).json({ 
      error: 'Failed to add member',
      details: error.message 
    });
  }
});

// REMOVE MEMBER FROM GROUP
app.delete('/api/groups/:groupId/members/:userId', authenticateToken, async (req, res) => {
  try {
    const { groupId, userId } = req.params;
    
    console.log('➖ Removing member from group:', { groupId, userId });
    
    // Validate ObjectId formats
    if (!mongoose.Types.ObjectId.isValid(groupId) || !mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ 
        error: 'Invalid ID format' 
      });
    }
    
    const group = await Group.findById(groupId);
    
    if (!group) {
      return res.status(404).json({ 
        error: 'Group not found' 
      });
    }
    
    // Check if requester is admin
    const isAdmin = group.admins.some(a => a.toString() === req.user.userId);
    if (!isAdmin) {
      return res.status(403).json({ 
        error: 'Only group admins can remove members' 
      });
    }
    
    // Can't remove the creator
    if (group.createdBy.toString() === userId) {
      return res.status(400).json({ 
        error: 'Cannot remove group creator' 
      });
    }
    
    // Remove from members and admins
    group.members = group.members.filter(m => m.toString() !== userId);
    group.admins = group.admins.filter(a => a.toString() !== userId);
    group.updatedAt = new Date();
    
    await group.save();
    await group.populate('members', 'name username profilePic isOnline');
    
    console.log(`✅ Member removed from group: ${userId} from ${group.name}`);
    
    res.json({
      message: 'Member removed successfully',
      group: group
    });
  } catch (error) {
    console.error('❌ Remove member error:', error);
    res.status(500).json({ 
      error: 'Failed to remove member',
      details: error.message 
    });
  }
});

// LEAVE GROUP (for non-admin members)
app.post('/api/groups/:groupId/leave', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    
    console.log('👋 User leaving group:', { groupId, userId: req.user.userId });
    
    if (!mongoose.Types.ObjectId.isValid(groupId)) {
      return res.status(400).json({ error: 'Invalid group ID format' });
    }
    
    const group = await Group.findById(groupId);
    
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    
    // Can't leave if you're the creator
    if (group.createdBy.toString() === req.user.userId) {
      return res.status(400).json({ 
        error: 'Group creator cannot leave. Transfer ownership or delete the group.' 
      });
    }
    
    // Remove from members and admins
    group.members = group.members.filter(m => m.toString() !== req.user.userId);
    group.admins = group.admins.filter(a => a.toString() !== req.user.userId);
    group.updatedAt = new Date();
    
    await group.save();
    
    console.log(`✅ User left group: ${req.user.userId} from ${group.name}`);
    
    res.json({ message: 'Left group successfully' });
  } catch (error) {
    console.error('❌ Leave group error:', error);
    res.status(500).json({ 
      error: 'Failed to leave group',
      details: error.message 
    });
  }
});

// DELETE GROUP
app.delete('/api/groups/:groupId', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    
    console.log('🗑️ Deleting group:', groupId);
    
    // Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(groupId)) {
      return res.status(400).json({ 
        error: 'Invalid group ID format' 
      });
    }
    
    const group = await Group.findById(groupId);
    
    if (!group) {
      return res.status(404).json({ 
        error: 'Group not found' 
      });
    }
    
    // Only creator can delete group
    if (group.createdBy.toString() !== req.user.userId) {
      return res.status(403).json({ 
        error: 'Only the group creator can delete the group' 
      });
    }
    
    // Delete all group messages
    const deletedMessages = await Message.deleteMany({ group: groupId });
    console.log(`🗑️ Deleted ${deletedMessages.deletedCount} messages`);
    
    // Delete the group
    await Group.findByIdAndDelete(groupId);
    
    console.log(`✅ Group deleted: ${group.name}`);
    
    res.json({
      message: 'Group deleted successfully'
    });
  } catch (error) {
    console.error('❌ Delete group error:', error);
    res.status(500).json({ 
      error: 'Failed to delete group',
      details: error.message 
    });
  }
});

// ========================================
// END OF GROUP ROUTES
// ========================================







// ========================================
// 💬 MESSAGING ENDPOINTS
// ========================================

app.get('/api/messages/:chatId', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { page = 1, limit = 50 } = req.query;
    
    const skip = (page - 1) * limit;
    
    const messages = await Message.find({
      $or: [
        { recipient: chatId, sender: req.user.userId },
        { sender: chatId, recipient: req.user.userId },
        { group: chatId }
      ]
    })
    .populate('sender', 'name username profilePic')
    .populate('recipient', 'name username profilePic')
    .populate('group', 'name')
    .sort({ timestamp: -1 })
    .limit(parseInt(limit))
    .skip(skip);
    
    res.json(messages.reverse());
  } catch (error) {
    console.error('❌ Get messages error:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { recipientId, groupId, content, messageType = 'text', fileUrl, fileName, fileSize, zegoMessageId } = req.body;
    
    if (!content && !fileUrl) {
      return res.status(400).json({ error: 'Message content or file is required' });
    }
    
    if (!recipientId && !groupId) {
      return res.status(400).json({ error: 'Either recipientId or groupId is required' });
    }
    
    const message = new Message({
      sender: req.user.userId,
      recipient: recipientId || null,
      group: groupId || null,
      content: content || '',
      messageType,
      fileUrl: fileUrl || null,
      fileName: fileName || null,
      fileSize: fileSize || null,
      zegoMessageId,
      timestamp: new Date()
    });
    
    await message.save();
    
    await message.populate('sender', 'name username profilePic');
    if (recipientId) {
      await message.populate('recipient', 'name username profilePic');
    }
    if (groupId) {
      await message.populate('group', 'name');
    }
    
    console.log(`✅ Message sent: ${req.user.userId} -> ${recipientId || groupId}`);
    
    res.status(201).json({
      message: 'Message sent successfully',
      data: message
    });
  } catch (error) {
    console.error('❌ Send message error:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    const userGroups = await Group.find({ members: req.user.userId }).distinct('_id');
    
    const recentMessages = await Message.aggregate([
      {
        $match: {
          $or: [
            { sender: new mongoose.Types.ObjectId(req.user.userId) },
            { recipient: new mongoose.Types.ObjectId(req.user.userId) },
            { group: { $in: userGroups } }
          ]
        }
      },
      {
        $sort: { timestamp: -1 }
      },
      {
        $group: {
          _id: {
            $cond: [
              { $ne: ["$group", null] },
              "$group",
              {
                $cond: [
                  { $eq: ["$sender", new mongoose.Types.ObjectId(req.user.userId)] },
                  "$recipient",
                  "$sender"
                ]
              }
            ]
          },
          lastMessage: { $first: "$ROOT" }
        }
      },
      {
        $sort: { "lastMessage.timestamp": -1 }
      }
    ]);
    
    const chats = [];
    for (const item of recentMessages) {
      const lastMessage = item.lastMessage;
      let chatInfo = {};
      
      if (lastMessage.group) {
        const group = await Group.findById(lastMessage.group)
          .populate('members', 'name username profilePic isOnline');
        if (group) {
          chatInfo = {
            id: group._id,
            name: group.name,
            type: 'group',
            profilePic: group.profilePic,
            lastMessage: lastMessage.content,
            lastMessageType: lastMessage.messageType,
            timestamp: lastMessage.timestamp,
            members: group.members,
            unreadCount: 0
          };
        }
      } else {
        const otherUserId = lastMessage.sender.toString() === req.user.userId 
          ? lastMessage.recipient 
          : lastMessage.sender;
        const otherUser = await User.findById(otherUserId, 'name username profilePic isOnline lastSeen');
        if (otherUser) {
          chatInfo = {
            id: otherUser._id,
            name: otherUser.name,
            username: otherUser.username,
            type: 'direct',
            profilePic: otherUser.profilePic,
            isOnline: otherUser.isOnline,
            lastSeen: otherUser.lastSeen,
            lastMessage: lastMessage.content,
            lastMessageType: lastMessage.messageType,
            timestamp: lastMessage.timestamp,
            unreadCount: 0
          };
        }
      }
      
      if (Object.keys(chatInfo).length > 0) {
        chats.push(chatInfo);
      }
    }
    
    res.json(chats);
  } catch (error) {
    console.error('❌ Get chats error:', error);
    res.status(500).json({ error: 'Failed to fetch chats' });
  }
});

// ========================================
// 📞 CALLING ENDPOINTS
// ========================================

app.post('/api/calls/initiate', authenticateToken, async (req, res) => {
  try {
    const { recipientId, callType = 'voice', groupId } = req.body;
    
    if (!recipientId && !groupId) {
      return res.status(400).json({ error: 'Either recipientId or groupId is required' });
    }
    
    const callId = `call_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const caller = await User.findById(req.user.userId, 'name username profilePic');
    
    let callData = {
      callId,
      callerId: req.user.userId,
      callerName: caller.name,
      callerProfilePic: caller.profilePic,
      callType,
      status: 'initiated',
      timestamp: new Date()
    };
    
    if (recipientId) {
      const recipient = await User.findById(recipientId, 'name username profilePic isOnline');
      if (!recipient) {
        return res.status(404).json({ error: 'Recipient not found' });
      }
      
      callData.recipientId = recipientId;
      callData.recipientName = recipient.name;
      callData.recipientProfilePic = recipient.profilePic;
      callData.recipientOnline = recipient.isOnline;
    } else {
      const group = await Group.findById(groupId).populate('members', 'name username profilePic isOnline');
      if (!group) {
        return res.status(404).json({ error: 'Group not found' });
      }
      
      callData.groupId = groupId;
      callData.groupName = group.name;
      callData.members = group.members;
    }
    
    console.log(`✅ Call initiated: ${callId}`);
    
    res.json({
      message: 'Call initiated successfully',
      call: callData
    });
  } catch (error) {
    console.error('❌ Initiate call error:', error);
    res.status(500).json({ error: 'Failed to initiate call' });
  }
});

app.post('/api/calls/:callId/end', authenticateToken, async (req, res) => {
  try {
    const { callId } = req.params;
    const { duration = 0, reason = 'ended' } = req.body;
    
    console.log(`✅ Call ended: ${callId}, duration: ${duration}s`);
    
    res.json({
      message: 'Call ended successfully',
      callId,
      duration,
      reason,
      endedBy: req.user.userId,
      timestamp: new Date()
    });
  } catch (error) {
    console.error('❌ End call error:', error);
    res.status(500).json({ error: 'Failed to end call' });
  }
});

app.get('/api/calls/history', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    
    const callHistory = [];
    
    res.json({
      calls: callHistory,
      page: parseInt(page),
      limit: parseInt(limit),
      total: 0
    });
  } catch (error) {
    console.error('❌ Get call history error:', error);
    res.status(500).json({ error: 'Failed to fetch call history' });
  }
});

// ========================================
// 👑 ADMIN ROUTES
// ========================================

app.post('/api/admin/create-admin', async (req, res) => {
  try {
    const existingAdmin = await User.findOne({ role: 'admin' });
    if (existingAdmin) {
      return res.status(400).json({ error: 'Admin user already exists' });
    }
    
    const { name, username, email, password } = req.body;
    
    if (!name || !username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const adminUser = new User({
      name,
      username,
      email,
      password: hashedPassword,
      role: 'admin',
      zegoUserId: `zego_admin_${new mongoose.Types.ObjectId()}`
    });
    
    await adminUser.save();
    
    console.log(`✅ Admin user created: ${username}`);
    
    res.status(201).json({
      message: 'Admin user created successfully',
      user: {
        id: adminUser._id,
        name: adminUser.name,
        username: adminUser.username,
        email: adminUser.email,
        role: adminUser.role
      }
    });
  } catch (error) {
    console.error('❌ Admin creation error:', error);
    res.status(500).json({ error: 'Admin creation failed' });
  }
});

app.post('/api/admin/users', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { name, username, email, password, role = 'user', profilePic } = req.body;
    
    if (!name || !username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({
      name,
      username,
      email,
      password: hashedPassword,
      role,
      profilePic: profilePic || '',
      zegoUserId: `zego_${new mongoose.Types.ObjectId()}`
    });
    
    await user.save();
    
    console.log(`✅ User created by admin: ${username}`);
    
    res.status(201).json({
      message: 'User created successfully',
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
    console.error('❌ Admin user creation error:', error);
    res.status(500).json({ error: 'User creation failed' });
  }
});

app.put('/api/admin/users/:userId', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { userId } = req.params;
    const updates = req.body;
    
    delete updates.password;
    updates.updatedAt = new Date();
    
    const user = await User.findByIdAndUpdate(
      userId,
      updates,
      { new: true, select: '-password' }
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    console.log(`✅ User updated by admin: ${user.username}`);
    
    res.json({
      message: 'User updated successfully',
      user
    });
  } catch (error) {
    console.error('❌ Admin user update error:', error);
    res.status(500).json({ error: 'User update failed' });
  }
});

app.delete('/api/admin/users/:userId', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { userId } = req.params;
    
    if (userId === req.user.userId) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    
    const user = await User.findByIdAndDelete(userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    console.log(`✅ User deleted by admin: ${user.username}`);
    
    res.json({
      message: 'User deleted successfully'
    });
  } catch (error) {
    console.error('❌ Admin user deletion error:', error);
    res.status(500).json({ error: 'User deletion failed' });
  }
});

app.put('/api/admin/users/:userId/role', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { userId } = req.params;
    const { role } = req.body;
    
    if (!['user', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    
    const user = await User.findByIdAndUpdate(
      userId,
      { role, updatedAt: new Date() },
      { new: true, select: '-password' }
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    console.log(`✅ User role updated: ${user.username} -> ${role}`);
    
    res.json({
      message: 'User role updated successfully',
      user
    });
  } catch (error) {
    console.error('❌ Role update error:', error);
    res.status(500).json({ error: 'Role update failed' });
  }
});













// // ========================================
// // 💾 BACKUP & RESTORE SYSTEM - FIXED VERSION
// // ========================================

// // 1️⃣ CREATE BACKUP - Download all user data to Cloudinary
// app.post("/api/backup/:userId", authenticateToken, async (req, res) => {
//   try {
//     const { userId } = req.params;

//     // Security: Users can only backup their own data (or admin can backup anyone)
//     if (req.user.userId !== userId && req.user.role !== 'admin') {
//       return res.status(403).json({ 
//         success: false,
//         message: "You can only backup your own data" 
//       });
//     }

//     console.log(`📦 Starting backup for user: ${userId}`);

//     // Fetch all user-related data
//     const user = await User.findById(userId).select('-password').lean();
//     if (!user) {
//       return res.status(404).json({ 
//         success: false,
//         message: "User not found" 
//       });
//     }

//     // Get all groups user is member of
//     const groups = await Group.find({ members: userId }).lean();
//     const groupIds = groups.map(g => g._id);

//     // Get ALL messages (sent, received, and group messages)
//     const messages = await Message.find({
//       $or: [
//         { sender: userId },           // Messages sent by user
//         { recipient: userId },        // Messages received by user
//         { group: { $in: groupIds } }  // Group messages
//       ]
//     }).lean();

//     // Prepare backup data
//     const backupData = {
//       version: "1.0",
//       backupDate: new Date(),
//       user: {
//         id: user._id,
//         name: user.name,
//         username: user.username,
//         email: user.email,
//         profilePic: user.profilePic,
//         role: user.role,
//         zegoUserId: user.zegoUserId,
//         createdAt: user.createdAt
//       },
//       groups: groups,
//       messages: messages,
//       statistics: {
//         totalGroups: groups.length,
//         totalMessages: messages.length,
//         sentMessages: messages.filter(m => m.sender.toString() === userId).length,
//         receivedMessages: messages.filter(m => m.recipient?.toString() === userId).length,
//         groupMessages: messages.filter(m => m.group).length
//       }
//     };

//     // Convert to JSON
//     const backupJSON = JSON.stringify(backupData, null, 2);
//     const backupBuffer = Buffer.from(backupJSON);

//     console.log(`📊 Backup stats: ${messages.length} messages, ${groups.length} groups`);

//     // Upload to Cloudinary using upload method (not upload_stream)
//     const uploadResult = await new Promise((resolve, reject) => {
//       const uploadStream = cloudinary.uploader.upload_stream(
//         {
//           resource_type: "raw",
//           folder: "hichat_backups",
//           public_id: `backup_${userId}_${Date.now()}`,
//           format: "json"
//         },
//         (error, result) => {
//           if (error) {
//             console.error('❌ Cloudinary upload error:', error);
//             reject(error);
//           } else {
//             resolve(result);
//           }
//         }
//       );

//       // Write buffer to stream
//       const readable = Readable.from([backupBuffer]);
//       readable.pipe(uploadStream);
//     });

//     // Save backup URL in user's record
//     await User.findByIdAndUpdate(userId, {
//       $set: {
//         lastBackup: {
//           url: uploadResult.secure_url,
//           date: new Date(),
//           publicId: uploadResult.public_id,
//           size: backupBuffer.length,
//           messageCount: messages.length,
//           groupCount: groups.length
//         }
//       }
//     });

//     console.log(`✅ Backup completed: ${uploadResult.secure_url}`);

//     res.json({
//       success: true,
//       message: "Backup created successfully!",
//       backup: {
//         url: uploadResult.secure_url,
//         date: new Date(),
//         size: `${(backupBuffer.length / 1024).toFixed(2)} KB`,
//         statistics: backupData.statistics
//       }
//     });

//   } catch (err) {
//     console.error("❌ Backup failed:", err);
//     res.status(500).json({ 
//       success: false,
//       message: "Backup failed", 
//       error: err.message 
//     });
//   }
// });


// // 2️⃣ RESTORE BACKUP - Restore user data from Cloudinary backup
// app.post("/api/restore/:userId", authenticateToken, async (req, res) => {
//   try {
//     const { userId } = req.params;

//     // Security: Users can only restore their own data (or admin can restore anyone)
//     if (req.user.userId !== userId && req.user.role !== 'admin') {
//       return res.status(403).json({ 
//         success: false,
//         message: "You can only restore your own data" 
//       });
//     }

//     console.log(`🔄 Starting restore for user: ${userId}`);

//     const user = await User.findById(userId);
//     if (!user) {
//       return res.status(404).json({ 
//         success: false,
//         message: "User not found" 
//       });
//     }

//     if (!user.lastBackup?.url) {
//       return res.status(404).json({ 
//         success: false,
//         message: "No backup found for this user. Please create a backup first." 
//       });
//     }

//     // Download backup JSON from Cloudinary
//     console.log(`📥 Downloading backup from: ${user.lastBackup.url}`);
//     const response = await axios.get(user.lastBackup.url);
//     const backupData = response.data;

//     // Validate backup data
//     if (!backupData.version || !backupData.user || !backupData.messages) {
//       return res.status(400).json({ 
//         success: false,
//         message: "Invalid backup file format" 
//       });
//     }

//     console.log(`📊 Restoring: ${backupData.statistics?.totalMessages || 0} messages, ${backupData.statistics?.totalGroups || 0} groups`);

//     // Start restore process (wrapped in try-catch for safety)
//     try {
//       // 1. Delete existing messages (only user's sent/received messages, not all)
//       await Message.deleteMany({
//         $or: [
//           { sender: userId },
//           { recipient: userId }
//         ]
//       });
//       console.log('✅ Cleared old messages');

//       // 2. Delete existing groups where user is creator (optional - be careful!)
//       // await Group.deleteMany({ createdBy: userId });

//       // 3. Restore groups (skip duplicates)
//       if (backupData.groups && backupData.groups.length > 0) {
//         for (const group of backupData.groups) {
//           const exists = await Group.findById(group._id);
//           if (!exists) {
//             await Group.create(group);
//           }
//         }
//         console.log(`✅ Restored ${backupData.groups.length} groups`);
//       }

//       // 4. Restore messages (skip duplicates)
//       if (backupData.messages && backupData.messages.length > 0) {
//         const messagesToInsert = [];
//         for (const msg of backupData.messages) {
//           const exists = await Message.findById(msg._id);
//           if (!exists) {
//             messagesToInsert.push(msg);
//           }
//         }
        
//         if (messagesToInsert.length > 0) {
//           await Message.insertMany(messagesToInsert, { ordered: false });
//         }
//         console.log(`✅ Restored ${messagesToInsert.length} messages`);
//       }

//       // 5. Update user profile (optional - restore profile pic, etc.)
//       if (backupData.user.profilePic) {
//         await User.findByIdAndUpdate(userId, {
//           profilePic: backupData.user.profilePic
//         });
//       }

//       res.json({
//         success: true,
//         message: "Backup restored successfully!",
//         restored: {
//           messages: backupData.messages?.length || 0,
//           groups: backupData.groups?.length || 0,
//           backupDate: backupData.backupDate
//         }
//       });

//     } catch (restoreError) {
//       console.error('❌ Restore operation failed:', restoreError);
//       throw new Error(`Restore failed: ${restoreError.message}`);
//     }

//   } catch (err) {
//     console.error("❌ Restore failed:", err);
//     res.status(500).json({ 
//       success: false,
//       message: "Restore failed", 
//       error: err.message 
//     });
//   }
// });


// // 3️⃣ GET BACKUP INFO - Check if backup exists
// app.get("/api/backup/:userId/info", authenticateToken, async (req, res) => {
//   try {
//     const { userId } = req.params;

//     // Security check
//     if (req.user.userId !== userId && req.user.role !== 'admin') {
//       return res.status(403).json({ 
//         success: false,
//         message: "Access denied" 
//       });
//     }

//     const user = await User.findById(userId).select('lastBackup');
    
//     if (!user) {
//       return res.status(404).json({ 
//         success: false,
//         message: "User not found" 
//       });
//     }

//     if (!user.lastBackup?.url) {
//       return res.json({
//         success: true,
//         hasBackup: false,
//         message: "No backup available"
//       });
//     }

//     res.json({
//       success: true,
//       hasBackup: true,
//       backup: {
//         url: user.lastBackup.url,
//         date: user.lastBackup.date,
//         size: user.lastBackup.size ? `${(user.lastBackup.size / 1024).toFixed(2)} KB` : 'Unknown',
//         messageCount: user.lastBackup.messageCount || 0,
//         groupCount: user.lastBackup.groupCount || 0
//       }
//     });

//   } catch (err) {
//     console.error("❌ Get backup info failed:", err);
//     res.status(500).json({ 
//       success: false,
//       message: "Failed to get backup info", 
//       error: err.message 
//     });
//   }
// });


// // 4️⃣ DELETE BACKUP - Remove backup from Cloudinary
// app.delete("/api/backup/:userId", authenticateToken, async (req, res) => {
//   try {
//     const { userId } = req.params;

//     // Security check
//     if (req.user.userId !== userId && req.user.role !== 'admin') {
//       return res.status(403).json({ 
//         success: false,
//         message: "Access denied" 
//       });
//     }

//     const user = await User.findById(userId);
    
//     if (!user || !user.lastBackup?.publicId) {
//       return res.status(404).json({ 
//         success: false,
//         message: "No backup found" 
//       });
//     }

//     // Delete from Cloudinary
//     await cloudinary.uploader.destroy(user.lastBackup.publicId, { resource_type: 'raw' });

//     // Clear backup info from user record
//     await User.findByIdAndUpdate(userId, {
//       $unset: { lastBackup: "" }
//     });

//     console.log(`✅ Backup deleted for user: ${userId}`);

//     res.json({
//       success: true,
//       message: "Backup deleted successfully"
//     });

//   } catch (err) {
//     console.error("❌ Delete backup failed:", err);
//     res.status(500).json({ 
//       success: false,
//       message: "Failed to delete backup", 
//       error: err.message 
//     });
//   }
// });






// ========================================
// 💾 BACKUP & RESTORE SYSTEM - FIXED VERSION
// ========================================

// 1️⃣ CREATE BACKUP - Download all user data to Cloudinary
app.post("/api/backup/:userId", authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;

    // Security: Users can only backup their own data (or admin can backup anyone)
    if (req.user.userId !== userId && req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false,
        message: "You can only backup your own data" 
      });
    }

    console.log(`📦 Starting backup for user: ${userId}`);

    // Fetch all user-related data
    const user = await User.findById(userId).select('-password').lean();
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: "User not found" 
      });
    }

    // Get all groups user is member of
    const groups = await Group.find({ members: userId }).lean();
    const groupIds = groups.map(g => g._id);

    // Get ALL messages (sent, received, and group messages)
    const messages = await Message.find({
      $or: [
        { sender: userId },           // Messages sent by user
        { recipient: userId },        // Messages received by user
        { group: { $in: groupIds } }  // Group messages
      ]
    }).lean();

    // Prepare backup data
    const backupData = {
      version: "1.0",
      backupDate: new Date(),
      user: {
        id: user._id,
        name: user.name,
        username: user.username,
        email: user.email,
        profilePic: user.profilePic,
        role: user.role,
        zegoUserId: user.zegoUserId,
        createdAt: user.createdAt
      },
      groups: groups,
      messages: messages,
      statistics: {
        totalGroups: groups.length,
        totalMessages: messages.length,
        sentMessages: messages.filter(m => m.sender.toString() === userId).length,
        receivedMessages: messages.filter(m => m.recipient?.toString() === userId).length,
        groupMessages: messages.filter(m => m.group).length
      }
    };

    // Convert to JSON
    const backupJSON = JSON.stringify(backupData, null, 2);
    const backupBuffer = Buffer.from(backupJSON);

    console.log(`📊 Backup stats: ${messages.length} messages, ${groups.length} groups`);

    // Upload to Cloudinary using upload method (not upload_stream)
    const uploadResult = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          resource_type: "raw",
          folder: "hichat_backups",
          public_id: `backup_${userId}_${Date.now()}`,
          format: "json"
        },
        (error, result) => {
          if (error) {
            console.error('❌ Cloudinary upload error:', error);
            reject(error);
          } else {
            resolve(result);
          }
        }
      );

      // Write buffer to stream
      const readable = Readable.from([backupBuffer]);
      readable.pipe(uploadStream);
    });

    // Save backup URL in user's record
    await User.findByIdAndUpdate(userId, {
      $set: {
        lastBackup: {
          url: uploadResult.secure_url,
          date: new Date(),
          publicId: uploadResult.public_id,
          size: backupBuffer.length,
          messageCount: messages.length,
          groupCount: groups.length
        }
      }
    });

    console.log(`✅ Backup completed: ${uploadResult.secure_url}`);

    res.json({
      success: true,
      message: "Backup created successfully!",
      backup: {
        url: uploadResult.secure_url,
        date: new Date(),
        size: `${(backupBuffer.length / 1024).toFixed(2)} KB`,
        statistics: backupData.statistics
      }
    });

  } catch (err) {
    console.error("❌ Backup failed:", err);
    res.status(500).json({ 
      success: false,
      message: "Backup failed", 
      error: err.message 
    });
  }
});


// 2️⃣ RESTORE BACKUP - Restore user data from Cloudinary backup
// app.post("/api/restore/:userId", authenticateToken, async (req, res) => {
//   try {
//     const { userId } = req.params;

//     // Security: Users can only restore their own data (or admin can restore anyone)
//     if (req.user.userId !== userId && req.user.role !== 'admin') {
//       return res.status(403).json({ 
//         success: false,
//         message: "You can only restore your own data" 
//       });
//     }

//     console.log(`🔄 Starting restore for user: ${userId}`);

//     const user = await User.findById(userId);
//     if (!user) {
//       return res.status(404).json({ 
//         success: false,
//         message: "User not found" 
//       });
//     }

//     if (!user.lastBackup?.url) {
//       return res.status(404).json({ 
//         success: false,
//         message: "No backup found for this user. Please create a backup first." 
//       });
//     }

//     // Download backup JSON from Cloudinary
//     console.log(`📥 Downloading backup from: ${user.lastBackup.url}`);
//     const response = await axios.get(user.lastBackup.url);
//     const backupData = response.data;

//     // Validate backup data
//     if (!backupData.version || !backupData.user || !backupData.messages) {
//       return res.status(400).json({ 
//         success: false,
//         message: "Invalid backup file format" 
//       });
//     }

//     console.log(`📊 Restoring: ${backupData.statistics?.totalMessages || 0} messages, ${backupData.statistics?.totalGroups || 0} groups`);

//     // Start restore process (wrapped in try-catch for safety)
//     try {
//       // 1. Delete existing messages (only user's sent/received messages, not all)
//       const deleteResult = await Message.deleteMany({
//         $or: [
//           { sender: userId },
//           { recipient: userId }
//         ]
//       });
//       console.log(`✅ Cleared ${deleteResult.deletedCount} old messages`);

//       // 2. Delete existing groups where user is a member (optional - careful!)
//       const groupDeleteResult = await Group.deleteMany({ 
//         members: userId,
//         createdBy: userId // Only delete groups created by this user
//       });
//       console.log(`✅ Cleared ${groupDeleteResult.deletedCount} old groups`);

//       // 3. Restore groups (recreate with new IDs to avoid duplicates)
//       if (backupData.groups && backupData.groups.length > 0) {
//         const groupsToInsert = backupData.groups.map(group => {
//           // Remove _id to let MongoDB generate new ones
//           const { _id, ...groupData } = group;
//           return groupData;
//         });
        
//         await Group.insertMany(groupsToInsert);
//         console.log(`✅ Restored ${groupsToInsert.length} groups`);
//       }

//       // 4. Restore messages (recreate with new IDs to avoid duplicates)
//       if (backupData.messages && backupData.messages.length > 0) {
//         const messagesToInsert = backupData.messages.map(msg => {
//           // Remove _id to let MongoDB generate new ones
//           const { _id, ...messageData } = msg;
//           return messageData;
//         });
        
//         if (messagesToInsert.length > 0) {
//           await Message.insertMany(messagesToInsert);
//         }
//         console.log(`✅ Restored ${messagesToInsert.length} messages`);
//       }

//       // 5. Update user profile (optional - restore profile pic, etc.)
//       if (backupData.user.profilePic) {
//         await User.findByIdAndUpdate(userId, {
//           profilePic: backupData.user.profilePic
//         });
//       }

//       res.json({
//         success: true,
//         message: "Backup restored successfully!",
//         restored: {
//           messages: backupData.messages?.length || 0,
//           groups: backupData.groups?.length || 0,
//           backupDate: backupData.backupDate
//         }
//       });

//     } catch (restoreError) {
//       console.error('❌ Restore operation failed:', restoreError);
//       throw new Error(`Restore failed: ${restoreError.message}`);
//     }

//   } catch (err) {
//     console.error("❌ Restore failed:", err);
//     res.status(500).json({ 
//       success: false,
//       message: "Restore failed", 
//       error: err.message 
//     });
//   }
// });




// 2️⃣ RESTORE BACKUP - Restore user data from Cloudinary backup
app.post("/api/restore/:userId", authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;

    // Security: Users can only restore their own data (or admin can restore anyone)
    if (req.user.userId !== userId && req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false,
        message: "You can only restore your own data" 
      });
    }

    console.log(`🔄 Starting restore for user: ${userId}`);

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: "User not found" 
      });
    }

    if (!user.lastBackup?.url) {
      return res.status(404).json({ 
        success: false,
        message: "No backup found for this user. Please create a backup first." 
      });
    }

    // Download backup JSON from Cloudinary
    console.log(`📥 Downloading backup from: ${user.lastBackup.url}`);
    const response = await axios.get(user.lastBackup.url);
    const backupData = response.data;

    // Validate backup data
    if (!backupData.version || !backupData.user || !backupData.messages) {
      return res.status(400).json({ 
        success: false,
        message: "Invalid backup file format" 
      });
    }

    console.log(`📊 Restoring: ${backupData.statistics?.totalMessages || 0} messages, ${backupData.statistics?.totalGroups || 0} groups`);

    // Start restore process (wrapped in try-catch for safety)
    try {
      // 1. Delete existing messages (only user's sent/received messages, not all)
      const deleteResult = await Message.deleteMany({
        $or: [
          { sender: userId },
          { recipient: userId }
        ]
      });
      console.log(`✅ Cleared ${deleteResult.deletedCount} old messages`);

      // 2. Delete existing groups where user is a member (optional - careful!)
      const groupDeleteResult = await Group.deleteMany({ 
        members: userId,
        createdBy: userId // Only delete groups created by this user
      });
      console.log(`✅ Cleared ${groupDeleteResult.deletedCount} old groups`);

      // 3. Restore groups with NEW zegoGroupId values to avoid duplicates
      if (backupData.groups && backupData.groups.length > 0) {
        const groupsToInsert = backupData.groups.map(group => {
          const { _id, ...groupData } = group;
          // 🔑 CRITICAL: Generate a NEW zegoGroupId to avoid unique constraint violation
          return {
            ...groupData,
            zegoGroupId: `group_${new mongoose.Types.ObjectId()}`  // Generate new ID
          };
        });
        
        const insertedGroups = await Group.insertMany(groupsToInsert);
        console.log(`✅ Restored ${insertedGroups.length} groups with new zegoGroupId values`);

        // Update messages that reference old group IDs to use new ones
        // Create a mapping of old group IDs to new group IDs
        const groupIdMap = {};
        backupData.groups.forEach((oldGroup, index) => {
          groupIdMap[oldGroup._id.toString()] = insertedGroups[index]._id.toString();
        });

        // 4. Restore messages with updated group references
        if (backupData.messages && backupData.messages.length > 0) {
          const messagesToInsert = backupData.messages.map(msg => {
            const { _id, ...messageData } = msg;
            // Update group reference if message belongs to a group
            if (messageData.group && groupIdMap[messageData.group.toString()]) {
              messageData.group = groupIdMap[messageData.group.toString()];
            }
            return messageData;
          });
          
          if (messagesToInsert.length > 0) {
            await Message.insertMany(messagesToInsert);
          }
          console.log(`✅ Restored ${messagesToInsert.length} messages with updated group references`);
        }
      } else if (backupData.messages && backupData.messages.length > 0) {
        // If no groups, just restore messages as-is
        const messagesToInsert = backupData.messages.map(msg => {
          const { _id, ...messageData } = msg;
          return messageData;
        });
        
        if (messagesToInsert.length > 0) {
          await Message.insertMany(messagesToInsert);
        }
        console.log(`✅ Restored ${messagesToInsert.length} messages`);
      }

      // 5. Update user profile (optional - restore profile pic, etc.)
      if (backupData.user.profilePic) {
        await User.findByIdAndUpdate(userId, {
          profilePic: backupData.user.profilePic
        });
      }

      res.json({
        success: true,
        message: "Backup restored successfully!",
        restored: {
          messages: backupData.messages?.length || 0,
          groups: backupData.groups?.length || 0,
          backupDate: backupData.backupDate
        }
      });

    } catch (restoreError) {
      console.error('❌ Restore operation failed:', restoreError);
      throw new Error(`Restore failed: ${restoreError.message}`);
    }

  } catch (err) {
    console.error("❌ Restore failed:", err);
    res.status(500).json({ 
      success: false,
      message: "Restore failed", 
      error: err.message 
    });
  }
});












// 3️⃣ GET BACKUP INFO - Check if backup exists
app.get("/api/backup/:userId/info", authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;

    // Security check
    if (req.user.userId !== userId && req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false,
        message: "Access denied" 
      });
    }

    const user = await User.findById(userId).select('lastBackup');
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: "User not found" 
      });
    }

    if (!user.lastBackup?.url) {
      return res.json({
        success: true,
        hasBackup: false,
        message: "No backup available"
      });
    }

    res.json({
      success: true,
      hasBackup: true,
      backup: {
        url: user.lastBackup.url,
        date: user.lastBackup.date,
        size: user.lastBackup.size ? `${(user.lastBackup.size / 1024).toFixed(2)} KB` : 'Unknown',
        messageCount: user.lastBackup.messageCount || 0,
        groupCount: user.lastBackup.groupCount || 0
      }
    });

  } catch (err) {
    console.error("❌ Get backup info failed:", err);
    res.status(500).json({ 
      success: false,
      message: "Failed to get backup info", 
      error: err.message 
    });
  }
});


// 4️⃣ DELETE BACKUP - Remove backup from Cloudinary
app.delete("/api/backup/:userId", authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;

    // Security check
    if (req.user.userId !== userId && req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false,
        message: "Access denied" 
      });
    }

    const user = await User.findById(userId);
    
    if (!user || !user.lastBackup?.publicId) {
      return res.status(404).json({ 
        success: false,
        message: "No backup found" 
      });
    }

    // Delete from Cloudinary
    await cloudinary.uploader.destroy(user.lastBackup.publicId, { resource_type: 'raw' });

    // Clear backup info from user record
    await User.findByIdAndUpdate(userId, {
      $unset: { lastBackup: "" }
    });

    console.log(`✅ Backup deleted for user: ${userId}`);

    res.json({
      success: true,
      message: "Backup deleted successfully"
    });

  } catch (err) {
    console.error("❌ Delete backup failed:", err);
    res.status(500).json({ 
      success: false,
      message: "Failed to delete backup", 
      error: err.message 
    });
  }
});
































//Profile Picture


// app.post("/api/users/:userId/profile", cloudinaryUpload.single("image"), async (req, res) => {
//   try {
//     const userId = req.params.userId;

//     const result = await cloudinary.v2.uploader.upload(req.file.path, {
//       folder: "hichat/profile_pics",
//       resource_type: "image",
//     });

//     await User.findByIdAndUpdate(userId, { profilePic: result.secure_url });
//     fs.unlinkSync(req.file.path); // remove local temp file

//     res.json({ message: "Profile updated", url: result.secure_url });
//   } catch (error) {
//     res.status(500).json({ message: "Upload failed", error });
//   }
// });




app.post("/api/users/:userId/profile", cloudinaryUpload.single("image"), async (req, res) => {
  try {
    const userId = req.params.userId;

    // If file not found
    if (!req.file || !req.file.path) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    // File is already uploaded to Cloudinary by Multer
    const imageUrl = req.file.path;

    // Update user's profilePic field in MongoDB
    await User.findByIdAndUpdate(userId, { profilePic: imageUrl });

    res.json({
      success: true,
      message: "Profile picture updated successfully",
      url: imageUrl,
    });
  } catch (error) {
    console.error("❌ Profile upload failed:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});




//First Admin without any error


// ========================================
// AUTO ADMIN CREATION - ADD THIS AFTER YOUR MODELS
// ========================================

// Function to create default admin if none exists
async function ensureAdminExists() {
  try {
    const adminCount = await User.countDocuments({ role: 'admin' });
    
    if (adminCount === 0) {
      console.log('🔐 No admin found. Creating default admin...');
      
      const hashedPassword = await bcrypt.hash('admin123', 10);
      
      const adminUser = new User({
        name: 'Admin User',
        username: 'admin',
        email: 'admin@hichat.com',
        password: hashedPassword,
        role: 'admin',
        zegoUserId: `zego_admin_${new mongoose.Types.ObjectId()}`
      });
      
      const savedAdmin = await adminUser.save();
      
      console.log('✅ Default admin created successfully!');
      console.log('📝 Admin Credentials:');
      console.log('   Username: admin');
      console.log('   Email: admin@hichat.com');
      console.log('   Password: admin123');
      console.log('⚠️  IMPORTANT: Change this password after first login!');
    } else {
      console.log('✅ Admin user already exists. Skipping creation.');
    }
  } catch (error) {
    console.error('❌ Error ensuring admin exists:', error.message);
  }
}





// ========================================
// 🚀 SERVER STARTUP
// ========================================

// const PORT = process.env.PORT || 3000;

// app.listen(PORT, () => {
//   console.log(`
// ╔════════════════════════════════════════════════════════════╗
// ║       🚀 Hi Chat Backend Server - PRODUCTION READY        ║
// ╠════════════════════════════════════════════════════════════╣
// ║  📡 Port:              ${PORT}                            
// ║  🗄️  Database:         ${MONGODB_URI.includes('localhost') ? 'Local MongoDB' : 'Remote MongoDB'}
// ║  ☁️  Cloudinary:        ${cloudinary.config().cloud_name} (✅ Active)
// ║  🎯 ZEGOCLOUD:         App ID ${ZEGOCLOUD_CONFIG.APP_ID} (✅ Configured)
// ║  🌍 Environment:       ${process.env.NODE_ENV || 'development'}
// ║  📁 File Uploads:      ✅ Cloudinary + Local Backup
// ║  💾 Backup System:     ✅ Enabled
// ╚════════════════════════════════════════════════════════════╝

// ✅ Server is ready to accept connections!
// 📝 API Documentation available at: http://localhost:${PORT}/api/health
//   `);
// });

// // Graceful shutdown
// process.on('SIGTERM', () => {
//   console.log('🛑 SIGTERM received, shutting down gracefully');
//   mongoose.connection.close(() => {
//     console.log('✅ Database connection closed');
//     process.exit(0);
//   });
// });

// process.on('SIGINT', () => {
//   console.log('\n🛑 SIGINT received, shutting down gracefully');
//   mongoose.connection.close(() => {
//     console.log('✅ Database connection closed');
//     process.exit(0);
//   });
// });

// // Error handlers
// process.on('unhandledRejection', (reason, promise) => {
//   console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
// });

// process.on('uncaughtException', (error) => {
//   console.error('❌ Uncaught Exception:', error);
//   process.exit(1);
// });



// app.listen(PORT, () => {
//   console.log('╔════════════════════════════════════════════════════════════╗');
//   console.log('║       🚀 Hi Chat Backend Server - PRODUCTION READY        ║');
//   console.log('╠════════════════════════════════════════════════════════════╣');
//   console.log(`║  📡 Port:              ${PORT}`);
//   console.log(`║  🗄️  Database:         ${MONGODB_URI.includes('localhost') ? 'Local MongoDB' : 'Remote MongoDB'}`);
//   console.log(`║  ☁️  Cloudinary:        ${cloudinary.config().cloud_name} (✅ Active)`);
//   console.log(`║  🎯 ZEGOCLOUD:         App ID ${ZEGOCLOUD_CONFIG.APP_ID} (✅ Configured)`);
//   console.log(`║  🌍 Environment:       ${process.env.NODE_ENV || 'development'}`);
//   console.log('║  📁 File Uploads:      ✅ Cloudinary + Local Backup');
//   console.log('║  💾 Backup System:     ✅ Enabled');
//   console.log('╚════════════════════════════════════════════════════════════╝');
  
//   console.log('\n✅ Server is ready to accept connections!');
//   console.log(`📝 API Documentation available at: http://localhost:${PORT}/api/health`);
// });

// // Graceful shutdown
// process.on('SIGTERM', () => {
//   console.log('🛑 SIGTERM received, shutting down gracefully');
//   mongoose.connection.close(() => {
//     console.log('✅ Database connection closed');
//     process.exit(0);
//   });
// });

// process.on('SIGINT', () => {
//   console.log('\n🛑 SIGINT received, shutting down gracefully');
//   mongoose.connection.close(() => {
//     console.log('✅ Database connection closed');
//     process.exit(0);
//   });
// });

// // Error handlers
// process.on('unhandledRejection', (reason, promise) => {
//   console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
//   // Application specific logging, throwing an error, or other logic here
// });

// process.on('uncaughtException', (err) => {
//   console.error('❌ Uncaught Exception:', err);
//   // Should close database/connections gracefully
//   process.exit(1); // Mandatory exit for uncaught exceptions
// });


// module.exports = app;


















// Change of Configs or Listeners




// ========================================
// MODIFIED SERVER STARTUP
// ========================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, async () => {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║       🚀 Hi Chat Backend Server - PRODUCTION READY        ║');
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log(`║  📡 Port:              ${PORT}`);
  console.log(`║  🗄️  Database:         ${MONGODB_URI.includes('localhost') ? 'Local MongoDB' : 'Remote MongoDB'}`);
  console.log(`║  ☁️  Cloudinary:        ${cloudinary.config().cloud_name} (✅ Active)`);
  console.log(`║  🎯 ZEGOCLOUD:         App ID ${ZEGOCLOUD_CONFIG.APP_ID} (✅ Configured)`);
  console.log(`║  🌍 Environment:       ${process.env.NODE_ENV || 'development'}`);
  console.log('║  📁 File Uploads:      ✅ Cloudinary + Local Backup');
  console.log('║  💾 Backup System:     ✅ Enabled');
  console.log('╚════════════════════════════════════════════════════════════╝');
  
  console.log('\n✅ Server is ready to accept connections!');
  console.log(`📝 API Documentation available at: http://localhost:${PORT}/api/health\n`);
  
  // Ensure admin exists
  await ensureAdminExists();
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully');
  mongoose.connection.close(() => {
    console.log('✅ Database connection closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('\n🛑 SIGINT received, shutting down gracefully');
  mongoose.connection.close(() => {
    console.log('✅ Database connection closed');
    process.exit(0);
  });
});

// Error handlers
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err);
  process.exit(1);
});

module.exports = app;
