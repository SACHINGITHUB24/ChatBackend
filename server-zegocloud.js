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
const { v2: cloudinary } = require('cloudinary');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
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
app.use(morgan('combined'))

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: Number.MAX_SAFE_INTEGER, // effectively unlimited requests
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
// 📁 CLOUDINARY CONFIGURATION
// ========================================

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'dafmi1nyb',
  api_key: process.env.CLOUDINARY_API_KEY || '328393763333636',
  api_secret: process.env.CLOUDINARY_API_SECRET || 'Tra1d9sGSDHul1VP2DWCXvM0lzs',
});

// Cloudinary storage configuration
// const cloudinaryStorage = new CloudinaryStorage({
//   cloudinary,
//   params: {
//     folder: 'HiChatUploads',
//     allowed_formats: ['jpg', 'png', 'jpeg', 'gif', 'mp4', 'mov', 'avi', 'pdf', 'doc', 'docx'],
//     resource_type: 'auto',
//   },
// });


// const cloudinaryStorage = new CloudinaryStorage({
//   cloudinary,
//   params: {
//     folder: 'uploads',
//     allowed_formats: ['jpg', 'png', 'jpeg', 'mp4', 'pdf', 'docx'],
//     resource_type: 'auto'
//   }
// });


// const cloudinaryUpload  = multer({ storage: cloudinaryStorage });





//Again Cloudinary

const cloudinaryStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'HiChatUploads', // main folder in Cloudinary
    allowed_formats: ['jpg','jpeg','png','gif','mp4','mov','avi','pdf','doc','docx','txt'],
    resource_type: 'auto', // auto-detects image/video/document
  }
});


const cloudinaryUpload = multer({
  storage: cloudinaryStorage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
});







// ========================================
// 📁 FILE UPLOAD CONFIGURATION
// ========================================

// const uploadsDir = path.join(__dirname, 'uploads');
// if (!fs.existsSync(uploadsDir)) {
//   fs.mkdirSync(uploadsDir, { recursive: true });
// }

// // Multer configuration for local file uploads (fallback)
// const localStorage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     const uploadPath = path.join(__dirname, 'uploads');
//     cb(null, uploadPath);
//   },
//   filename: (req, file, cb) => {
//     const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
//     cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
//   }
// });

// const upload = multer({ 
//   storage: localStorage,
//   limits: {
//     fileSize: 10 * 1024 * 1024 // 10MB limit
//   },
//   fileFilter: (req, file, cb) => {
//     // Allow images, videos, and documents
//     const allowedTypes = /jpeg|jpg|png|gif|mp4|mov|avi|pdf|doc|docx|txt/;
//     const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
//     const mimetype = allowedTypes.test(file.mimetype);

//     if (mimetype && extname) {
//       return cb(null, true);
//     } else {
//       cb(new Error('Invalid file type. Only images, videos, and documents are allowed.'));
//     }
//   }
// });

// Cloudinary upload configuration

// const cloudinaryUpload = multer({ 
//   storage: cloudinaryStorage,
//   limits: {
//     fileSize: 50 * 1024 * 1024 // 50MB limit for Cloudinary
//   },
//   fileFilter: (req, file, cb) => {
//     // Allow images, videos, and documents
//     const allowedTypes = /jpeg|jpg|png|gif|mp4|mov|avi|pdf|doc|docx|txt/;
//     const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
//     const mimetype = allowedTypes.test(file.mimetype);

//     if (mimetype && extname) {
//       return cb(null, true);
//     } else {
//       cb(new Error('Invalid file type. Only images, videos, and documents are allowed.'));
//     }
//   }
// });



const uploadCloudinary = multer({
  storage: cloudinaryStorage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|mp4|mov|avi|pdf|doc|docx|txt/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (mimetype && extname) cb(null, true);
    else cb(new Error('Invalid file type.'));
  }
});





//Local Backup 

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const localStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, `${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`);
  }
});



const uploadLocal = multer({
  storage: localStorage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|mp4|mov|avi|pdf|doc|docx|txt/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (mimetype && extname) cb(null, true);
    else cb(new Error('Invalid file type.'));
  }
});







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

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/hichat';

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

//ZEGOCLOUD Token Generation
// app.post('/api/getZegoToken', async (req, res) => {
//   try {
//     const { userId } = req.body;
    
//     if (!userId) {
//       return res.status(400).json({ error: 'userId is required' });
//     }
    
//     // Verify user exists
//     const user = await User.findById(userId);
//     if (!user) {
//       return res.status(404).json({ error: 'User not found' });
//     }
    
//     // Generate ZEGOCLOUD user ID if not exists
//     if (!user.zegoUserId) {
//       user.zegoUserId = `zego_${user._id}`;
//       await user.save();
//     }
    
//     // Generate token
//     const token = generateZegoToken(
//       ZEGOCLOUD_CONFIG.APP_ID,
//       user.zegoUserId,
//       ZEGOCLOUD_CONFIG.SERVER_SECRET,
//       ZEGOCLOUD_CONFIG.TOKEN_EXPIRY
//     );
    
//     console.log(`🎫 Generated ZEGOCLOUD token for user: ${user.username} (${user.zegoUserId})`);
    
//     res.json({
//       token: token,
//       userId: user.zegoUserId,
//       expiresIn: ZEGOCLOUD_CONFIG.TOKEN_EXPIRY,
//       user: {
//         id: user._id,
//         name: user.name,
//         username: user.username
//       }
//     });
    
//   } catch (error) {
//     console.error('❌ Token generation error:', error);
//     res.status(500).json({ error: 'Token generation failed' });
//   }
// });




//Updated ZEGOCLOUD Token Generation

// app.post('/api/getZegoToken', async (req, res) => {
//   try {
//     const { userId } = req.body;

//     if (!userId) {
//       return res.status(400).json({ error: 'userId is required' });
//     }

//     // Verify user exists in MongoDB
//     const user = await User.findById(userId);
//     if (!user) {
//       return res.status(404).json({ error: 'User not found' });
//     }

//     // Generate ZEGOCLOUD user ID if not exists
//     if (!user.zegoUserId) {
//       user.zegoUserId = `zego_${user._id}`;
//       await user.save();
//     }

//     // Generate Zego token
//     const token = generateZegoToken(
//       ZEGOCLOUD_CONFIG.APP_ID,
//       user.zegoUserId,
//       ZEGOCLOUD_CONFIG.SERVER_SECRET,
//       3600 // ✅ 1 hour validity (increase if needed)
//     );

//     console.log(`🎫 Generated ZEGOCLOUD token for user: ${user.username} (${user.zegoUserId})`);

//     return res.json({
//       token,
//       userId: user.zegoUserId,
//       expiresIn: 3600,
//       user: {
//         id: user._id,
//         name: user.name,
//         username: user.username
//       }
//     });

//   } catch (error) {
//     console.error('❌ Token generation error:', error);
//     return res.status(500).json({ error: 'Token generation failed' });
//   }
// });








// ✅ Fixed ZEGOCLOUD Token Route (copy this exact code)
app.post('/api/getZegoToken', async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId is required' });

    // Find user in DB
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Assign zegoUserId if missing
    if (!user.zegoUserId) {
      user.zegoUserId = `zego_${user._id}`;
      await user.save();
    }

    // ⚙️ 24 hours minus 30-second safety buffer
    const effectiveTimeInSeconds = (24 * 60 * 60) - 30;
    const payload = '';

    // ✅ Generate token using your helper function (NOT ZegoServerAssistant)
    const token = generateZegoToken(
      ZEGOCLOUD_CONFIG.APP_ID,
      user.zegoUserId,
      ZEGOCLOUD_CONFIG.SERVER_SECRET,
      effectiveTimeInSeconds
    );

    const expiresAt = Date.now() + (effectiveTimeInSeconds * 1000);

    console.log(`🎫 Zego token generated for ${user.username} (${user.zegoUserId}), expires in ${effectiveTimeInSeconds}s`);

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



//Refresh Token For Clint side {Optional}

app.post('/api/refreshZegoToken', async (req, res) => {
  try {
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



// ========================================
// 📁 FILE UPLOAD ENDPOINTS
// ========================================

// File Upload (Profile Pictures, Documents, etc.)
app.post('/api/upload', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { userId, type = 'general' } = req.body;
    const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
    const fileUrl = `${baseUrl}/uploads/${req.file.filename}`;

    // Log upload details
    console.log(`✅ File uploaded: ${req.file.filename} (${req.file.size} bytes) for user: ${req.user.userId}`);

    // If it's a profile picture, update user's profilePic field
    if (type === 'profile' && (userId === req.user.userId || req.user.role === 'admin')) {
      try {
        await User.findByIdAndUpdate(
          userId || req.user.userId,
          { 
            profilePic: fileUrl,
            updatedAt: new Date()
          }
        );
        console.log(`✅ Profile picture updated for user: ${userId || req.user.userId}`);
      } catch (updateError) {
        console.error('⚠️ Failed to update profile picture in database:', updateError);
        // Continue anyway - file was uploaded successfully
      }
    }

    res.json({
      message: 'File uploaded successfully',
      fileUrl: fileUrl,
      imageUrl: fileUrl, // For backward compatibility
      filename: req.file.filename,
      originalName: req.file.originalname,
      size: req.file.size,
      type: type
    });

  } catch (error) {
    console.error('❌ File upload error:', error);
    res.status(500).json({ error: 'File upload failed' });
  }
});


app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  res.json({
    message: 'File uploaded successfully',
    url: req.file.path
  });
});

// ========================================
// 📁 CLOUDINARY UPLOAD ROUTES
// ========================================

// Profile Image Upload to Cloudinary
// app.post('/api/cloudinary/profile', authenticateToken, cloudinaryUpload.single('file'), async (req, res) => {
//   try {
//     if (!req.file) {
//       return res.status(400).json({ 
//         success: false, 
//         error: 'No file uploaded' 
//       });
//     }

//     const { userId, type = 'profile' } = req.body;
    
//     // Update user's profile picture in database
//     if (userId === req.user.userId || req.user.role === 'admin') {
//       try {
//         await User.findByIdAndUpdate(
//           userId || req.user.userId,
//           { 
//             profilePic: req.file.path,
//             updatedAt: new Date()
//           }
//         );
//         console.log(`✅ Profile picture updated for user: ${userId || req.user.userId}`);
//       } catch (updateError) {
//         console.error('⚠️ Failed to update profile picture in database:', updateError);
//       }
//     }

//     return res.json({
//       success: true,
//       url: req.file.path,
//       publicId: req.file.filename,
//       resourceType: req.file.resource_type || 'image',
//     });
//   } catch (error) {
//     console.error('Profile upload error:', error);
//     res.status(500).json({ 
//       success: false, 
//       error: error.message 
//     });
//   }
// });



app.post('/api/cloudinary/profile', authenticateToken, cloudinaryUpload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  try {
    await User.findByIdAndUpdate(req.user.userId, {
      profilePic: req.file.path,
      updatedAt: new Date()
    });

    res.json({
      success: true,
      url: req.file.path,
      publicId: req.file.filename,
      resourceType: req.file.resource_type || 'image',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// Chat Media Upload to Cloudinary
// app.post('/api/cloudinary/chat', authenticateToken, cloudinaryUpload.single('file'), async (req, res) => {
//   try {
//     if (!req.file) {
//       return res.status(400).json({ 
//         success: false, 
//         error: 'No file uploaded' 
//       });
//     }

//     return res.json({
//       success: true,
//       url: req.file.path,
//       publicId: req.file.filename,
//       resourceType: req.file.resource_type || 'auto',
//       originalName: req.file.originalname,
//       size: req.file.size,
//     });
//   } catch (error) {
//     console.error('Chat upload error:', error);
//     res.status(500).json({ 
//       success: false, 
//       error: error.message 
//     });
//   }
// });



app.post('/api/cloudinary/chat', authenticateToken, cloudinaryUpload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  res.json({
    success: true,
    url: req.file.path,
    publicId: req.file.filename,
    resourceType: req.file.resource_type || 'auto',
    originalName: req.file.originalname,
    size: req.file.size,
  });
});






// Multiple Files Upload to Cloudinary
// app.post('/api/cloudinary/multiple', authenticateToken, cloudinaryUpload.array('files', 10), async (req, res) => {
//   try {
//     if (!req.files || req.files.length === 0) {
//       return res.status(400).json({ 
//         success: false, 
//         error: 'No files uploaded' 
//       });
//     }

//     const uploadedFiles = req.files.map(file => ({
//       url: file.path,
//       publicId: file.filename,
//       resourceType: file.resource_type || 'auto',
//       originalName: file.originalname,
//       size: file.size,
//     }));

//     return res.json({
//       success: true,
//       files: uploadedFiles,
//     });
//   } catch (error) {
//     console.error('Multiple upload error:', error);
//     res.status(500).json({ 
//       success: false, 
//       error: error.message 
//     });
//   }
// });



app.post('/api/cloudinary/multiple', authenticateToken, cloudinaryUpload.array('files', 10), (req, res) => {
  if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'No files uploaded' });

  const uploadedFiles = req.files.map(f => ({
    url: f.path,
    publicId: f.filename,
    resourceType: f.resource_type || 'auto',
    originalName: f.originalname,
    size: f.size
  }));

  res.json({ success: true, files: uploadedFiles });
});


// Get uploaded file info
app.get('/api/upload/:filename', (req, res) => {
  try {
    const { filename } = req.params;
    const filePath = path.join(__dirname, 'uploads', filename);
    
    if (fs.existsSync(filePath)) {
      const stats = fs.statSync(filePath);
      res.json({
        filename: filename,
        size: stats.size,
        uploadDate: stats.birthtime,
        url: `${req.protocol}://${req.get('host')}/uploads/${filename}`
      });
    } else {
      res.status(404).json({ error: 'File not found' });
    }
  } catch (error) {
    console.error('❌ File info error:', error);
    res.status(500).json({ error: 'Failed to get file info' });
  }
});

// Delete uploaded file (admin only)
app.delete('/api/upload/:filename', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { filename } = req.params;
    const filePath = path.join(__dirname, 'uploads', filename);
    
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      console.log(`✅ File deleted: ${filename}`);
      res.json({ message: 'File deleted successfully' });
    } else {
      res.status(404).json({ error: 'File not found' });
    }
  } catch (error) {
    console.error('❌ File deletion error:', error);
    res.status(500).json({ error: 'Failed to delete file' });
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
    }).populate('members', 'name username profilePic isOnline lastSeen');
    
    res.json(groups);
  } catch (error) {
    console.error('❌ Get groups error:', error);
    res.status(500).json({ error: 'Failed to fetch groups' });
  }
});

// Update Group
app.put('/api/groups/:groupId', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { name, description, profilePic } = req.body;
    
    // Check if user is admin of the group
    const group = await Group.findById(groupId);
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    
    if (!group.admins.includes(req.user.userId)) {
      return res.status(403).json({ error: 'Only group admins can update group details' });
    }
    
    // Update group
    const updatedGroup = await Group.findByIdAndUpdate(
      groupId,
      {
        name: name || group.name,
        description: description !== undefined ? description : group.description,
        profilePic: profilePic !== undefined ? profilePic : group.profilePic,
        updatedAt: new Date()
      },
      { new: true }
    ).populate('members', 'name username profilePic isOnline lastSeen')
     .populate('admins', 'name username profilePic');
    
    console.log(`✅ Group updated: ${updatedGroup.name}`);
    
    res.json({
      message: 'Group updated successfully',
      group: updatedGroup
    });
    
  } catch (error) {
    console.error('❌ Update group error:', error);
    res.status(500).json({ error: 'Failed to update group' });
  }
});

// Delete Group
app.delete('/api/groups/:groupId', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    
    // Check if user is admin of the group
    const group = await Group.findById(groupId);
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    
    if (!group.admins.includes(req.user.userId)) {
      return res.status(403).json({ error: 'Only group admins can delete the group' });
    }
    
    // Delete all messages in the group
    await Message.deleteMany({ group: groupId });
    
    // Delete the group
    await Group.findByIdAndDelete(groupId);
    
    console.log(`✅ Group deleted: ${group.name}`);
    
    res.json({
      message: 'Group deleted successfully'
    });
    
  } catch (error) {
    console.error('❌ Delete group error:', error);
    res.status(500).json({ error: 'Failed to delete group' });
  }
});

// Add Member to Group
app.post('/api/groups/:groupId/members', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { userId } = req.body;
    
    // Check if user is admin of the group
    const group = await Group.findById(groupId);
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    
    if (!group.admins.includes(req.user.userId)) {
      return res.status(403).json({ error: 'Only group admins can add members' });
    }
    
    // Check if user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check if user is already a member
    if (group.members.includes(userId)) {
      return res.status(400).json({ error: 'User is already a member' });
    }
    
    // Add member
    group.members.push(userId);
    group.updatedAt = new Date();
    await group.save();
    
    const updatedGroup = await Group.findById(groupId)
      .populate('members', 'name username profilePic isOnline lastSeen')
      .populate('admins', 'name username profilePic');
    
    console.log(`✅ Member added to group: ${user.username} -> ${group.name}`);
    
    res.json({
      message: 'Member added successfully',
      group: updatedGroup
    });
    
  } catch (error) {
    console.error('❌ Add member error:', error);
    res.status(500).json({ error: 'Failed to add member' });
  }
});

// Remove Member from Group
app.delete('/api/groups/:groupId/members/:userId', authenticateToken, async (req, res) => {
  try {
    const { groupId, userId } = req.params;
    
    // Check if user is admin of the group
    const group = await Group.findById(groupId);
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    
    if (!group.admins.includes(req.user.userId)) {
      return res.status(403).json({ error: 'Only group admins can remove members' });
    }
    
    // Don't allow removing the group creator
    if (group.createdBy.toString() === userId) {
      return res.status(400).json({ error: 'Cannot remove group creator' });
    }
    
    // Remove member
    group.members = group.members.filter(member => member.toString() !== userId);
    group.admins = group.admins.filter(admin => admin.toString() !== userId);
    group.updatedAt = new Date();
    await group.save();
    
    const updatedGroup = await Group.findById(groupId)
      .populate('members', 'name username profilePic isOnline lastSeen')
      .populate('admins', 'name username profilePic');
    
    console.log(`✅ Member removed from group: ${userId} -> ${group.name}`);
    
    res.json({
      message: 'Member removed successfully',
      group: updatedGroup
    });
    
  } catch (error) {
    console.error('❌ Remove member error:', error);
    res.status(500).json({ error: 'Failed to remove member' });
  }
});

// Admin: Create Admin User (One-time setup)
app.post('/api/admin/create-admin', async (req, res) => {
  try {
    // Check if any admin already exists
    const existingAdmin = await User.findOne({ role: 'admin' });
    if (existingAdmin) {
      return res.status(400).json({ error: 'Admin user already exists' });
    }
    
    const { name, username, email, password } = req.body;
    
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
    
    // Create admin user
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

// Admin: Create User (CRUD)
app.post('/api/admin/users', authenticateToken, async (req, res) => {
  try {
    // Check if current user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { name, username, email, password, role = 'user', profilePic } = req.body;
    
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

// Admin: Update User
app.put('/api/admin/users/:userId', authenticateToken, async (req, res) => {
  try {
    // Check if current user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { userId } = req.params;
    const updates = req.body;
    
    // Don't allow password updates through this endpoint
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

// Admin: Delete User
app.delete('/api/admin/users/:userId', authenticateToken, async (req, res) => {
  try {
    // Check if current user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { userId } = req.params;
    
    // Don't allow admin to delete themselves
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

// Update User Online Status
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

// Get User Online Status
app.get('/api/user/:userId/online-status', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const user = await User.findById(userId, 'isOnline lastSeen');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      isOnline: user.isOnline,
      lastSeen: user.lastSeen
    });
    
  } catch (error) {
    console.error('❌ Get online status error:', error);
    res.status(500).json({ error: 'Failed to get online status' });
  }
});

// Get All Users (for chat/contact list)
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find(
      { _id: { $ne: req.user.userId } }, // Exclude current user
      'name username email profilePic isOnline lastSeen role createdAt'
    ).sort({ name: 1 });
    
    res.json(users);
  } catch (error) {
    console.error('❌ Get users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// ========================================
// 💬 MESSAGING ENDPOINTS
// ========================================

// Get Chat Messages
app.get('/api/messages/:chatId', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { page = 1, limit = 50 } = req.query;
    
    const skip = (page - 1) * limit;
    
    // Get messages for direct chat or group
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
    
    res.json(messages.reverse()); // Return in chronological order
  } catch (error) {
    console.error('❌ Get messages error:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Send Message
app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { recipientId, groupId, content, messageType = 'text', zegoMessageId } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'Message content is required' });
    }
    
    if (!recipientId && !groupId) {
      return res.status(400).json({ error: 'Either recipientId or groupId is required' });
    }
    
    // Create message
    const message = new Message({
      sender: req.user.userId,
      recipient: recipientId || null,
      group: groupId || null,
      content,
      messageType,
      zegoMessageId,
      timestamp: new Date()
    });
    
    await message.save();
    
    // Populate sender info
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

// Get Chat List (Recent conversations)
app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    // Get recent messages for the user
    const recentMessages = await Message.aggregate([
      {
        $match: {
          $or: [
            { sender: req.user.userId },
            { recipient: req.user.userId },
            { 
              group: { $in: await Group.find({ members: req.user.userId }).distinct('_id') }
            }
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
                  { $eq: ["$sender", req.user.userId] },
                  "$recipient",
                  "$sender"
                ]
              }
            ]
          },
          lastMessage: { $first: "$$ROOT" }
        }
      },
      {
        $sort: { "lastMessage.timestamp": -1 }
      }
    ]);
    
    // Populate user and group details
    const chats = [];
    for (const item of recentMessages) {
      const lastMessage = item.lastMessage;
      let chatInfo = {};
      
      if (lastMessage.group) {
        // Group chat
        const group = await Group.findById(lastMessage.group)
          .populate('members', 'name username profilePic isOnline');
        if (group) {
          chatInfo = {
            id: group._id,
            name: group.name,
            type: 'group',
            profilePic: group.profilePic,
            lastMessage: lastMessage.content,
            timestamp: lastMessage.timestamp,
            members: group.members,
            unreadCount: 0 // TODO: Implement unread count
          };
        }
      } else {
        // Direct chat
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
            timestamp: lastMessage.timestamp,
            unreadCount: 0 // TODO: Implement unread count
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

// Initiate Call
app.post('/api/calls/initiate', authenticateToken, async (req, res) => {
  try {
    const { recipientId, callType = 'voice', groupId } = req.body;
    
    if (!recipientId && !groupId) {
      return res.status(400).json({ error: 'Either recipientId or groupId is required' });
    }
    
    // Generate unique call ID
    const callId = `call_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // Get caller info
    const caller = await User.findById(req.user.userId, 'name username profilePic');
    
    let callData = {
      callId,
      callerId: req.user.userId,
      callerName: caller.name,
      callerProfilePic: caller.profilePic,
      callType, // 'voice' or 'video'
      status: 'initiated',
      timestamp: new Date()
    };
    
    if (recipientId) {
      // Direct call
      const recipient = await User.findById(recipientId, 'name username profilePic isOnline');
      if (!recipient) {
        return res.status(404).json({ error: 'Recipient not found' });
      }
      
      callData.recipientId = recipientId;
      callData.recipientName = recipient.name;
      callData.recipientProfilePic = recipient.profilePic;
      callData.recipientOnline = recipient.isOnline;
    } else {
      // Group call
      const group = await Group.findById(groupId).populate('members', 'name username profilePic isOnline');
      if (!group) {
        return res.status(404).json({ error: 'Group not found' });
      }
      
      callData.groupId = groupId;
      callData.groupName = group.name;
      callData.members = group.members;
    }
    
    console.log(`✅ Call initiated: ${callId} by ${caller.name}`);
    
    res.json({
      message: 'Call initiated successfully',
      call: callData
    });
    
  } catch (error) {
    console.error('❌ Initiate call error:', error);
    res.status(500).json({ error: 'Failed to initiate call' });
  }
});

// End Call
app.post('/api/calls/:callId/end', authenticateToken, async (req, res) => {
  try {
    const { callId } = req.params;
    const { duration = 0, reason = 'ended' } = req.body;
    
    console.log(`✅ Call ended: ${callId} by ${req.user.userId}, duration: ${duration}s`);
    
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

// Get Call History
app.get('/api/calls/history', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    
    // For now, return empty array as call history is managed by ZEGOCLOUD
    // In a full implementation, you'd store call records in database
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

// Admin: Update User Role
app.put('/api/admin/users/:userId/role', authenticateToken, async (req, res) => {
  try {
    // Check if current user is admin
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

//Backup Logic implemented But for testing Purposes 
app.get('/backup/:userId', async (req, res) => {
  try {
    const chats = await Chat.find({ participants: req.params.userId }).populate('messages');
    const backupData = JSON.stringify(chats);
    const filePath = path.join(__dirname, 'backup.json');
    fs.writeFileSync(filePath, backupData);

    // Upload the JSON backup to Cloudinary
    const result = await cloudinary.uploader.upload(filePath, {
      resource_type: 'raw',
      folder: 'backups'
    });

    res.json({
      message: 'Backup created successfully',
      backupUrl: result.secure_url
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
