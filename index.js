// const express = require('express');
// const http = require('http');
// const socketIo = require('socket.io');
// const cors = require('cors');
// const bcrypt = require('bcryptjs');
// const jwt = require('jsonwebtoken');
// const multer = require('multer');
// const path = require('path');
// const fs = require('fs');
// require('dotenv').config();

// // Import database connection and models
// const { connectDB, testConnection } = require('./config/database');
// const User = require('./models/User');
// const Message = require('./models/Message');
// const Group = require('./models/Group');

// // Connect to MongoDB
// connectDB();

// // Create uploads directory if it doesn't exist
// const uploadsDir = path.join(__dirname, 'uploads');
// if (!fs.existsSync(uploadsDir)) {
//   fs.mkdirSync(uploadsDir, { recursive: true });
// }

// const app = express();
// const server = http.createServer(app);
// const io = socketIo(server, {
//   cors: {
//     origin: "*",
//     methods: ["GET", "POST"]
//   }
// });

// // Middleware
// app.use(cors());
// app.use(express.json({ limit: '50mb' }));
// app.use(express.urlencoded({ extended: true, limit: '50mb' }));
// app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// // File upload configuration
// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, 'uploads/');
//   },
//   filename: (req, file, cb) => {
//     const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
//     cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
//   }
// });

// const upload = multer({ 
//   storage: storage,
//   limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
//   fileFilter: (req, file, cb) => {
//     // Allow all file types for now
//     cb(null, true);
//   }
// });

// const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// // Authentication middleware
// const authenticateToken = (req, res, next) => {
//   const authHeader = req.headers['authorization'];
//   const token = authHeader && authHeader.split(' ')[1];

//   if (!token) {
//     return res.sendStatus(401);
//   }

//   jwt.verify(token, JWT_SECRET, (err, user) => {
//     if (err) return res.sendStatus(403);
//     req.user = user;
//     next();
//   });
// };

// // Routes

// // Health check endpoint
// app.get('/api/health', async (req, res) => {
//   try {
//     // Test database connection
//     const dbStatus = await User.countDocuments();
//     res.json({
//       status: 'OK',
//       message: 'Server is running',
//       database: 'Connected',
//       userCount: dbStatus,
//       timestamp: new Date().toISOString()
//     });
//   } catch (error) {
//     res.status(500).json({
//       status: 'ERROR',
//       message: 'Database connection failed',
//       error: error.message,
//       timestamp: new Date().toISOString()
//     });
//   }
// });

// // Admin middleware
// const requireAdmin = async (req, res, next) => {
//   try {
//     const user = await User.findById(req.user.userId);
//     if (!user || user.role !== 'admin') {
//       return res.status(403).json({ error: 'Admin access required' });
//     }
//     next();
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// };

// // Admin: Create new user
// app.post('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
//   try {
//     const { name, username, email, password, role = 'user' } = req.body;

//     // Check if username already exists
//     const existingUser = await User.findOne({ username });
//     if (existingUser) {
//       return res.status(400).json({ error: 'Username already exists' });
//     }

//     // Hash password
//     const hashedPassword = await bcrypt.hash(password, 10);

//     // Create user
//     const user = new User({
//       name,
//       username,
//       email,
//       password: hashedPassword,
//       role
//     });

//     await user.save();

//     res.status(201).json({
//       user: {
//         id: user._id,
//         name: user.name,
//         username: user.username,
//         email: user.email,
//         role: user.role,
//         profilePic: user.profilePic,
//         isOnline: user.isOnline,
//         lastSeen: user.lastSeen,
//         createdAt: user.createdAt
//       }
//     });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Login
// app.post('/api/login', async (req, res) => {
//   try {
//     const { username, password } = req.body;

//     // Find user by username
//     const user = await User.findOne({ username });
//     if (!user) {
//       return res.status(400).json({ error: 'Invalid username or password' });
//     }

//     // Check password
//     const isValidPassword = await bcrypt.compare(password, user.password);
//     if (!isValidPassword) {
//       return res.status(400).json({ error: 'Invalid username or password' });
//     }

//     // Update user online status
//     user.isOnline = true;
//     user.lastSeen = new Date();
//     await user.save();

//     // Generate token
//     const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET);

//     res.json({
//       token,
//       user: {
//         id: user._id,
//         name: user.name,
//         username: user.username,
//         email: user.email,
//         role: user.role,
//         profilePic: user.profilePic,
//         isOnline: user.isOnline
//       }
//     });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Get all users (for admin)
// app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
//   try {
//     const users = await User.find({}, '-password');
//     res.json(users);
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Admin: Update user
// app.put('/api/admin/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
//   try {
//     const { userId } = req.params;
//     const { name, username, email, role, profilePic } = req.body;

//     // Check if username already exists (excluding current user)
//     if (username) {
//       const existingUser = await User.findOne({ username, _id: { $ne: userId } });
//       if (existingUser) {
//         return res.status(400).json({ error: 'Username already exists' });
//       }
//     }

//     const user = await User.findByIdAndUpdate(
//       userId,
//       { name, username, email, role, profilePic },
//       { new: true, select: '-password' }
//     );

//     if (!user) {
//       return res.status(404).json({ error: 'User not found' });
//     }

//     res.json(user);
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Admin: Delete user
// app.delete('/api/admin/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
//   try {
//     const { userId } = req.params;
    
//     // Prevent admin from deleting themselves
//     if (userId === req.user.userId) {
//       return res.status(400).json({ error: 'Cannot delete your own account' });
//     }

//     const user = await User.findByIdAndDelete(userId);
//     if (!user) {
//       return res.status(404).json({ error: 'User not found' });
//     }

//     res.json({ message: 'User deleted successfully' });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Admin: Reset user password
// app.put('/api/admin/users/:userId/password', authenticateToken, requireAdmin, async (req, res) => {
//   try {
//     const { userId } = req.params;
//     const { password } = req.body;

//     if (!password || password.length < 6) {
//       return res.status(400).json({ error: 'Password must be at least 6 characters' });
//     }

//     const hashedPassword = await bcrypt.hash(password, 10);
    
//     const user = await User.findByIdAndUpdate(
//       userId,
//       { password: hashedPassword },
//       { new: true, select: '-password' }
//     );

//     if (!user) {
//       return res.status(404).json({ error: 'User not found' });
//     }

//     res.json({ message: 'Password updated successfully' });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Get user profile
// app.get('/api/profile', authenticateToken, async (req, res) => {
//   try {
//     const user = await User.findById(req.user.userId, '-password');
//     res.json(user);
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Update user profile
// app.put('/api/profile', authenticateToken, async (req, res) => {
//   try {
//     const { name, email, profilePic } = req.body;
//     const user = await User.findByIdAndUpdate(
//       req.user.userId,
//       { name, email, profilePic },
//       { new: true, select: '-password' }
//     );
//     res.json(user);
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Logout
// app.post('/api/logout', authenticateToken, async (req, res) => {
//   try {
//     await User.findByIdAndUpdate(req.user.userId, { 
//       isOnline: false, 
//       lastSeen: new Date() 
//     });
//     res.json({ message: 'Logged out successfully' });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // File upload endpoint
// app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
//   try {
//     if (!req.file) {
//       return res.status(400).json({ error: 'No file uploaded' });
//     }

//     const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    
//     res.json({
//       message: 'File uploaded successfully',
//       filename: req.file.filename,
//       originalName: req.file.originalname,
//       size: req.file.size,
//       url: fileUrl
//     });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Get messages for a chat
// app.get('/api/messages/:chatId', authenticateToken, async (req, res) => {
//   try {
//     const { chatId } = req.params;
//     const { page = 1, limit = 50 } = req.query;
    
//     const messages = await Message.find({ chatId })
//       .populate('senderId', 'name username profilePic')
//       .sort({ createdAt: -1 })
//       .limit(limit * 1)
//       .skip((page - 1) * limit);
    
//     res.json(messages.reverse());
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Send message
// app.post('/api/messages', authenticateToken, async (req, res) => {
//   try {
//     const { chatId, text, type = 'text', filePath, fileName } = req.body;
    
//     const message = new Message({
//       chatId,
//       senderId: req.user.userId,
//       text,
//       type,
//       filePath,
//       fileName,
//       timestamp: new Date()
//     });
    
//     await message.save();
//     await message.populate('senderId', 'name username profilePic');
    
//     // Emit to all connected clients
//     io.emit('new_message', message);
    
//     res.status(201).json(message);
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Create group
// app.post('/api/groups', authenticateToken, async (req, res) => {
//   try {
//     const { name, description, members = [] } = req.body;
    
//     const group = new Group({
//       name,
//       description,
//       createdBy: req.user.userId,
//       members: [req.user.userId, ...members],
//       admins: [req.user.userId]
//     });
    
//     await group.save();
//     await group.populate('members', 'name username profilePic');
//     await group.populate('createdBy', 'name username');
    
//     res.status(201).json(group);
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Get user's groups
// app.get('/api/groups', authenticateToken, async (req, res) => {
//   try {
//     const groups = await Group.find({ members: req.user.userId })
//       .populate('members', 'name username profilePic isOnline')
//       .populate('createdBy', 'name username')
//       .sort({ updatedAt: -1 });
    
//     res.json(groups);
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Get online users
// app.get('/api/users/online', authenticateToken, async (req, res) => {
//   try {
//     const onlineUsers = await User.find({ 
//       isOnline: true, 
//       _id: { $ne: req.user.userId } 
//     }, 'name username profilePic isOnline lastSeen');
    
//     res.json(onlineUsers);
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Search users
// app.get('/api/users/search', authenticateToken, async (req, res) => {
//   try {
//     const { q } = req.query;
//     if (!q) {
//       return res.json([]);
//     }
    
//     const users = await User.find({
//       $and: [
//         { _id: { $ne: req.user.userId } },
//         {
//           $or: [
//             { name: { $regex: q, $options: 'i' } },
//             { username: { $regex: q, $options: 'i' } }
//           ]
//         }
//       ]
//     }, 'name username profilePic isOnline').limit(20);
    
//     res.json(users);
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Socket.IO for real-time messaging
// const connectedUsers = new Map();

// io.on('connection', (socket) => {
//   console.log('User connected:', socket.id);

//   socket.on('user_connected', async (data) => {
//     const { userId, username } = data;
//     connectedUsers.set(socket.id, { userId, username });
    
//     // Update user online status
//     await User.findByIdAndUpdate(userId, { isOnline: true });
    
//     // Broadcast user online status
//     socket.broadcast.emit('user_online', { userId, username });
//   });

//   socket.on('send_message', (data) => {
//     // Broadcast message to all connected clients
//     io.emit('receive_message', data);
//   });

//   socket.on('join_group', (groupId) => {
//     socket.join(groupId);
//   });

//   socket.on('send_group_message', (data) => {
//     socket.to(data.groupId).emit('receive_group_message', data);
//   });

//   socket.on('disconnect', async () => {
//     const user = connectedUsers.get(socket.id);
//     if (user) {
//       // Update user offline status
//       await User.findByIdAndUpdate(user.userId, { 
//         isOnline: false, 
//         lastSeen: new Date() 
//       });
      
//       // Broadcast user offline status
//       socket.broadcast.emit('user_offline', { userId: user.userId });
//       connectedUsers.delete(socket.id);
//     }
//     console.log('User disconnected:', socket.id);
//   });
// });

// const PORT = process.env.PORT || 3000;
// server.listen(PORT, () => {
//   console.log(`Server running on port ${PORT}`);
// });


//New backennd Code

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

// Import database connection and models
const { connectDB, testConnection } = require('./config/database');
const User = require('./models/User');
const Message = require('./models/Message');
const Group = require('./models/Group');

// Connect to MongoDB
connectDB();

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
  fileFilter: (req, file, cb) => {
    // Allow all file types for now
    cb(null, true);
  }
});

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Routes

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    // Test database connection
    const dbStatus = await User.countDocuments();
    res.json({
      status: 'OK',
      message: 'Server is running',
      database: 'Connected',
      userCount: dbStatus,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      status: 'ERROR',
      message: 'Database connection failed',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Admin middleware
const requireAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Admin: Create new user
app.post('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, username, email, password, role = 'user' } = req.body;

    // Check if username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      name,
      username,
      email,
      password: hashedPassword,
      role
    });

    await user.save();

    res.status(201).json({
      user: {
        id: user._id,
        name: user.name,
        username: user.username,
        email: user.email,
        role: user.role,
        profilePic: user.profilePic,
        isOnline: user.isOnline,
        lastSeen: user.lastSeen,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find user by username
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    // Update user online status
    user.isOnline = true;
    user.lastSeen = new Date();
    await user.save();

    // Generate token
    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET);

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        username: user.username,
        email: user.email,
        role: user.role,
        profilePic: user.profilePic,
        isOnline: user.isOnline
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all users (for admin)
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await User.find({}, '-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Update user
app.put('/api/admin/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { name, username, email, role, profilePic } = req.body;

    // Check if username already exists (excluding current user)
    if (username) {
      const existingUser = await User.findOne({ username, _id: { $ne: userId } });
      if (existingUser) {
        return res.status(400).json({ error: 'Username already exists' });
      }
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { name, username, email, role, profilePic },
      { new: true, select: '-password' }
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Delete user
app.delete('/api/admin/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Prevent admin from deleting themselves
    if (userId === req.user.userId) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }

    const user = await User.findByIdAndDelete(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Reset user password
app.put('/api/admin/users/:userId/password', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { password } = req.body;

    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = await User.findByIdAndUpdate(
      userId,
      { password: hashedPassword },
      { new: true, select: '-password' }
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId, '-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update user profile
app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { name, email, profilePic } = req.body;
    const user = await User.findByIdAndUpdate(
      req.user.userId,
      { name, email, profilePic },
      { new: true, select: '-password' }
    );
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Logout
app.post('/api/logout', authenticateToken, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.userId, { 
      isOnline: false, 
      lastSeen: new Date() 
    });
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// File upload endpoint
app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    
    res.json({
      message: 'File uploaded successfully',
      filename: req.file.filename,
      originalName: req.file.originalname,
      size: req.file.size,
      url: fileUrl
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get messages for a chat
app.get('/api/messages/:chatId', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { page = 1, limit = 50 } = req.query;
    
    const messages = await Message.find({ chatId })
      .populate('senderId', 'name username profilePic')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    res.json(messages.reverse());
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Send message
app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { chatId, text, type = 'text', metadata, groupId } = req.body;
    
    const message = new Message({
      chatId,
      senderId: req.user.userId,
      text,
      type,
      metadata: metadata || {},
      groupId,
      timestamp: new Date()
    });
    
    await message.save();
    await message.populate('senderId', 'name username profilePic');
    
    // Emit to appropriate room
    if (groupId) {
      io.to(groupId).emit('new_message', message);
    } else {
      io.emit('new_message', message);
    }
    
    res.status(201).json(message);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get chat messages with pagination
app.get('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { page = 1, limit = 50 } = req.query;
    
    const messages = await Message.find({ chatId })
      .populate('senderId', 'name username profilePic')
      .sort({ timestamp: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    res.json(messages.reverse());
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get group messages
app.get('/api/groups/:groupId/messages', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { page = 1, limit = 50 } = req.query;
    
    // Verify user is member of the group
    const group = await Group.findOne({ 
      _id: groupId, 
      members: req.user.userId 
    });
    
    if (!group) {
      return res.status(403).json({ error: 'Access denied to group messages' });
    }
    
    const messages = await Message.find({ groupId })
      .populate('senderId', 'name username profilePic')
      .sort({ timestamp: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    res.json(messages.reverse());
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete message
app.delete('/api/messages/:messageId', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    
    const message = await Message.findOne({
      _id: messageId,
      senderId: req.user.userId
    });
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found or access denied' });
    }
    
    await Message.findByIdAndDelete(messageId);
    
    // Notify clients about message deletion
    if (message.groupId) {
      io.to(message.groupId).emit('message_deleted', { messageId, chatId: message.chatId });
    } else {
      io.emit('message_deleted', { messageId, chatId: message.chatId });
    }
    
    res.json({ message: 'Message deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Clear chat messages
app.delete('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    
    await Message.deleteMany({ 
      chatId,
      senderId: req.user.userId 
    });
    
    res.json({ message: 'Chat cleared successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user's chats
app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    // Get recent messages for each chat the user is involved in
    const recentMessages = await Message.aggregate([
      {
        $match: {
          $or: [
            { senderId: req.user.userId },
            { recipientId: req.user.userId }
          ]
        }
      },
      {
        $sort: { timestamp: -1 }
      },
      {
        $group: {
          _id: '$chatId',
          lastMessage: { $first: '$$ROOT' },
          unreadCount: {
            $sum: {
              $cond: [
                {
                  $and: [
                    { $ne: ['$senderId', req.user.userId] },
                    { $eq: ['$isRead', false] }
                  ]
                },
                1,
                0
              ]
            }
          }
        }
      }
    ]);
    
    // Populate sender information
    await Message.populate(recentMessages, {
      path: 'lastMessage.senderId',
      select: 'name username profilePic'
    });
    
    res.json(recentMessages);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mark messages as read
app.put('/api/chats/:chatId/read', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    
    await Message.updateMany(
      { 
        chatId,
        senderId: { $ne: req.user.userId },
        isRead: false
      },
      { isRead: true }
    );
    
    res.json({ message: 'Messages marked as read' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create group
app.post('/api/groups', authenticateToken, async (req, res) => {
  try {
    const { name, description, members = [] } = req.body;
    
    const group = new Group({
      name,
      description,
      createdBy: req.user.userId,
      members: [req.user.userId, ...members],
      admins: [req.user.userId]
    });
    
    await group.save();
    await group.populate('members', 'name username profilePic');
    await group.populate('createdBy', 'name username');
    
    res.status(201).json(group);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user's groups
app.get('/api/groups', authenticateToken, async (req, res) => {
  try {
    const groups = await Group.find({ members: req.user.userId })
      .populate('members', 'name username profilePic isOnline')
      .populate('createdBy', 'name username')
      .sort({ updatedAt: -1 });
    
    res.json(groups);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get group details
app.get('/api/groups/:groupId', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const group = await Group.findOne({ 
      _id: groupId, 
      members: req.user.userId 
    })
    .populate('members', 'name username profilePic isOnline lastSeen')
    .populate('createdBy', 'name username')
    .populate('admins', 'name username');
    
    if (!group) {
      return res.status(404).json({ error: 'Group not found or access denied' });
    }
    
    res.json(group);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update group
app.put('/api/groups/:groupId', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { name, description, profilePic, members } = req.body;
    
    // Check if user is admin of the group
    const group = await Group.findOne({ 
      _id: groupId, 
      admins: req.user.userId 
    });
    
    if (!group) {
      return res.status(403).json({ error: 'Only group admins can update group details' });
    }
    
    const updates = {};
    if (name) updates.name = name;
    if (description !== undefined) updates.description = description;
    if (profilePic !== undefined) updates.profilePic = profilePic;
    if (members) updates.members = members;
    
    const updatedGroup = await Group.findByIdAndUpdate(
      groupId,
      updates,
      { new: true }
    )
    .populate('members', 'name username profilePic isOnline')
    .populate('createdBy', 'name username');
    
    // Notify group members about update
    io.to(groupId).emit('group_updated', updatedGroup);
    
    res.json(updatedGroup);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete group
app.delete('/api/groups/:groupId', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    
    // Check if user is the creator or admin
    const group = await Group.findOne({ 
      _id: groupId, 
      $or: [
        { createdBy: req.user.userId },
        { admins: req.user.userId }
      ]
    });
    
    if (!group) {
      return res.status(403).json({ error: 'Only group creator or admin can delete the group' });
    }
    
    await Group.findByIdAndDelete(groupId);
    
    // Notify all group members
    io.to(groupId).emit('group_deleted', { groupId });
    
    res.json({ message: 'Group deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add member to group
app.post('/api/groups/:groupId/members', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { userId } = req.body;
    
    // Check if user is admin of the group
    const group = await Group.findOne({ 
      _id: groupId, 
      admins: req.user.userId 
    });
    
    if (!group) {
      return res.status(403).json({ error: 'Only group admins can add members' });
    }
    
    // Check if user is already a member
    if (group.members.includes(userId)) {
      return res.status(400).json({ error: 'User is already a member' });
    }
    
    // Add member
    group.members.push(userId);
    await group.save();
    
    const updatedGroup = await Group.findById(groupId)
      .populate('members', 'name username profilePic isOnline');
    
    // Notify group members
    io.to(groupId).emit('member_added', { groupId, userId, group: updatedGroup });
    
    res.json(updatedGroup);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Remove member from group
app.delete('/api/groups/:groupId/members/:userId', authenticateToken, async (req, res) => {
  try {
    const { groupId, userId } = req.params;
    
    // Check if user is admin of the group or removing themselves
    const group = await Group.findById(groupId);
    
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    
    const isAdmin = group.admins.includes(req.user.userId);
    const isSelf = userId === req.user.userId;
    
    if (!isAdmin && !isSelf) {
      return res.status(403).json({ error: 'Only group admins can remove members' });
    }
    
    // Remove member
    group.members = group.members.filter(member => member.toString() !== userId);
    
    // If removing an admin, remove from admins too
    group.admins = group.admins.filter(admin => admin.toString() !== userId);
    
    await group.save();
    
    const updatedGroup = await Group.findById(groupId)
      .populate('members', 'name username profilePic isOnline');
    
    // Notify group members
    io.to(groupId).emit('member_removed', { groupId, userId, group: updatedGroup });
    
    res.json(updatedGroup);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get online users
app.get('/api/users/online', authenticateToken, async (req, res) => {
  try {
    const onlineUsers = await User.find({ 
      isOnline: true, 
      _id: { $ne: req.user.userId } 
    }, 'name username profilePic isOnline lastSeen');
    
    res.json(onlineUsers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Search users
app.get('/api/users/search', authenticateToken, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q) {
      return res.json([]);
    }
    
    const users = await User.find({
      $and: [
        { _id: { $ne: req.user.userId } },
        {
          $or: [
            { name: { $regex: q, $options: 'i' } },
            { username: { $regex: q, $options: 'i' } }
          ]
        }
      ]
    }, 'name username profilePic isOnline').limit(20);
    
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Socket.IO for real-time messaging and WebRTC signaling
const connectedUsers = new Map();
const activeRooms = new Map();
const activeCalls = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // User connection
  socket.on('user_connected', async (data) => {
    const { userId, username } = data;
    connectedUsers.set(socket.id, { userId, username, socketId: socket.id });
    
    // Update user online status
    await User.findByIdAndUpdate(userId, { isOnline: true });
    
    // Broadcast user online status
    socket.broadcast.emit('user_online', { userId, username });
    
    console.log(`User ${username} (${userId}) connected`);
  });

  // Real-time messaging
  socket.on('send_message', async (data) => {
    try {
      const { chatId, message, userId, groupId } = data;
      
      // Save message to database
      const newMessage = new Message({
        chatId,
        senderId: userId,
        text: message,
        type: 'text',
        timestamp: new Date()
      });
      
      await newMessage.save();
      await newMessage.populate('senderId', 'name username profilePic');
      
      // Broadcast to appropriate room
      if (groupId) {
        socket.to(groupId).emit('new_message', newMessage);
      } else {
        io.emit('new_message', newMessage);
      }
    } catch (error) {
      console.error('Error sending message:', error);
    }
  });

  // Group management
  socket.on('join_group', (groupId) => {
    socket.join(groupId);
    console.log(`Socket ${socket.id} joined group ${groupId}`);
  });

  socket.on('leave_group', (groupId) => {
    socket.leave(groupId);
    console.log(`Socket ${socket.id} left group ${groupId}`);
  });

  socket.on('group_created', (data) => {
    // Notify all members about new group
    data.members.forEach(memberId => {
      const memberSocket = Array.from(connectedUsers.entries())
        .find(([_, user]) => user.userId === memberId);
      if (memberSocket) {
        io.to(memberSocket[0]).emit('group_created', data);
      }
    });
  });

  socket.on('group_updated', (data) => {
    socket.to(data.groupId).emit('group_updated', data);
  });

  socket.on('member_added', (data) => {
    socket.to(data.groupId).emit('member_added', data);
  });

  socket.on('member_removed', (data) => {
    socket.to(data.groupId).emit('member_removed', data);
  });

  // Typing indicators
  socket.on('typing', (data) => {
    const { chatId, userId, isTyping } = data;
    socket.broadcast.emit('typing', { chatId, userId, isTyping });
  });

  // File sharing
  socket.on('file_shared', (data) => {
    const { chatId, fileInfo, userId } = data;
    socket.broadcast.emit('file_shared', { chatId, fileInfo, userId });
  });

  // Voice messages
  socket.on('voice_message', (data) => {
    const { chatId, voiceInfo, userId } = data;
    socket.broadcast.emit('voice_message', { chatId, voiceInfo, userId });
  });

  // WebRTC Signaling for Audio Calls
  socket.on('webrtc-signal', (data) => {
    const signalData = data.data;
    
    switch (signalData.type) {
      case 'call-offer':
        // Find target user and send offer
        const targetUser = Array.from(connectedUsers.entries())
          .find(([_, user]) => user.userId === signalData.to);
        
        if (targetUser) {
          activeCalls.set(signalData.callId, {
            caller: signalData.from,
            callee: signalData.to,
            status: 'calling'
          });
          
          io.to(targetUser[0]).emit('webrtc-signal', {
            type: 'call-offer',
            data: {
              ...signalData,
              fromName: connectedUsers.get(socket.id)?.username || 'Unknown'
            }
          });
        }
        break;

      case 'call-answer':
        // Forward answer to caller
        const callerUser = Array.from(connectedUsers.entries())
          .find(([_, user]) => user.userId === signalData.to);
        
        if (callerUser) {
          activeCalls.set(signalData.callId, {
            ...activeCalls.get(signalData.callId),
            status: 'connected'
          });
          
          io.to(callerUser[0]).emit('webrtc-signal', {
            type: 'call-answer',
            data: signalData
          });
        }
        break;

      case 'ice-candidate':
        // Forward ICE candidate to the other peer
        const otherUser = Array.from(connectedUsers.entries())
          .find(([_, user]) => user.userId === signalData.to);
        
        if (otherUser) {
          io.to(otherUser[0]).emit('webrtc-signal', {
            type: 'ice-candidate',
            data: signalData
          });
        }
        break;

      case 'call-end':
      case 'call-reject':
        // Forward call end/reject to the other peer
        const peerUser = Array.from(connectedUsers.entries())
          .find(([_, user]) => user.userId === signalData.to);
        
        if (peerUser) {
          io.to(peerUser[0]).emit('webrtc-signal', {
            type: signalData.type,
            data: signalData
          });
        }
        
        // Clean up call data
        activeCalls.delete(signalData.callId);
        break;
    }
  });

  // User status updates
  socket.on('user_status', async (data) => {
    const { userId, status } = data;
    try {
      await User.findByIdAndUpdate(userId, { status });
      socket.broadcast.emit('user_status_updated', { userId, status });
    } catch (error) {
      console.error('Error updating user status:', error);
    }
  });

  // Disconnect handling
  socket.on('disconnect', async () => {
    const user = connectedUsers.get(socket.id);
    if (user) {
      try {
        // Update user offline status
        await User.findByIdAndUpdate(user.userId, { 
          isOnline: false, 
          lastSeen: new Date() 
        });
        
        // Broadcast user offline status
        socket.broadcast.emit('user_offline', { userId: user.userId });
        
        // Clean up any active calls
        for (const [callId, call] of activeCalls.entries()) {
          if (call.caller === user.userId || call.callee === user.userId) {
            // Notify the other party that call ended
            const otherUserId = call.caller === user.userId ? call.callee : call.caller;
            const otherUser = Array.from(connectedUsers.entries())
              .find(([_, u]) => u.userId === otherUserId);
            
            if (otherUser) {
              io.to(otherUser[0]).emit('webrtc-signal', {
                type: 'call-end',
                data: { callId, reason: 'user_disconnected' }
              });
            }
            
            activeCalls.delete(callId);
          }
        }
        
        connectedUsers.delete(socket.id);
        console.log(`User ${user.username} (${user.userId}) disconnected`);
      } catch (error) {
        console.error('Error handling disconnect:', error);
      }
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});



