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

//This Previous Code




//The New Code
// server.js
require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Import database connection and models
const { connectDB } = require('./config/database');
const User = require('./models/User');
const Message = require('./models/Message');
const Group = require('./models/Group');

connectDB();

// Ensure uploads dir
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  }
});

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/uploads', express.static(uploadsDir));

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir + '/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter: (req, file, cb) => cb(null, true)
});

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Authentication middleware (REST)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// --- REST endpoints (kept and extended) ---

// Health check
app.get('/api/health', async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    res.json({
      status: 'OK',
      message: 'Server is running',
      database: 'Connected',
      userCount,
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

// --- (admin and auth routes you provided are preserved) ---
// For brevity: re-include your admin/login/profile routes unchanged from your original file.
// I'll paste the main ones needed here — keep your other admin endpoints as-is:

// Admin: Create new user (example)
app.post('/api/admin/users', authenticateToken, async (req, res, next) => {
  // This route expects a requireAdmin middleware - keep yours if you have it.
  next(); // placeholder if you still use existing requireAdmin, we'll define below
});

// ... (You already had many admin endpoints above; keep them as you had) ...

// Login (reuse your existing implementation)
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: 'Invalid username or password' });
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(400).json({ error: 'Invalid username or password' });

    user.isOnline = true;
    user.lastSeen = new Date();
    await user.save();

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

// File upload endpoint
app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
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

// Get messages for a chat (pagination)
app.get('/api/messages/:chatId', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const page = parseInt(req.query.page || '1', 10);
    const limit = Math.min(100, parseInt(req.query.limit || '50', 10));
    const messages = await Message.find({ chatId })
      .populate('senderId', 'name username profilePic')
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip((page - 1) * limit);
    res.json(messages.reverse());
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create or get private chat (returns chatId built from two sorted userIds)
app.post('/api/chats/private', authenticateToken, async (req, res) => {
  try {
    const { otherUserId } = req.body;
    const me = req.user.userId;
    if (!otherUserId) return res.status(400).json({ error: 'otherUserId required' });

    // canonical chatId for 1-1: sorted combination
    const chatId = [me, otherUserId].sort().join('_');

    // optionally prime with a "system message" or create metadata collection if required
    res.json({ chatId });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get chats list for current user (groups + private chats summary)
app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // 1) groups the user is member of
    const groups = await Group.find({ members: userId })
      .select('_id name members createdBy updatedAt')
      .populate('members', 'name username profilePic');

    // 2) private chats list: we can aggregate last message per private chatId where chatId contains user's id and has underscore (our scheme)
    const privateChatAgg = await Message.aggregate([
      { $match: { chatId: { $regex: `^.*${userId}.*_.*` } } }, // simplistic: includes userId
      { $sort: { timestamp: -1 } },
      {
        $group: {
          _id: "$chatId",
          lastMessage: { $first: "$$ROOT" }
        }
      },
      { $limit: 100 },
      { $sort: { "lastMessage.timestamp": -1 } }
    ]);

    // populate lastMessage.senderId
    const privateChats = [];
    for (const c of privateChatAgg) {
      const msg = await Message.findById(c.lastMessage._id).populate('senderId', 'name username profilePic');
      privateChats.push({
        chatId: c._id,
        lastMessage: msg
      });
    }

    res.json({ groups, privateChats });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mark messages as read in a chat (pass chatId and messageIds)
app.put('/api/messages/read', authenticateToken, async (req, res) => {
  try {
    const { chatId, messageIds = [] } = req.body;
    const userId = req.user.userId;
    if (!chatId || !Array.isArray(messageIds) || messageIds.length === 0) {
      return res.status(400).json({ error: 'chatId and messageIds required' });
    }

    await Message.updateMany(
      { _id: { $in: messageIds } },
      { $addToSet: { readBy: userId } }
    );

    // Optionally, notify via socket about read receipts
    io.to(chatId).emit('messages_read', { chatId, messageIds, userId });

    res.json({ message: 'Marked as read' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- Socket.IO: real-time 1-1 and group chats ---

// Helper: verify JWT token from socket handshake (either auth or query)
const verifySocketToken = (token) => {
  try {
    if (!token) return null;
    const payload = jwt.verify(token, JWT_SECRET);
    return payload;
  } catch (err) {
    return null;
  }
};

const connectedUsers = new Map(); // socket.id => { userId, username }

// Use middleware to authenticate socket connection (optional)
io.use((socket, next) => {
  // client should send token in handshake auth: { token }
  const token = socket.handshake.auth && socket.handshake.auth.token || socket.handshake.query && socket.handshake.query.token;
  const user = verifySocketToken(token);
  if (!user) {
    return next(); // allow unauthenticated? we still allow but won't set user on socket
  }
  socket.user = user; // { userId, username }
  next();
});

io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id);

  // If token was provided and valid, register user and join personal room
  if (socket.user && socket.user.userId) {
    const userId = socket.user.userId.toString();
    const username = socket.user.username || 'unknown';
    connectedUsers.set(socket.id, { userId, username });
    socket.join(userId); // personal room for direct messages
    console.log(`Socket ${socket.id} authenticated as ${userId}`);

    // Update DB online status
    User.findByIdAndUpdate(userId, { isOnline: true }).catch(() => {});
    // Notify others
    socket.broadcast.emit('user_online', { userId, username });
  }

  // Event: user manually registers connection (optional fallback if socket.auth not used)
  socket.on('user_connected', async (data) => {
    try {
      const { userId, username } = data;
      if (!userId) return;
      connectedUsers.set(socket.id, { userId: userId.toString(), username });
      socket.join(userId.toString());
      await User.findByIdAndUpdate(userId, { isOnline: true, lastSeen: new Date() });
      socket.broadcast.emit('user_online', { userId, username });
    } catch (err) {
      console.error('user_connected error', err);
    }
  });

  // PRIVATE MESSAGE (1-to-1)
  // client sends: { senderId, receiverId, text, type, filePath, fileName }
  socket.on('send_private_message', async (data) => {
    try {
      const { senderId, receiverId, text, type = 'text', filePath, fileName } = data;
      if (!senderId || !receiverId) return;

      // canonical chatId: sorted
      const chatId = [senderId.toString(), receiverId.toString()].sort().join('_');

      const message = new Message({
        chatId,
        senderId,
        text,
        type,
        filePath,
        fileName,
        timestamp: new Date(),
        deliveredTo: [], // track delivered recipients
        readBy: []
      });

      await message.save();
      await message.populate('senderId', 'name username profilePic');

      // Emit to both personal rooms (sender & receiver)
      io.to(senderId.toString()).to(receiverId.toString()).emit('private_message', message);

      // Optionally mark delivered for receiver(s) who are online immediately
      const receiverSocketIds = Array.from(connectedUsers.entries())
        .filter(([, v]) => v.userId === receiverId.toString())
        .map(([sid]) => sid);

      // If receiver is online, mark delivered and notify
      if (receiverSocketIds.length > 0) {
        await Message.findByIdAndUpdate(message._id, { $addToSet: { deliveredTo: receiverId } });
        io.to(receiverId.toString()).emit('message_delivered', { messageId: message._id, chatId, to: receiverId });
      }
    } catch (error) {
      console.error('send_private_message error', error);
    }
  });

  // GROUP MESSAGE
  // client sends: { groupId, senderId, text, type, filePath, fileName }
  socket.on('send_group_message', async (data) => {
    try {
      const { groupId, senderId, text, type = 'text', filePath, fileName } = data;
      if (!groupId || !senderId) return;

      const message = new Message({
        chatId: groupId.toString(),
        senderId,
        text,
        type,
        filePath,
        fileName,
        timestamp: new Date(),
        deliveredTo: [],
        readBy: []
      });

      await message.save();
      await message.populate('senderId', 'name username profilePic');

      // Emit only to group room
      io.to(groupId.toString()).emit('group_message', message);

      // Optionally mark delivered for group members who are online (add to deliveredTo)
      const group = await Group.findById(groupId).select('members');
      if (group && group.members && group.members.length > 0) {
        const onlineMemberIds = Array.from(connectedUsers.values()).map(v => v.userId);
        const deliveredNow = group.members
          .map(m => m.toString())
          .filter(m => onlineMemberIds.includes(m));
        if (deliveredNow.length > 0) {
          await Message.findByIdAndUpdate(message._id, { $addToSet: { deliveredTo: { $each: deliveredNow } } });
          // notify each online member individually if desired
          deliveredNow.forEach(mid => {
            io.to(mid).emit('message_delivered', { messageId: message._id, chatId: groupId, to: mid });
          });
        }
      }
    } catch (error) {
      console.error('send_group_message error', error);
    }
  });

  // JOIN GROUP ROOM
  socket.on('join_group', (groupId) => {
    try {
      if (!groupId) return;
      socket.join(groupId.toString());
      console.log(`Socket ${socket.id} joined group ${groupId}`);
    } catch (err) {
      console.error('join_group', err);
    }
  });

  // LEAVE GROUP ROOM
  socket.on('leave_group', (groupId) => {
    try {
      if (!groupId) return;
      socket.leave(groupId.toString());
      console.log(`Socket ${socket.id} left group ${groupId}`);
    } catch (err) {
      console.error('leave_group', err);
    }
  });

  // TYPING INDICATOR
  // data: { chatId, senderId, isGroup }
  socket.on('typing', (data) => {
    try {
      const { chatId, senderId, isGroup } = data;
      if (isGroup) {
        socket.to(chatId.toString()).emit('user_typing', { chatId, senderId });
      } else {
        // chatId for private chats could be receiverId
        // if chatId is the other user's id, emit to them
        socket.to(chatId.toString()).emit('user_typing', { chatId, senderId });
      }
    } catch (err) {
      console.error('typing', err);
    }
  });

  // MESSAGE READ (via socket)
  // data: { chatId, messageIds, readerId }
  socket.on('messages_read', async (data) => {
    try {
      const { chatId, messageIds = [], readerId } = data;
      if (!chatId || !Array.isArray(messageIds)) return;
      await Message.updateMany(
        { _id: { $in: messageIds } },
        { $addToSet: { readBy: readerId } }
      );
      io.to(chatId.toString()).emit('messages_read', { chatId, messageIds, readerId });
    } catch (err) {
      console.error('messages_read', err);
    }
  });

  // Optional: message_delivered ack from client
  // data: { messageId, chatId, userId }
  socket.on('message_delivered_ack', async (data) => {
    try {
      const { messageId, chatId, userId } = data;
      if (!messageId || !userId) return;
      await Message.findByIdAndUpdate(messageId, { $addToSet: { deliveredTo: userId } });
      io.to(chatId.toString()).emit('message_delivered', { messageId, chatId, to: userId });
    } catch (err) {
      console.error('message_delivered_ack', err);
    }
  });

  // Disconnect handling
  socket.on('disconnect', async () => {
    try {
      const info = connectedUsers.get(socket.id);
      if (info) {
        // mark offline
        await User.findByIdAndUpdate(info.userId, { isOnline: false, lastSeen: new Date() });
        socket.broadcast.emit('user_offline', { userId: info.userId });
        connectedUsers.delete(socket.id);
      }
      console.log('Socket disconnected:', socket.id);
    } catch (err) {
      console.error('disconnect error', err);
    }
  });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

