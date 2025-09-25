// Ultimate Hi Chat Backend - Socket.IO + WebRTC + Messaging + MongoDB
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
require('dotenv').config();

// Import MongoDB Models
const User = require('./models/User');
const Message = require('./models/Message');
const Group = require('./models/Group');

const app = express();
const server = http.createServer(app);

// Socket.IO server with enhanced configuration
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
    credentials: true
  },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000
});

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'hi-chat-ultimate-secret-2024';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://ChatAppData:CHATAPPDATA@chatappdata.ua6pnti.mongodb.net/?retryWrites=true&w=majority&appName=ChatAppData';

// Enhanced storage for Socket.IO connections
const socketStorage = {
  userSockets: new Map(),    // userId -> socket.id
  socketUsers: new Map(),    // socket.id -> userId
  chatRooms: new Map(),      // chatId -> Set of userIds
  activeCalls: new Map(),    // callId -> call data
  typingUsers: new Map()     // chatId -> Set of typing userIds
};

// ===== MongoDB Connection =====
async function connectDB() {
  try {
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    console.log('✅ MongoDB Connected Successfully');
    await mongoose.connection.db.admin().ping();
    console.log('✅ MongoDB Ping Successful');
  } catch (error) {
    console.error('❌ MongoDB Connection Error:', error.message);
    process.exit(1);
  }
}

// ===== System Initialization =====
async function initSystem() {
  try {
    let adminUser = await User.findOne({ username: 'admin' });
    if (!adminUser) {
      adminUser = new User({
        name: 'Administrator',
        username: 'admin',
        email: 'admin@hichat.com',
        password: await bcrypt.hash('admin123', 12),
        role: 'admin',
        status: 'active'
      });
      await adminUser.save();
      console.log('✅ Admin user created');
    }

    const testUsers = [
      { name: 'John Doe', username: 'john', email: 'john@test.com' },
      { name: 'Jane Smith', username: 'jane', email: 'jane@test.com' },
      { name: 'Bob Wilson', username: 'bob', email: 'bob@test.com' }
    ];

    for (const userData of testUsers) {
      const existingUser = await User.findOne({ username: userData.username });
      if (!existingUser) {
        const user = new User({
          ...userData,
          password: await bcrypt.hash('password123', 12),
          role: 'user',
          status: 'active'
        });
        await user.save();
        console.log(`✅ Test user created: ${userData.username}`);
      }
    }

    const userCount = await User.countDocuments();
    console.log(`✅ System initialized with ${userCount} users`);
  } catch (error) {
    console.error('❌ Error initializing system:', error);
  }
}

// ===== Middleware =====
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '50mb' }));

// ===== Auth Middleware =====
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token provided' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    if (!user || user.status !== 'active') return res.status(401).json({ error: 'Invalid user' });

    req.user = { userId: decoded.userId, username: decoded.username, role: decoded.role, userDoc: user };
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ===== API Routes =====
app.get('/api/health', async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const messageCount = await Message.countDocuments();
    const onlineUsers = await User.countDocuments({ isOnline: true });
    
    res.json({
      status: 'OK',
      message: 'Hi Chat Backend with Socket.IO & MongoDB',
      version: '3.1.0',
      database: { users: userCount, messages: messageCount, onlineUsers },
      realtime: { 
        connections: socketStorage.userSockets.size,
        chatRooms: socketStorage.chatRooms.size,
        activeCalls: socketStorage.activeCalls.size
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ status: 'ERROR', error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const user = await User.findOne({
      $or: [{ username: username.toLowerCase() }, { email: username.toLowerCase() }]
    });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(401).json({ error: 'Invalid credentials' });

    user.isOnline = true;
    user.lastSeen = new Date();
    await user.save();

    const token = jwt.sign({ userId: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    
    res.json({ 
      success: true, 
      token, 
      user: {
        id: user._id, name: user.name, username: user.username, 
        email: user.email, role: user.role, isOnline: user.isOnline
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/users', auth, async (req, res) => {
  try {
    const users = await User.find({ status: 'active' }).select('-password').lean();
    res.json({ success: true, users });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.post('/api/chats', auth, async (req, res) => {
  try {
    const { participants, type = 'direct', name } = req.body;
    if (!participants || participants.length < 2) return res.status(400).json({ error: 'Need at least 2 participants' });

    let chatId;
    if (type === 'direct') {
      const sortedParticipants = participants.sort();
      chatId = `direct_${sortedParticipants.join('_')}`;
    } else {
      const group = new Group({
        name: name || `Group ${Date.now()}`,
        createdBy: req.user.userId,
        members: participants,
        admins: [req.user.userId]
      });
      await group.save();
      chatId = group._id.toString();
    }

    socketStorage.chatRooms.set(chatId, new Set());
    res.status(201).json({ success: true, chatId, participants, type });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create chat' });
  }
});

app.get('/api/messages/:chatId', auth, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { limit = 50 } = req.query;

    const messages = await Message.find({ chatId })
      .populate('senderId', 'name username profilePic')
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .lean();

    messages.reverse();
    res.json({ success: true, messages });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get messages' });
  }
});

// ===== Socket.IO Event Handling =====
io.on('connection', (socket) => {
  console.log(`🔌 Socket.IO connected: ${socket.id}`);
  let userId = null;

  // User connection
  socket.on('user_connected', async (data) => {
    try {
      userId = data.userId;
      socketStorage.userSockets.set(userId, socket.id);
      socketStorage.socketUsers.set(socket.id, userId);

      await User.findByIdAndUpdate(userId, { isOnline: true, lastSeen: new Date() });
      socket.emit('connected', { userId, socketId: socket.id });
      socket.broadcast.emit('user_online', { userId, username: data.username });
      
      console.log(`👤 User connected: ${data.username} (${userId})`);
    } catch (error) {
      console.error('User connection error:', error);
    }
  });

  // Join chat room
  socket.on('join_chat', (data) => {
    try {
      const { chatId } = data;
      socket.join(chatId);
      
      if (!socketStorage.chatRooms.has(chatId)) {
        socketStorage.chatRooms.set(chatId, new Set());
      }
      socketStorage.chatRooms.get(chatId).add(userId);
      
      socket.emit('chat_joined', { chatId });
      console.log(`💬 User ${userId} joined chat: ${chatId}`);
    } catch (error) {
      console.error('Join chat error:', error);
    }
  });

  // Handle messages
  socket.on('message', async (msg) => {
    try {
      const { chatId, message, recipientId, groupId } = msg;
      if (!chatId || !message || !userId) return;

      const newMessage = new Message({
        chatId, senderId: userId, recipientId, groupId,
        text: message, type: 'text', timestamp: new Date()
      });
      await newMessage.save();
      await newMessage.populate('senderId', 'name username profilePic');

      const messageData = {
        id: newMessage._id, chatId, senderId: newMessage.senderId,
        content: newMessage.text, timestamp: newMessage.timestamp,
        senderName: newMessage.senderId.name
      };

      socket.to(chatId).emit('new_message', messageData);
      console.log(`📨 Message sent to chat: ${chatId}`);
    } catch (error) {
      console.error('Message error:', error);
    }
  });

  // Typing indicators
  socket.on('typing', (data) => {
    try {
      const { chatId, isTyping } = data;
      if (!socketStorage.typingUsers.has(chatId)) {
        socketStorage.typingUsers.set(chatId, new Set());
      }
      
      const typingSet = socketStorage.typingUsers.get(chatId);
      if (isTyping) {
        typingSet.add(userId);
      } else {
        typingSet.delete(userId);
      }
      
      socket.to(chatId).emit('typing', { userId, isTyping, chatId });
    } catch (error) {
      console.error('Typing error:', error);
    }
  });

  // WebRTC Call Events
  socket.on('call_user', (data) => {
    try {
      const { targetUserId, callId, callerName } = data;
      socketStorage.activeCalls.set(callId, {
        callerId: userId, targetUserId, status: 'calling', startTime: new Date()
      });
      
      const targetSocketId = socketStorage.userSockets.get(targetUserId);
      if (targetSocketId) {
        io.to(targetSocketId).emit('incoming_call', {
          callId, callerUserId: userId, callerName
        });
      }
      console.log(`📞 Call initiated: ${userId} -> ${targetUserId}`);
    } catch (error) {
      console.error('Call user error:', error);
    }
  });

  socket.on('answer_call', (data) => {
    try {
      const { callId, targetUserId } = data;
      const call = socketStorage.activeCalls.get(callId);
      if (call) {
        call.status = 'active';
        call.answerTime = new Date();
      }
      
      const targetSocketId = socketStorage.userSockets.get(targetUserId);
      if (targetSocketId) {
        io.to(targetSocketId).emit('call_answered', { callId });
      }
    } catch (error) {
      console.error('Answer call error:', error);
    }
  });

  socket.on('reject_call', (data) => {
    try {
      const { callId, targetUserId } = data;
      socketStorage.activeCalls.delete(callId);
      
      const targetSocketId = socketStorage.userSockets.get(targetUserId);
      if (targetSocketId) {
        io.to(targetSocketId).emit('call_rejected', { callId });
      }
    } catch (error) {
      console.error('Reject call error:', error);
    }
  });

  socket.on('end_call', (data) => {
    try {
      const { callId, targetUserId } = data;
      socketStorage.activeCalls.delete(callId);
      
      const targetSocketId = socketStorage.userSockets.get(targetUserId);
      if (targetSocketId) {
        io.to(targetSocketId).emit('call_ended', { callId });
      }
    } catch (error) {
      console.error('End call error:', error);
    }
  });

  // WebRTC signaling
  socket.on('webrtc-signal', (data) => {
    try {
      const { targetUserId, signal, callId, type } = data;
      const targetSocketId = socketStorage.userSockets.get(targetUserId);
      if (targetSocketId) {
        io.to(targetSocketId).emit('webrtc-signal', {
          signal, callId, fromUserId: userId, signalType: type
        });
      }
    } catch (error) {
      console.error('WebRTC signal error:', error);
    }
  });

  // Disconnect handling
  socket.on('disconnect', async () => {
    try {
      if (userId) {
        await User.findByIdAndUpdate(userId, { isOnline: false, lastSeen: new Date() });
        
        socketStorage.userSockets.delete(userId);
        socketStorage.socketUsers.delete(socket.id);
        
        // Clean up chat rooms
        socketStorage.chatRooms.forEach((participants, chatId) => {
          participants.delete(userId);
          if (participants.size === 0) {
            socketStorage.chatRooms.delete(chatId);
          }
        });
        
        // Clean up typing indicators
        socketStorage.typingUsers.forEach((typingSet, chatId) => {
          typingSet.delete(userId);
        });
        
        socket.broadcast.emit('user_offline', { userId });
        console.log(`👤 User disconnected: ${userId}`);
      }
    } catch (error) {
      console.error('Disconnect error:', error);
    }
  });
});

// ===== Cleanup Tasks =====
setInterval(() => {
  // Clean up old calls
  const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
  socketStorage.activeCalls.forEach((call, callId) => {
    if (call.startTime < fiveMinutesAgo) {
      socketStorage.activeCalls.delete(callId);
    }
  });
}, 60000);

// ===== Error Handling =====
process.on('unhandledRejection', (error) => {
  console.error('Unhandled Promise Rejection:', error);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

// ===== Server Startup =====
async function startServer() {
  try {
    await connectDB();
    await initSystem();
    
    server.listen(PORT, () => {
      console.log(`🚀 Hi Chat Backend with Socket.IO running on port ${PORT}`);
      console.log(`📡 Socket.IO server ready`);
      console.log(`🌐 API: http://localhost:${PORT}/api`);
      console.log(`💾 MongoDB: Connected and initialized`);
      console.log(`🔑 Admin: admin/admin123`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

startServer();
module.exports = { app, server, io };
