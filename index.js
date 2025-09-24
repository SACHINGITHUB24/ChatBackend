// Ultimate Hi Chat Backend - WebSocket → Socket.IO Migration
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
require('dotenv').config();

// MongoDB Models
const User = require('./models/User');
const Message = require('./models/Message');
const Group = require('./models/Group');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'hi-chat-ultimate-secret-2024';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://ChatAppData:CHATAPPDATA@chatappdata.ua6pnti.mongodb.net/?retryWrites=true&w=majority';

// In-memory storage for socket connections and chat rooms
const wsStorage = {
  connections: new Map(),
  chatRooms: new Map()
};

// ===== MongoDB Connection =====
async function connectDB() {
  try {
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('✅ MongoDB Connected Successfully');
  } catch (error) {
    console.error('❌ MongoDB Connection Error:', error.message);
    process.exit(1);
  }
}

// ===== System Initialization =====
async function initSystem() {
  try {
    // Admin user
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

    // Test users
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
    console.log(`✅ Initialized MongoDB with ${userCount} users`);
  } catch (error) {
    console.error('❌ Error initializing system:', error);
  }
}

// ===== Middleware =====
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json({ limit: '50mb' }));

// ===== Auth Middleware =====
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || user.status !== 'active') return res.status(401).json({ error: 'Invalid user' });

    req.user = { userId: decoded.userId, username: decoded.username, role: decoded.role };
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ===== API Routes =====

// Health check
app.get('/api/health', async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const messageCount = await Message.countDocuments();
    const groupCount = await Group.countDocuments();
    res.json({
      status: 'OK',
      message: 'Hi Chat Ultimate Backend with MongoDB',
      version: '2.1.0',
      database: 'MongoDB Connected',
      users: userCount,
      messages: messageCount,
      groups: groupCount,
      connections: wsStorage.connections.size,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ status: 'ERROR', message: 'Database connection failed', error: error.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ $or: [{ username: username.toLowerCase() }, { email: username.toLowerCase() }] });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(401).json({ error: 'Invalid credentials' });

    user.isOnline = true;
    user.lastSeen = new Date();
    await user.save();

    const token = jwt.sign({ userId: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user: { id: user._id, name: user.name, username: user.username, email: user.email, role: user.role, profilePic: user.profilePic, isOnline: user.isOnline } });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Fetch all users
app.get('/api/users', auth, async (req, res) => {
  try {
    const users = await User.find({}, '-password').lean();
    res.json({ success: true, users });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// ===== Socket.IO =====
io.on("connection", (socket) => {
  console.log("🔌 Socket.IO connected:", socket.id);
  let userId = null;

  socket.on("user_connected", async (data) => {
    userId = data.userId;
    wsStorage.connections.set(userId, socket);

    await User.findByIdAndUpdate(userId, { isOnline: true, lastSeen: new Date() });
    socket.emit("connected", { userId });
    console.log(`👤 User connected: ${data.username}`);
  });

  socket.on("join_chat", (data) => {
    const { chatId } = data;
    socket.join(chatId);
    if (!wsStorage.chatRooms.has(chatId)) wsStorage.chatRooms.set(chatId, new Set());
    wsStorage.chatRooms.get(chatId).add(userId);
    socket.emit("chat_joined", { chatId });
    console.log(`💬 User joined chat: ${chatId}`);
  });

  socket.on("message", (msg) => handleWSMessage(msg, userId));

  socket.on("typing", (msg) => socket.to(msg.chatId).emit("typing", { username: msg.username, chatId: msg.chatId }));

  socket.on("webrtc-signal", (msg) => handleWebRTCSignal(msg, userId));

  socket.on("disconnect", async () => {
    if (userId) {
      wsStorage.connections.delete(userId);
      await User.findByIdAndUpdate(userId, { isOnline: false, lastSeen: new Date() });
    }
    console.log("🔌 Socket.IO disconnected");
  });
});

// ===== Message Handler =====
function handleWSMessage(msg, senderId) {
  const { chatId, message } = msg;
  if (!chatId || !message) return;

  const messageId = 'msg-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
  const newMessage = { id: messageId, chatId, senderId, content: message, type: 'text', timestamp: new Date(), readBy: [senderId] };

  // Broadcast
  broadcastToChat(chatId, { type: 'new_message', ...newMessage });
}

// ===== Broadcast Functions =====
function broadcastToChat(chatId, message, excludeUserId = null) {
  const participants = wsStorage.chatRooms.get(chatId);
  if (participants) {
    participants.forEach(uid => {
      if (uid !== excludeUserId) {
        const sock = wsStorage.connections.get(uid);
        if (sock) sock.emit(message.type, message);
      }
    });
  }
}

function broadcastToUser(userId, message) {
  const sock = wsStorage.connections.get(userId);
  if (sock) sock.emit(message.type, message);
}

// ===== WebRTC Signal Handler =====
function handleWebRTCSignal(msg, fromUserId) {
  const { targetUserId, signal, callId } = msg;
  broadcastToUser(targetUserId, { type: 'webrtc-signal', signal, callId, fromUserId });
}

// ===== Start Server =====
async function startServer() {
  try {
    await connectDB();
    await initSystem();
    server.listen(PORT, () => {
      console.log(`🚀 Hi Chat Ultimate Backend with MongoDB running on port ${PORT}`);
      console.log(`📡 Socket.IO server ready`);
      console.log(`🌐 API: http://localhost:${PORT}/api`);
      console.log(`💾 MongoDB: Connected`);
      console.log(`🔑 Admin: admin/admin123`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

module.exports = { app, server, io };
