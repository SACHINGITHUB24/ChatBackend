// index.js
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const path = require('path');

// Import your Mongoose models (ensure these exist)
const User = require('./models/User');
const Message = require('./models/Message');
const Group = require('./models/Group');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  maxHttpBufferSize: 10 * 1024 * 1024 // 10MB payloads
});

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'hi-chat-ultimate-secret-2024';
const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI || 'mongodb+srv://ChatAppData:CHATAPPDATA@chatappdata.ua6pnti.mongodb.net/?retryWrites=true&w=majority&appName=ChatAppData';

// In-memory maps to track sockets (socket.io gives rooms, but we keep a map for direct user signaling)
const userSockets = new Map(); // userId -> Set(socketId) (support multiple devices)
const chatRooms = new Map();   // chatId -> Set(userId)  (helps when emitting to DB-backed participants)

/* -------------------- MongoDB Connection -------------------- */
async function connectDB() {
  try {
    await mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
    console.log('✅ MongoDB Connected Successfully');
  } catch (err) {
    console.error('❌ MongoDB connection failed:', err);
    process.exit(1);
  }
}

/* -------------------- Initialize admin + test users -------------------- */
async function initSystem() {
  try {
    let admin = await User.findOne({ username: 'admin' });
    if (!admin) {
      admin = new User({
        name: 'Administrator',
        username: 'admin',
        email: 'admin@hichat.com',
        password: await bcrypt.hash('admin123', 12),
        role: 'admin',
        status: 'active'
      });
      await admin.save();
      console.log('✅ Admin user created');
    }

    const testUsers = [
      { name: 'John Doe', username: 'john', email: 'john@test.com' },
      { name: 'Jane Smith', username: 'jane', email: 'jane@test.com' },
      { name: 'Bob Wilson', username: 'bob', email: 'bob@test.com' },
    ];

    for (const u of testUsers) {
      const exists = await User.findOne({ username: u.username });
      if (!exists) {
        const created = new User({
          ...u,
          password: await bcrypt.hash('password123', 12),
          role: 'user',
          status: 'active'
        });
        await created.save();
        console.log(`✅ Test user created: ${u.username}`);
      }
    }

    console.log('✅ System initialization complete');
  } catch (err) {
    console.error('❌ initSystem error:', err);
  }
}

/* -------------------- Middleware & Helpers -------------------- */
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '50mb' }));

// Auth middleware for HTTP routes
const httpAuth = async (req, res, next) => {
  try {
    const header = req.header('Authorization') || '';
    const token = header.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || user.status !== 'active') return res.status(401).json({ error: 'Invalid user' });
    req.user = { id: decoded.userId, username: decoded.username, role: decoded.role };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

/* -------------------- HTTP API Routes -------------------- */

// Health
app.get('/api/health', async (req, res) => {
  try {
    const users = await User.countDocuments();
    const messages = await Message.countDocuments();
    const groups = await Group.countDocuments();
    res.json({
      status: 'OK',
      users,
      messages,
      groups,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ status: 'ERROR', message: err.message });
  }
});

// Login (returns JWT + user profile)
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username & password required' });

    const lookup = username.includes('@') ? { email: username.toLowerCase() } : { username: username.toLowerCase() };
    const user = await User.findOne(lookup);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    user.isOnline = true;
    user.lastSeen = new Date();
    await user.save();

    const token = jwt.sign({ userId: user._id.toString(), username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({
      success: true,
      token,
      user: {
        _id: user._id,
        name: user.name,
        username: user.username,
        email: user.email,
        role: user.role,
        profilePic: user.profilePic,
        isOnline: user.isOnline
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Fetch users (protected)
app.get('/api/users', httpAuth, async (req, res) => {
  try {
    const users = await User.find({}, '-password').lean();
    res.json({ success: true, users });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Groups - create and list
app.get('/api/groups', httpAuth, async (req, res) => {
  try {
    const groups = await Group.find().populate('members', 'username name _id').lean();
    res.json({ success: true, groups });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch groups' });
  }
});

app.post('/api/groups', httpAuth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Group name required' });
    const group = new Group({ name, members: [req.user.id], createdBy: req.user.id });
    await group.save();
    res.status(201).json({ success: true, group });
  } catch (err) {
    console.error('Create group error:', err);
    res.status(500).json({ error: 'Failed to create group' });
  }
});

// Join group
app.post('/api/groups/:id/join', httpAuth, async (req, res) => {
  try {
    const group = await Group.findById(req.params.id);
    if (!group) return res.status(404).json({ error: 'Group not found' });
    if (!group.members.includes(req.user.id)) {
      group.members.push(req.user.id);
      await group.save();
    }
    res.json({ success: true, group });
  } catch (err) {
    res.status(500).json({ error: 'Failed to join group' });
  }
});

// Get group messages (paginated)
app.get('/api/groups/:id/messages', httpAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const messages = await Message.find({ chatId: id })
      .sort({ createdAt: 1 })
      .limit(limit)
      .populate('senderId', 'username name _id')
      .lean();
    res.json({ success: true, messages });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Post a message via HTTP (optional)
app.post('/api/messages', httpAuth, async (req, res) => {
  try {
    const { chatId, content, file, type = 'text' } = req.body;
    if (!chatId || (!content && !file)) return res.status(400).json({ error: 'chatId and content/file required' });

    const message = new Message({
      chatId,
      senderId: req.user.id,
      content,
      file: file || null,
      type,
      createdAt: new Date()
    });
    await message.save();
    const populated = await message.populate('senderId', 'username name _id');

    // Emit to room
    io.to(chatId).emit('new_message', populated);
    res.status(201).json({ success: true, message: populated });
  } catch (err) {
    console.error('API message error:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

/* -------------------- Socket.IO (Realtime) -------------------- */

// Socket middleware: validate JWT token if present in handshake auth
io.use(async (socket, next) => {
  try {
    // Accept either token in handshake.auth.token or require client to emit 'user_connected' after connecting
    const token = socket.handshake.auth?.token;
    if (token) {
      const decoded = jwt.verify(token, JWT_SECRET);
      socket.user = { id: decoded.userId, username: decoded.username, role: decoded.role };
      return next();
    }
    // If no token, allow connection but socket.user will be null; the client can send 'authenticate' or 'user_connected' event with token
    return next();
  } catch (err) {
    console.warn('Socket auth failed:', err.message);
    return next(); // allow connection but require later auth event
  }
});

io.on('connection', (socket) => {
  console.log('🔌 Socket connected:', socket.id);

  // If socket.user already set (handshake token), add to userSockets map
  if (socket.user && socket.user.id) {
    const uid = socket.user.id.toString();
    if (!userSockets.has(uid)) userSockets.set(uid, new Set());
    userSockets.get(uid).add(socket.id);
    // Optionally emit presence to others
  }

  // Provide an explicit auth event if client didn't send token in handshake
  socket.on('authenticate', async ({ token }) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      socket.user = { id: decoded.userId, username: decoded.username, role: decoded.role };
      const uid = socket.user.id.toString();
      if (!userSockets.has(uid)) userSockets.set(uid, new Set());
      userSockets.get(uid).add(socket.id);
      // Update DB online status
      await User.findByIdAndUpdate(uid, { isOnline: true, lastSeen: new Date() });
      socket.emit('authenticated', { userId: uid });
    } catch (err) {
      socket.emit('unauthorized', { message: 'Invalid token' });
    }
  });

  // user_connected: older clients may use this - accept either way
  socket.on('user_connected', async (payload) => {
    // payload may contain token or { userId, username }
    try {
      if (payload?.token) {
        const decoded = jwt.verify(payload.token, JWT_SECRET);
        socket.user = { id: decoded.userId, username: decoded.username, role: decoded.role };
      } else if (!socket.user && payload?.userId) {
        socket.user = { id: payload.userId, username: payload.username };
      }
      if (socket.user && socket.user.id) {
        const uid = socket.user.id.toString();
        if (!userSockets.has(uid)) userSockets.set(uid, new Set());
        userSockets.get(uid).add(socket.id);
        await User.findByIdAndUpdate(uid, { isOnline: true, lastSeen: new Date() });
        socket.emit('connected', { userId: uid });
        // optional broadcast to others that user is online
        io.emit('user_online', { userId: uid, username: socket.user.username });
      }
    } catch (err) {
      console.warn('user_connected error', err);
    }
  });

  // Join a chat room (direct or group)
  socket.on('join_chat', async (data) => {
    try {
      const { chatId } = data;
      if (!chatId) return;
      socket.join(chatId);

      // Optionally keep a server-side map of chat participants for broadcasting offline -> online
      if (!chatRooms.has(chatId)) chatRooms.set(chatId, new Set());
      if (socket.user && socket.user.id) chatRooms.get(chatId).add(socket.user.id.toString());

      socket.emit('chat_joined', { chatId });
      console.log(`Socket ${socket.id} joined chat ${chatId}`);
    } catch (err) {
      console.error('join_chat error', err);
    }
  });

  // Leave chat
  socket.on('leave_chat', (data) => {
    const { chatId } = data;
    if (!chatId) return;
    socket.leave(chatId);
    if (chatRooms.has(chatId) && socket.user && socket.user.id) {
      chatRooms.get(chatId).delete(socket.user.id.toString());
    }
    socket.emit('chat_left', { chatId });
  });

  // Realtime message (from client)
  socket.on('send_message', async (data) => {
    // data: { chatId, content, file(optional), type(optional) }
    try {
      if (!socket.user || !socket.user.id) {
        // Not authenticated
        socket.emit('error', { message: 'Not authenticated' });
        return;
      }
      const { chatId, content, file = null, type = 'text' } = data;
      if (!chatId || (!content && !file)) return;

      // Persist to DB
      const msgDoc = new Message({
        chatId,
        senderId: socket.user.id,
        content: content || '',
        file: file || null,
        type,
        createdAt: new Date(),
      });
      await msgDoc.save();
      await msgDoc.populate('senderId', 'username name _id');

      // Emit to room
      io.to(chatId).emit('new_message', msgDoc);

      // Update chatRooms map last message info (optional)
      // (If you maintain Chat documents you can update them here.)
    } catch (err) {
      console.error('send_message error', err);
    }
  });

  // Typing indicator
  socket.on('typing', (data) => {
    // data: { chatId, username, isTyping }
    try {
      const { chatId, username, isTyping = true } = data;
      if (!chatId) return;
      socket.to(chatId).emit('typing', { chatId, username, isTyping });
    } catch (err) {
      console.error('typing error', err);
    }
  });

  /* ---------------- WebRTC Signaling (calls) ----------------
     We'll relay signaling messages to the target user's sockets.
     Expected message shape:
       { type: 'call-offer'|'call-answer'|'ice-candidate'|'call-end', payload: { ... }, to: targetUserId }
  */
  socket.on('webrtc-signal', (data) => {
    try {
      const { type, payload, to } = data;
      if (!to) return;
      const targetSockets = userSockets.get(to.toString());
      if (!targetSockets) return;
      // Send event to all target sockets
      for (const sid of targetSockets) {
        io.to(sid).emit('webrtc-signal', { type, payload, from: socket.user ? socket.user.id : null });
      }
    } catch (err) {
      console.error('webrtc-signal error', err);
    }
  });

  // Convenience events for calling users (older format)
  socket.on('call_user', (data) => {
    // { targetUserId, callId, callerName }
    const target = data.targetUserId;
    const set = userSockets.get(target);
    if (set) {
      for (const sid of set) io.to(sid).emit('incoming_call', { callId: data.callId, callerUserId: socket.user?.id, callerName: data.callerName });
    }
  });

  socket.on('answer_call', (data) => {
    const target = data.targetUserId;
    const set = userSockets.get(target);
    if (set) {
      for (const sid of set) io.to(sid).emit('call_answered', { callId: data.callId });
    }
  });

  socket.on('reject_call', (data) => {
    const target = data.targetUserId;
    const set = userSockets.get(target);
    if (set) {
      for (const sid of set) io.to(sid).emit('call_rejected', { callId: data.callId });
    }
  });

  socket.on('end_call', (data) => {
    const target = data.targetUserId;
    const set = userSockets.get(target);
    if (set) {
      for (const sid of set) io.to(sid).emit('call_ended', { callId: data.callId });
    }
  });

  // On disconnect: remove from userSockets, update DB status
  socket.on('disconnect', async (reason) => {
    try {
      if (socket.user && socket.user.id) {
        const uid = socket.user.id.toString();
        if (userSockets.has(uid)) {
          const s = userSockets.get(uid);
          s.delete(socket.id);
          if (s.size === 0) {
            userSockets.delete(uid);
            // mark offline
            await User.findByIdAndUpdate(uid, { isOnline: false, lastSeen: new Date() });
            io.emit('user_offline', { userId: uid });
          } else {
            userSockets.set(uid, s);
          }
        }
      }
      // remove from chatRooms sets
      for (const [chatId, set] of chatRooms.entries()) {
        if (socket.user && socket.user.id) set.delete(socket.user.id.toString());
        if (set.size === 0) chatRooms.delete(chatId);
      }
      console.log('🔌 Socket disconnected:', socket.id, 'reason:', reason);
    } catch (err) {
      console.error('disconnect handler error:', err);
    }
  });
});

/* -------------------- Start server -------------------- */
async function start() {
  try {
    await connectDB();
    await initSystem();

    server.listen(PORT, () => {
      console.log(`🚀 Hi Chat Ultimate Backend with MongoDB (Socket.IO) running on port ${PORT}`);
      console.log(`📡 Socket.IO server ready`);
    });
  } catch (err) {
    console.error('Server start error:', err);
    process.exit(1);
  }
}

start();

/* -------------------- Exports (for tests or other imports) -------------------- */
module.exports = { app, server, io };
