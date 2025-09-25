// // index.js
// require('dotenv').config();
// const express = require('express');
// const http = require('http');
// const { Server } = require('socket.io');
// const cors = require('cors');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcryptjs');
// const mongoose = require('mongoose');
// const path = require('path');

// // Import your Mongoose models (ensure these exist)
// const User = require('./models/User');
// const Message = require('./models/Message');
// const Group = require('./models/Group');

// const app = express();
// const server = http.createServer(app);

// const io = new Server(server, {
//   cors: { origin: '*', methods: ['GET', 'POST'] },
//   maxHttpBufferSize: 10 * 1024 * 1024 // 10MB payloads
// });

// const PORT = process.env.PORT || 3001;
// const JWT_SECRET = process.env.JWT_SECRET || 'hi-chat-ultimate-secret-2024';
// const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI || 'mongodb+srv://ChatAppData:CHATAPPDATA@chatappdata.ua6pnti.mongodb.net/?retryWrites=true&w=majority&appName=ChatAppData';

// // In-memory maps to track sockets (socket.io gives rooms, but we keep a map for direct user signaling)
// const userSockets = new Map(); // userId -> Set(socketId) (support multiple devices)
// const chatRooms = new Map();   // chatId -> Set(userId)  (helps when emitting to DB-backed participants)

// /* -------------------- MongoDB Connection -------------------- */
// async function connectDB() {
//   try {
//     await mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
//     console.log('✅ MongoDB Connected Successfully');
//   } catch (err) {
//     console.error('❌ MongoDB connection failed:', err);
//     process.exit(1);
//   }
// }

// /* -------------------- Initialize admin + test users -------------------- */
// async function initSystem() {
//   try {
//     let admin = await User.findOne({ username: 'admin' });
//     if (!admin) {
//       admin = new User({
//         name: 'Administrator',
//         username: 'admin',
//         email: 'admin@hichat.com',
//         password: await bcrypt.hash('admin123', 12),
//         role: 'admin',
//         status: 'active'
//       });
//       await admin.save();
//       console.log('✅ Admin user created');
//     }

//     const testUsers = [
//       { name: 'John Doe', username: 'john', email: 'john@test.com' },
//       { name: 'Jane Smith', username: 'jane', email: 'jane@test.com' },
//       { name: 'Bob Wilson', username: 'bob', email: 'bob@test.com' },
//     ];

//     for (const u of testUsers) {
//       const exists = await User.findOne({ username: u.username });
//       if (!exists) {
//         const created = new User({
//           ...u,
//           password: await bcrypt.hash('password123', 12),
//           role: 'user',
//           status: 'active'
//         });
//         await created.save();
//         console.log(`✅ Test user created: ${u.username}`);
//       }
//     }

//     console.log('✅ System initialization complete');
//   } catch (err) {
//     console.error('❌ initSystem error:', err);
//   }
// }

// /* -------------------- Middleware & Helpers -------------------- */
// app.use(cors({ origin: '*', credentials: true }));
// app.use(express.json({ limit: '50mb' }));

// // Auth middleware for HTTP routes
// const httpAuth = async (req, res, next) => {
//   try {
//     const header = req.header('Authorization') || '';
//     const token = header.replace('Bearer ', '');
//     if (!token) return res.status(401).json({ error: 'No token' });
//     const decoded = jwt.verify(token, JWT_SECRET);
//     const user = await User.findById(decoded.userId);
//     if (!user || user.status !== 'active') return res.status(401).json({ error: 'Invalid user' });
//     req.user = { id: decoded.userId, username: decoded.username, role: decoded.role };
//     next();
//   } catch (err) {
//     return res.status(401).json({ error: 'Invalid token' });
//   }
// };

// /* -------------------- HTTP API Routes -------------------- */

// // Health
// app.get('/api/health', async (req, res) => {
//   try {
//     const users = await User.countDocuments();
//     const messages = await Message.countDocuments();
//     const groups = await Group.countDocuments();
//     res.json({
//       status: 'OK',
//       users,
//       messages,
//       groups,
//       timestamp: new Date().toISOString()
//     });
//   } catch (err) {
//     res.status(500).json({ status: 'ERROR', message: err.message });
//   }
// });

// // Login (returns JWT + user profile)
// app.post('/api/login', async (req, res) => {
//   try {
//     const { username, password } = req.body;
//     if (!username || !password) return res.status(400).json({ error: 'username & password required' });

//     const lookup = username.includes('@') ? { email: username.toLowerCase() } : { username: username.toLowerCase() };
//     const user = await User.findOne(lookup);
//     if (!user) return res.status(401).json({ error: 'Invalid credentials' });

//     const ok = await bcrypt.compare(password, user.password);
//     if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

//     user.isOnline = true;
//     user.lastSeen = new Date();
//     await user.save();

//     const token = jwt.sign({ userId: user._id.toString(), username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
//     res.json({
//       success: true,
//       token,
//       user: {
//         _id: user._id,
//         name: user.name,
//         username: user.username,
//         email: user.email,
//         role: user.role,
//         profilePic: user.profilePic,
//         isOnline: user.isOnline
//       }
//     });
//   } catch (err) {
//     console.error('Login error:', err);
//     res.status(500).json({ error: 'Login failed' });
//   }
// });

// // Fetch users (protected)
// app.get('/api/users', httpAuth, async (req, res) => {
//   try {
//     const users = await User.find({}, '-password').lean();
//     res.json({ success: true, users });
//   } catch (err) {
//     res.status(500).json({ error: 'Failed to fetch users' });
//   }
// });

// // Groups - create and list
// app.get('/api/groups', httpAuth, async (req, res) => {
//   try {
//     const groups = await Group.find().populate('members', 'username name _id').lean();
//     res.json({ success: true, groups });
//   } catch (err) {
//     res.status(500).json({ error: 'Failed to fetch groups' });
//   }
// });

// app.post('/api/groups', httpAuth, async (req, res) => {
//   try {
//     const { name } = req.body;
//     if (!name) return res.status(400).json({ error: 'Group name required' });
//     const group = new Group({ name, members: [req.user.id], createdBy: req.user.id });
//     await group.save();
//     res.status(201).json({ success: true, group });
//   } catch (err) {
//     console.error('Create group error:', err);
//     res.status(500).json({ error: 'Failed to create group' });
//   }
// });

// // Join group
// app.post('/api/groups/:id/join', httpAuth, async (req, res) => {
//   try {
//     const group = await Group.findById(req.params.id);
//     if (!group) return res.status(404).json({ error: 'Group not found' });
//     if (!group.members.includes(req.user.id)) {
//       group.members.push(req.user.id);
//       await group.save();
//     }
//     res.json({ success: true, group });
//   } catch (err) {
//     res.status(500).json({ error: 'Failed to join group' });
//   }
// });

// // Get group messages (paginated)
// app.get('/api/groups/:id/messages', httpAuth, async (req, res) => {
//   try {
//     const { id } = req.params;
//     const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
//     const messages = await Message.find({ chatId: id })
//       .sort({ createdAt: 1 })
//       .limit(limit)
//       .populate('senderId', 'username name _id')
//       .lean();
//     res.json({ success: true, messages });
//   } catch (err) {
//     res.status(500).json({ error: 'Failed to fetch messages' });
//   }
// });

// // Post a message via HTTP (optional)
// app.post('/api/messages', httpAuth, async (req, res) => {
//   try {
//     const { chatId, content, file, type = 'text' } = req.body;
//     if (!chatId || (!content && !file)) return res.status(400).json({ error: 'chatId and content/file required' });

//     const message = new Message({
//       chatId,
//       senderId: req.user.id,
//       content,
//       file: file || null,
//       type,
//       createdAt: new Date()
//     });
//     await message.save();
//     const populated = await message.populate('senderId', 'username name _id');

//     // Emit to room
//     io.to(chatId).emit('new_message', populated);
//     res.status(201).json({ success: true, message: populated });
//   } catch (err) {
//     console.error('API message error:', err);
//     res.status(500).json({ error: 'Failed to send message' });
//   }
// });

// /* -------------------- Socket.IO (Realtime) -------------------- */

// // Socket middleware: validate JWT token if present in handshake auth
// io.use(async (socket, next) => {
//   try {
//     // Accept either token in handshake.auth.token or require client to emit 'user_connected' after connecting
//     const token = socket.handshake.auth?.token;
//     if (token) {
//       const decoded = jwt.verify(token, JWT_SECRET);
//       socket.user = { id: decoded.userId, username: decoded.username, role: decoded.role };
//       return next();
//     }
//     // If no token, allow connection but socket.user will be null; the client can send 'authenticate' or 'user_connected' event with token
//     return next();
//   } catch (err) {
//     console.warn('Socket auth failed:', err.message);
//     return next(); // allow connection but require later auth event
//   }
// });

// io.on('connection', (socket) => {
//   console.log('🔌 Socket connected:', socket.id);

//   // If socket.user already set (handshake token), add to userSockets map
//   if (socket.user && socket.user.id) {
//     const uid = socket.user.id.toString();
//     if (!userSockets.has(uid)) userSockets.set(uid, new Set());
//     userSockets.get(uid).add(socket.id);
//     // Optionally emit presence to others
//   }

//   // Provide an explicit auth event if client didn't send token in handshake
//   socket.on('authenticate', async ({ token }) => {
//     try {
//       const decoded = jwt.verify(token, JWT_SECRET);
//       socket.user = { id: decoded.userId, username: decoded.username, role: decoded.role };
//       const uid = socket.user.id.toString();
//       if (!userSockets.has(uid)) userSockets.set(uid, new Set());
//       userSockets.get(uid).add(socket.id);
//       // Update DB online status
//       await User.findByIdAndUpdate(uid, { isOnline: true, lastSeen: new Date() });
//       socket.emit('authenticated', { userId: uid });
//     } catch (err) {
//       socket.emit('unauthorized', { message: 'Invalid token' });
//     }
//   });

//   // user_connected: older clients may use this - accept either way
//   socket.on('user_connected', async (payload) => {
//     // payload may contain token or { userId, username }
//     try {
//       if (payload?.token) {
//         const decoded = jwt.verify(payload.token, JWT_SECRET);
//         socket.user = { id: decoded.userId, username: decoded.username, role: decoded.role };
//       } else if (!socket.user && payload?.userId) {
//         socket.user = { id: payload.userId, username: payload.username };
//       }
//       if (socket.user && socket.user.id) {
//         const uid = socket.user.id.toString();
//         if (!userSockets.has(uid)) userSockets.set(uid, new Set());
//         userSockets.get(uid).add(socket.id);
//         await User.findByIdAndUpdate(uid, { isOnline: true, lastSeen: new Date() });
//         socket.emit('connected', { userId: uid });
//         // optional broadcast to others that user is online
//         io.emit('user_online', { userId: uid, username: socket.user.username });
//       }
//     } catch (err) {
//       console.warn('user_connected error', err);
//     }
//   });

//   // Join a chat room (direct or group)
//   socket.on('join_chat', async (data) => {
//     try {
//       const { chatId } = data;
//       if (!chatId) return;
//       socket.join(chatId);

//       // Optionally keep a server-side map of chat participants for broadcasting offline -> online
//       if (!chatRooms.has(chatId)) chatRooms.set(chatId, new Set());
//       if (socket.user && socket.user.id) chatRooms.get(chatId).add(socket.user.id.toString());

//       socket.emit('chat_joined', { chatId });
//       console.log(`Socket ${socket.id} joined chat ${chatId}`);
//     } catch (err) {
//       console.error('join_chat error', err);
//     }
//   });

//   // Leave chat
//   socket.on('leave_chat', (data) => {
//     const { chatId } = data;
//     if (!chatId) return;
//     socket.leave(chatId);
//     if (chatRooms.has(chatId) && socket.user && socket.user.id) {
//       chatRooms.get(chatId).delete(socket.user.id.toString());
//     }
//     socket.emit('chat_left', { chatId });
//   });

//   // Realtime message (from client)
//   socket.on('send_message', async (data) => {
//     // data: { chatId, content, file(optional), type(optional) }
//     try {
//       if (!socket.user || !socket.user.id) {
//         // Not authenticated
//         socket.emit('error', { message: 'Not authenticated' });
//         return;
//       }
//       const { chatId, content, file = null, type = 'text' } = data;
//       if (!chatId || (!content && !file)) return;

//       // Persist to DB
//       const msgDoc = new Message({
//         chatId,
//         senderId: socket.user.id,
//         content: content || '',
//         file: file || null,
//         type,
//         createdAt: new Date(),
//       });
//       await msgDoc.save();
//       await msgDoc.populate('senderId', 'username name _id');

//       // Emit to room
//       io.to(chatId).emit('new_message', msgDoc);

//       // Update chatRooms map last message info (optional)
//       // (If you maintain Chat documents you can update them here.)
//     } catch (err) {
//       console.error('send_message error', err);
//     }
//   });

//   // Typing indicator
//   socket.on('typing', (data) => {
//     // data: { chatId, username, isTyping }
//     try {
//       const { chatId, username, isTyping = true } = data;
//       if (!chatId) return;
//       socket.to(chatId).emit('typing', { chatId, username, isTyping });
//     } catch (err) {
//       console.error('typing error', err);
//     }
//   });

//   /* ---------------- WebRTC Signaling (calls) ----------------
//      We'll relay signaling messages to the target user's sockets.
//      Expected message shape:
//        { type: 'call-offer'|'call-answer'|'ice-candidate'|'call-end', payload: { ... }, to: targetUserId }
//   */
//   socket.on('webrtc-signal', (data) => {
//     try {
//       const { type, payload, to } = data;
//       if (!to) return;
//       const targetSockets = userSockets.get(to.toString());
//       if (!targetSockets) return;
//       // Send event to all target sockets
//       for (const sid of targetSockets) {
//         io.to(sid).emit('webrtc-signal', { type, payload, from: socket.user ? socket.user.id : null });
//       }
//     } catch (err) {
//       console.error('webrtc-signal error', err);
//     }
//   });

//   // Convenience events for calling users (older format)
//   socket.on('call_user', (data) => {
//     // { targetUserId, callId, callerName }
//     const target = data.targetUserId;
//     const set = userSockets.get(target);
//     if (set) {
//       for (const sid of set) io.to(sid).emit('incoming_call', { callId: data.callId, callerUserId: socket.user?.id, callerName: data.callerName });
//     }
//   });

//   socket.on('answer_call', (data) => {
//     const target = data.targetUserId;
//     const set = userSockets.get(target);
//     if (set) {
//       for (const sid of set) io.to(sid).emit('call_answered', { callId: data.callId });
//     }
//   });

//   socket.on('reject_call', (data) => {
//     const target = data.targetUserId;
//     const set = userSockets.get(target);
//     if (set) {
//       for (const sid of set) io.to(sid).emit('call_rejected', { callId: data.callId });
//     }
//   });

//   socket.on('end_call', (data) => {
//     const target = data.targetUserId;
//     const set = userSockets.get(target);
//     if (set) {
//       for (const sid of set) io.to(sid).emit('call_ended', { callId: data.callId });
//     }
//   });

//   // On disconnect: remove from userSockets, update DB status
//   socket.on('disconnect', async (reason) => {
//     try {
//       if (socket.user && socket.user.id) {
//         const uid = socket.user.id.toString();
//         if (userSockets.has(uid)) {
//           const s = userSockets.get(uid);
//           s.delete(socket.id);
//           if (s.size === 0) {
//             userSockets.delete(uid);
//             // mark offline
//             await User.findByIdAndUpdate(uid, { isOnline: false, lastSeen: new Date() });
//             io.emit('user_offline', { userId: uid });
//           } else {
//             userSockets.set(uid, s);
//           }
//         }
//       }
//       // remove from chatRooms sets
//       for (const [chatId, set] of chatRooms.entries()) {
//         if (socket.user && socket.user.id) set.delete(socket.user.id.toString());
//         if (set.size === 0) chatRooms.delete(chatId);
//       }
//       console.log('🔌 Socket disconnected:', socket.id, 'reason:', reason);
//     } catch (err) {
//       console.error('disconnect handler error:', err);
//     }
//   });
// });

// /* -------------------- Start server -------------------- */
// async function start() {
//   try {
//     await connectDB();
//     await initSystem();

//     server.listen(PORT, () => {
//       console.log(`🚀 Hi Chat Ultimate Backend with MongoDB (Socket.IO) running on port ${PORT}`);
//       console.log(`📡 Socket.IO server ready`);
//     });
//   } catch (err) {
//     console.error('Server start error:', err);
//     process.exit(1);
//   }
// }

// start();

// /* -------------------- Exports (for tests or other imports) -------------------- */
// module.exports = { app, server, io };














// // Ultimate Hi Chat Backend - WebSocket → Socket.IO Migration (FIXED)
// const express = require('express');
// const http = require('http');
// const { Server } = require('socket.io');
// const cors = require('cors');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcryptjs');
// const mongoose = require('mongoose');
// require('dotenv').config();

// // MongoDB Models
// const User = require('./models/User');
// const Message = require('./models/Message');
// const Group = require('./models/Group');

// const app = express();
// const server = http.createServer(app);
// const io = new Server(server, {
//   cors: { origin: "*", methods: ["GET", "POST"] }
// });

// const PORT = process.env.PORT || 3001;
// const JWT_SECRET = process.env.JWT_SECRET || 'hi-chat-ultimate-secret-2024';
// const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://ChatAppData:CHATAPPDATA@chatappdata.ua6pnti.mongodb.net/?retryWrites=true&w=majority';

// // In-memory storage for socket connections and chat rooms
// const wsStorage = {
//   connections: new Map(),
//   chatRooms: new Map(),
//   userSockets: new Map() // userId -> socketId mapping
// };

// // ===== MongoDB Connection =====
// async function connectDB() {
//   try {
//     await mongoose.connect(MONGODB_URI, {
//       useNewUrlParser: true,
//       useUnifiedTopology: true,
//     });
//     console.log('✅ MongoDB Connected Successfully');
//   } catch (error) {
//     console.error('❌ MongoDB Connection Error:', error.message);
//     process.exit(1);
//   }
// }

// // ===== System Initialization =====
// async function initSystem() {
//   try {
//     // Admin user
//     let adminUser = await User.findOne({ username: 'admin' });
//     if (!adminUser) {
//       adminUser = new User({
//         name: 'Administrator',
//         username: 'admin',
//         email: 'admin@hichat.com',
//         password: await bcrypt.hash('admin123', 12),
//         role: 'admin',
//         status: 'active'
//       });
//       await adminUser.save();
//       console.log('✅ Admin user created');
//     }

//     // Test users
//     const testUsers = [
//       { name: 'John Doe', username: 'john', email: 'john@test.com' },
//       { name: 'Jane Smith', username: 'jane', email: 'jane@test.com' },
//       { name: 'Bob Wilson', username: 'bob', email: 'bob@test.com' }
//     ];
    
//     for (const userData of testUsers) {
//       const existingUser = await User.findOne({ username: userData.username });
//       if (!existingUser) {
//         const user = new User({
//           ...userData,
//           password: await bcrypt.hash('password123', 12),
//           role: 'user',
//           status: 'active'
//         });
//         await user.save();
//         console.log(`✅ Test user created: ${userData.username}`);
//       }
//     }

//     const userCount = await User.countDocuments();
    
//         console.log(`✅ Initialized MongoDB with ${userCount} users`);

//   } catch (error) {
//     console.error('❌ Error initializing system:', error);
//   }
// }

// // ===== Middleware =====
// app.use(cors({ origin: "*", credentials: true }));
// app.use(express.json({ limit: '50mb' }));

// // ===== Auth Middleware =====
// const auth = async (req, res, next) => {
//   try {
//     const token = req.header('Authorization')?.replace('Bearer ', '');
//     if (!token) return res.status(401).json({ error: 'No token' });

//     const decoded = jwt.verify(token, JWT_SECRET);
//     const user = await User.findById(decoded.userId);
//     if (!user || user.status !== 'active') return res.status(401).json({ error: 'Invalid user' });

//     req.user = { userId: decoded.userId, username: decoded.username, role: decoded.role };
//     next();
//   } catch (error) {
//     res.status(401).json({ error: 'Invalid token' });
//   }
// };

// // ===== API Routes =====

// // Health check
// app.get('/api/health', async (req, res) => {
//   try {
//     const userCount = await User.countDocuments();
//     const messageCount = await Message.countDocuments();
//     const groupCount = await Group.countDocuments();
//     res.json({
//       status: 'OK',
//       message: 'Hi Chat Ultimate Backend with MongoDB & Socket.IO',
//       version: '2.2.0',
//       database: 'MongoDB Connected',
//       users: userCount,
//       messages: messageCount,
//       groups: groupCount,
//       connections: wsStorage.connections.size,
//       timestamp: new Date().toISOString()
//     });
//   } catch (error) {
//     res.status(500).json({ status: 'ERROR', message: 'Database connection failed', error: error.message });
//   }
// });

// // Login
// app.post('/api/login', async (req, res) => {
//   try {
//     const { username, password } = req.body;
//     const user = await User.findOne({ 
//       $or: [{ username: username.toLowerCase() }, { email: username.toLowerCase() }] 
//     });
//     if (!user) return res.status(401).json({ error: 'Invalid credentials' });

//     const isValidPassword = await bcrypt.compare(password, user.password);
//     if (!isValidPassword) return res.status(401).json({ error: 'Invalid credentials' });

//     user.isOnline = true;
//     user.lastSeen = new Date();
//     await user.save();

//     const token = jwt.sign(
//       { userId: user._id, username: user.username, role: user.role }, 
//       JWT_SECRET, 
//       { expiresIn: '30d' }
//     );
    
//     res.json({ 
//       success: true, 
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
//     console.error('Login error:', error);
//     res.status(500).json({ error: 'Login failed' });
//   }
// });

// // Fetch all users
// app.get('/api/users', auth, async (req, res) => {
//   try {
//     const users = await User.find({}, '-password').lean();
//     res.json({ success: true, users });
//   } catch (error) {
//     res.status(500).json({ error: 'Failed to fetch users' });
//   }
// });

// // Get messages for a chat
// app.get('/api/messages/:chatId', auth, async (req, res) => {
//   try {
//     const { chatId } = req.params;
//     const messages = await Message.find({ chatId })
//       .populate('senderId', 'name username profilePic')
//       .sort({ timestamp: 1 })
//       .limit(100)
//       .lean();
    
//     res.json({ success: true, messages });
//   } catch (error) {
//     res.status(500).json({ error: 'Failed to fetch messages' });
//   }
// });

// // Create or get chat
// app.post('/api/chats', auth, async (req, res) => {
//   try {
//     const { participants, type = 'direct' } = req.body;
//     if (!participants || participants.length < 2) {
//       return res.status(400).json({ error: 'Need at least 2 participants' });
//     }

//     // For direct chats, create a consistent chatId
//     let chatId;
//     // if (type === 'direct') {
//     //   const sortedParticipants = participants.sort();
//     //   chatId = direct_${sortedParticipants.join('_')};
//     // } else {
//     //   chatId = group_${Date.now()}_${Math.random().toString(36).substr(2, 9)};
//     // }


//     if (type === 'direct') {
//   const sortedParticipants = participants.sort();
//   chatId = `direct_${sortedParticipants.join('_')}`;
// } else {
//   chatId = `group_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
// }


//     res.json({ success: true, chatId, participants, type });
//   } catch (error) {
//     res.status(500).json({ error: 'Failed to create chat' });
//   }
// });

// // ===== Socket.IO Event Handlers =====
// io.on("connection", (socket) => {
//   console.log("🔌 Socket.IO connected:", socket.id);
//   let userId = null;

//   // User connection
//   socket.on("user_connected", async (data) => {
//     try {
//       userId = data.userId;
//       wsStorage.connections.set(userId, socket);
//       wsStorage.userSockets.set(socket.id, userId);

//       await User.findByIdAndUpdate(userId, { 
//         isOnline: true, 
//         lastSeen: new Date() 
//       });
      
//       socket.emit("connected", { userId });
//       // console.log(👤 User connected: ${data.username} (${userId}));
//             console.log(`👤 User connected: ${data.username} (${userId})`);

//     } catch (error) {
//       console.error('Error in user_connected:', error);
//     }
//   });

//   // Join chat room
//   socket.on("join_chat", (data) => {
//     try {
//       const { chatId } = data;
//       socket.join(chatId);
      
//       if (!wsStorage.chatRooms.has(chatId)) {
//         wsStorage.chatRooms.set(chatId, new Set());
//       }
//       wsStorage.chatRooms.get(chatId).add(userId);
      
//       socket.emit("chat_joined", { chatId });
//       // console.log(💬 User ${userId} joined chat: ${chatId});

//             console.log(`💬 User ${userId} joined chat: ${chatId}`);

//     } catch (error) {
//       console.error('Error in join_chat:', error);
//     }
//   });

//   // Handle messages
//   socket.on("message", async (msg) => {
//     try {
//       await handleWSMessage(msg, userId, socket);
//     } catch (error) {
//       console.error('Error handling message:', error);
//     }
//   });

//   // Typing indicators
//   socket.on("typing", (msg) => {
//     try {
//       socket.to(msg.chatId).emit("typing", { 
//         username: msg.username, 
//         chatId: msg.chatId,
//         userId: userId
//       });
//     } catch (error) {
//       console.error('Error in typing:', error);
//     }
//   });

//   // WebRTC signaling
//   socket.on("webrtc-signal", (msg) => {
//     try {
//       handleWebRTCSignal(msg, userId);
//     } catch (error) {
//       console.error('Error in webrtc-signal:', error);
//     }
//   });

//   // Disconnect handler
//   socket.on("disconnect", async () => {
//     try {
//       if (userId) {
//         wsStorage.connections.delete(userId);
//         wsStorage.userSockets.delete(socket.id);
        
//         await User.findByIdAndUpdate(userId, { 
//           isOnline: false, 
//           lastSeen: new Date() 
//         });
        
//         // console.log(🔌 User ${userId} disconnected);
//             console.log(`🔌 User ${userId} disconnected`);

//       }
//     } catch (error) {
//       console.error('Error in disconnect:', error);
//     }
//   });
// });

// // ===== Message Handler =====
// async function handleWSMessage(msg, senderId, socket) {
//   try {
//     const { chatId, message, type = 'text', metadata = {} } = msg;
    
//     if (!chatId || !message || !senderId) {
//       console.error('Invalid message data:', { chatId, message, senderId });
//       return;
//     }

//     // Save message to MongoDB
//     const newMessage = new Message({
//       chatId,
//       senderId,
//       text: message,
//       type,
//       metadata,
//       timestamp: new Date()
//     });
    
//     await newMessage.save();
    
//     // Populate sender info for broadcasting
//     await newMessage.populate('senderId', 'name username profilePic');
    
//     const messageData = {
//       type: 'new_message',
//       id: newMessage._id,
//       chatId: newMessage.chatId,
//       senderId: newMessage.senderId,
//       content: newMessage.text,
//       messageType: newMessage.type,
//       timestamp: newMessage.timestamp,
//       metadata: newMessage.metadata
//     };

//     // Broadcast to chat room
//     socket.to(chatId).emit('new_message', messageData);
    
//     // console.log(📨 Message saved and broadcast: ${chatId});

//         console.log(`📨 Message saved and broadcast: ${chatId}`);

//   } catch (error) {
//     console.error('Error in handleWSMessage:', error);
//   }
// }

// // ===== Broadcast Functions =====
// function broadcastToChat(chatId, message, excludeUserId = null) {
//   try {
//     const participants = wsStorage.chatRooms.get(chatId);
//     if (participants) {
//       participants.forEach(uid => {
//         if (uid !== excludeUserId) {
//           const sock = wsStorage.connections.get(uid);
//           if (sock) {
//             sock.emit(message.type || 'message', message);
//           }
//         }
//       });
//     }
//   } catch (error) {
//     console.error('Error in broadcastToChat:', error);
//   }
// }

// function broadcastToUser(userId, message) {
//   try {
//     const sock = wsStorage.connections.get(userId);
//     if (sock) {
//       sock.emit(message.type || 'message', message);
//     }
//   } catch (error) {
//     console.error('Error in broadcastToUser:', error);
//   }
// }

// // ===== WebRTC Signal Handler =====
// function handleWebRTCSignal(msg, fromUserId) {
//   try {
//     const { targetUserId, signal, callId, type } = msg;
    
//     const signalData = {
//       type: 'webrtc-signal',
//       signal,
//       callId,
//       fromUserId,
//       signalType: type
//     };
    
//     broadcastToUser(targetUserId, signalData);
//     // console.log(📞 WebRTC signal from ${fromUserId} to ${targetUserId});

//         console.log(`📞 WebRTC signal from ${fromUserId} to ${targetUserId}`);

//   } catch (error) {
//     console.error('Error in handleWebRTCSignal:', error);
//   }
// }

// // ===== Error Handling =====
// process.on('uncaughtException', (error) => {
//   console.error('Uncaught Exception:', error);
// });

// process.on('unhandledRejection', (error) => {
//   console.error('Unhandled Rejection:', error);
// });

// // ===== Start Server =====
// async function startServer() {
//   try {
//     await connectDB();
//     await initSystem();
    
//     server.listen(PORT, () => {
//       // console.log(🚀 Hi Chat Ultimate Backend with MongoDB & Socket.IO running on port ${PORT});
//       // console.log(📡 Socket.IO server ready);
//       // console.log(🌐 API: http://localhost:${PORT}/api);
//       // console.log(💾 MongoDB: Connected and initialized);
//       // console.log(🔑 Admin: admin/admin123);

//             console.log(`🚀 Hi Chat Ultimate Backend with MongoDB & Socket.IO running on port ${PORT}`);
//       console.log(`📡 Socket.IO server ready`);
//       console.log(`🌐 API: http://localhost:${PORT}/api`);
//       console.log(`💾 MongoDB: Connected and initialized`);
//       console.log(`🔑 Admin: admin/admin123`);

//     });
//   } catch (error) {
//     console.error('❌ Failed to start server:', error);
//     process.exit(1);
//   }
// }

// startServer();

// module.exports = { app, server, io };













//PRevious Code Testing



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


