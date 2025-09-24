// // Ultimate Hi Chat Backend - WebSocket + WebRTC + Messaging + MongoDB
// const express = require('express');
// const http = require('http');
// const WebSocket = require('ws');
// const cors = require('cors');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcryptjs');
// const path = require('path');
// const fs = require('fs');
// const mongoose = require('mongoose');
// require('dotenv').config();

// // Import MongoDB models
// const User = require('./models/User');
// const Message = require('./models/Message');
// const Group = require('./models/Group');

// const app = express();
// const server = http.createServer(app);

// // WebSocket server with proper configuration
// const wss = new WebSocket.Server({ 
//   server,
//   perMessageDeflate: false,
//   clientTracking: true,
//   maxPayload: 10 * 1024 * 1024 // 10MB
// });

// const PORT = process.env.PORT || 3001;
// const JWT_SECRET = process.env.JWT_SECRET || 'hi-chat-ultimate-secret-2024';
// const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://ChatAppData:CHATAPPDATA@chatappdata.ua6pnti.mongodb.net/?retryWrites=true&w=majority&appName=ChatAppData';

// // WebSocket storage (keep for real-time connections)
// const wsStorage = {
//   connections: new Map(),
//   chatRooms: new Map()
// };

// // MongoDB Connection
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

// // Initialize system with MongoDB
// async function initSystem() {
//   try {
//     // Check if admin user exists
//     let adminUser = await User.findOne({ username: 'admin' });
    
//     if (!adminUser) {
//       // Create admin user
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

//     // Create test users if they don't exist
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
//     console.log(`✅ Initialized MongoDB with ${userCount} users`);
//   } catch (error) {
//     console.error('❌ Error initializing system:', error);
//   }
// }

// // Middleware
// app.use(cors({ origin: '*', credentials: true }));
// app.use(express.json({ limit: '50mb' }));

// // Auth middleware
// const auth = async (req, res, next) => {
//   try {
//     const token = req.header('Authorization')?.replace('Bearer ', '');
//     if (!token) {
//       return res.status(401).json({ error: 'No token' });
//     }

//     const decoded = jwt.verify(token, JWT_SECRET);
//     const user = await User.findById(decoded.userId);
    
//     if (!user || user.status !== 'active') {
//       return res.status(401).json({ error: 'Invalid user' });
//     }

//     req.user = { userId: decoded.userId, username: decoded.username, role: decoded.role };
//     next();
//   } catch (error) {
//     res.status(401).json({ error: 'Invalid token' });
//   }
// };

// // API Routes

// app.get('/api/health', async (req, res) => {
//   try {
//     const userCount = await User.countDocuments();
//     const messageCount = await Message.countDocuments();
//     const groupCount = await Group.countDocuments();
    
//     res.json({
//       status: 'OK',
//       message: 'Hi Chat Ultimate Backend with MongoDB',
//       version: '2.1.0',
//       database: 'MongoDB Connected',
//       users: userCount,
//       messages: messageCount,
//       groups: groupCount,
//       connections: wsStorage.connections.size,
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

// app.post('/api/login', async (req, res) => {
//   try {
//     const { username, password } = req.body;
    
//     // Find user by username or email
//     const user = await User.findOne({
//       $or: [
//         { username: username.toLowerCase() },
//         { email: username.toLowerCase() }
//       ]
//     });

//     if (!user) {
//       return res.status(401).json({ error: 'Invalid credentials' });
//     }

//     // Check password
//     const isValidPassword = await bcrypt.compare(password, user.password);
//     if (!isValidPassword) {
//       return res.status(401).json({ error: 'Invalid credentials' });
//     }

//     // Update user online status
//     user.isOnline = true;
//     user.lastSeen = new Date();
//     await user.save();

//     const token = jwt.sign(
//       { userId: user._id, username: user.username, role: user.role },
//       JWT_SECRET,
//       { expiresIn: '30d' }
//     );

//     const userResponse = {
//       id: user._id,
//       name: user.name,
//       username: user.username,
//       email: user.email,
//       role: user.role,
//       profilePic: user.profilePic,
//       isOnline: user.isOnline
//     };

//     res.json({ success: true, token, user: userResponse });

//   } catch (error) {
//     console.error('Login error:', error);
//     res.status(500).json({ error: 'Login failed' });
//   }
// });

// app.get('/api/users', auth, async (req, res) => {
//   try {
//     const users = await User.find({}, '-password').lean();
//     res.json({ success: true, users });
//   } catch (error) {
//     res.status(500).json({ error: 'Failed to fetch users' });
//   }
// });

// app.post('/api/chats', auth, (req, res) => {
//   try {
//     const { participants, type = 'direct' } = req.body;

//     if (!participants || participants.length < 2) {
//       return res.status(400).json({ error: 'Need at least 2 participants' });
//     }

//     // Check for existing direct chat
//     if (type === 'direct') {
//       for (const [id, chat] of db.chats) {
//         if (chat.type === 'direct' && 
//             chat.participants.length === 2 &&
//             chat.participants.includes(participants[0]) &&
//             chat.participants.includes(participants[1])) {
//           return res.json({ success: true, chat, existing: true });
//         }
//       }
//     }

//     const chatId = 'chat-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
//     const chat = {
//       id: chatId,
//       participants,
//       type,
//       createdBy: req.user.userId,
//       lastMessage: null,
//       lastMessageTime: null,
//       isActive: true,
//       createdAt: new Date()
//     };

//     db.chats.set(chatId, chat);
//     db.chatRooms.set(chatId, new Set());

//     res.status(201).json({ success: true, chat });

//   } catch (error) {
//     res.status(500).json({ error: 'Failed to create chat' });
//   }
// });

// app.get('/api/chats/:userId', auth, (req, res) => {
//   try {
//     const userId = req.params.userId;
    
//     if (userId !== req.user.userId && req.user.role !== 'admin') {
//       return res.status(403).json({ error: 'Access denied' });
//     }

//     const chats = Array.from(db.chats.values())
//       .filter(chat => chat.participants.includes(userId) && chat.isActive)
//       .map(chat => {
//         const participants = chat.participants.map(id => {
//           const user = db.users.get(id);
//           return user ? { id: user.id, name: user.name, username: user.username, isOnline: user.isOnline } : null;
//         }).filter(Boolean);

//         return { ...chat, participantDetails: participants };
//       });

//     res.json({ success: true, chats });

//   } catch (error) {
//     res.status(500).json({ error: 'Failed to get chats' });
//   }
// });

// app.post('/api/messages', auth, (req, res) => {
//   try {
//     const { chatId, content, type = 'text' } = req.body;

//     if (!chatId || !content) {
//       return res.status(400).json({ error: 'Chat ID and content required' });
//     }

//     const chat = db.chats.get(chatId);
//     if (!chat || !chat.participants.includes(req.user.userId)) {
//       return res.status(403).json({ error: 'Invalid chat or access denied' });
//     }

//     const messageId = 'msg-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
//     const message = {
//       id: messageId,
//       chatId,
//       senderId: req.user.userId,
//       content,
//       type,
//       timestamp: new Date(),
//       isDeleted: false,
//       readBy: [req.user.userId]
//     };

//     db.messages.set(messageId, message);

//     // Update chat
//     chat.lastMessage = content;
//     chat.lastMessageTime = new Date();
//     db.chats.set(chatId, chat);

//     const sender = db.users.get(req.user.userId);
//     const messageWithSender = {
//       ...message,
//       senderName: sender?.name || 'Unknown'
//     };

//     // Broadcast via WebSocket
//     broadcastToChat(chatId, { type: 'new_message', ...messageWithSender });

//     res.status(201).json({ success: true, data: messageWithSender });

//   } catch (error) {
//     res.status(500).json({ error: 'Failed to send message' });
//   }
// });

// app.get('/api/messages/:chatId', auth, (req, res) => {
//   try {
//     const { chatId } = req.params;
//     const { limit = 50 } = req.query;

//     const chat = db.chats.get(chatId);
//     if (!chat || !chat.participants.includes(req.user.userId)) {
//       return res.status(403).json({ error: 'Access denied' });
//     }

//     const messages = Array.from(db.messages.values())
//       .filter(msg => msg.chatId === chatId && !msg.isDeleted)
//       .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
//       .slice(-parseInt(limit))
//       .map(msg => {
//         const sender = db.users.get(msg.senderId);
//         return { ...msg, senderName: sender?.name || 'Unknown' };
//       });

//     res.json({ success: true, messages });

//   } catch (error) {
//     res.status(500).json({ error: 'Failed to get messages' });
//   }
// });

// // WebSocket handlers
// async function broadcastToChat(chatId, message, excludeUserId = null) {
//   try {
//     // For MongoDB, we need to find participants differently
//     // This is a simplified approach - in production, you might want to store chat participants
//     const participants = wsStorage.chatRooms.get(chatId) || new Set();
    
//     participants.forEach(userId => {
//       if (userId !== excludeUserId) {
//         const ws = wsStorage.connections.get(userId);
//         if (ws && ws.readyState === WebSocket.OPEN) {
//           ws.send(JSON.stringify(message));
//         }
//       }
//     });
//   } catch (error) {
//     console.error('Broadcast error:', error);
//   }
// }

// function broadcastToUser(userId, message) {
//   const ws = wsStorage.connections.get(userId);
//   if (ws && ws.readyState === WebSocket.OPEN) {
//     ws.send(JSON.stringify(message));
//   }
// }

// // WebSocket connection handling
// wss.on('connection', (ws) => {
//   console.log('🔌 WebSocket connected');
  
//   let userId = null;

//   ws.on('message', async (data) => {
//     try {
//       const msg = JSON.parse(data);
      
//       switch (msg.type) {
//         case 'user_connected':
//           userId = msg.userId;
//           wsStorage.connections.set(userId, ws);
          
//           // Update user online status in MongoDB
//           try {
//             await User.findByIdAndUpdate(userId, {
//               isOnline: true,
//               lastSeen: new Date()
//             });
//           } catch (error) {
//             console.error('Error updating user status:', error);
//           }
          
//           ws.send(JSON.stringify({ type: 'connected', userId }));
//           console.log(`👤 User connected: ${msg.username}`);
//           break;

//         case 'join_chat':
//           const { chatId } = msg;
//           ws.currentChatId = chatId;
          
//           if (!wsStorage.chatRooms.has(chatId)) {
//             wsStorage.chatRooms.set(chatId, new Set());
//           }
//           wsStorage.chatRooms.get(chatId).add(userId);
          
//           ws.send(JSON.stringify({ type: 'chat_joined', chatId }));
//           console.log(`💬 User joined chat: ${chatId}`);
//           break;

//         case 'message':
//           console.log(`📨 Handling message from ${userId}: ${msg.message}`);
//           handleWSMessage(msg, userId);
//           break;

//         case 'typing':
//           broadcastToChat(msg.chatId, {
//             type: 'typing',
//             userId,
//             isTyping: msg.isTyping,
//             chatId: msg.chatId
//           }, userId);
//           break;

//         case 'call_user':
//           handleCallUser(msg, userId);
//           break;

//         case 'answer_call':
//           handleAnswerCall(msg, userId);
//           break;

//         case 'reject_call':
//           handleRejectCall(msg, userId);
//           break;

//         case 'end_call':
//           handleEndCall(msg, userId);
//           break;

//         case 'webrtc-signal':
//           handleWebRTCSignal(msg, userId);
//           break;
//       }
//     } catch (error) {
//       console.error('WebSocket error:', error);
//     }
//   });

//   ws.on('close', async () => {
//     if (userId) {
//       try {
//         await User.findByIdAndUpdate(userId, {
//           isOnline: false,
//           lastSeen: new Date()
//         });
//       } catch (error) {
//         console.error('Error updating user offline status:', error);
//       }
//       wsStorage.connections.delete(userId);
//     }
//     console.log('🔌 WebSocket disconnected');
//   });
// });

// function handleWSMessage(msg, senderId) {
//   const { chatId, message, timestamp } = msg;
  
//   console.log(`📨 Processing message: chatId=${chatId}, message="${message}", senderId=${senderId}`);
  
//   if (!chatId || !message) {
//     console.log('❌ Missing chatId or message content');
//     return;
//   }

//   const chat = db.chats.get(chatId);
//   if (!chat) {
//     console.log(`❌ Chat not found: ${chatId}`);
//     return;
//   }

//   if (!chat.participants.includes(senderId)) {
//     console.log(`❌ User ${senderId} not in chat ${chatId}`);
//     return;
//   }
  
//   const messageId = 'msg-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
//   const newMessage = {
//     id: messageId,
//     chatId,
//     senderId,
//     content: message,
//     type: 'text',
//     timestamp: new Date(timestamp || Date.now()),
//     isDeleted: false,
//     readBy: [senderId]
//   };

//   db.messages.set(messageId, newMessage);

//   chat.lastMessage = message;
//   chat.lastMessageTime = new Date();
//   db.chats.set(chatId, chat);

//   const sender = db.users.get(senderId);
//   const messageWithSender = {
//     type: 'new_message',
//     ...newMessage,
//     senderName: sender?.name || 'Unknown'
//   };

//   console.log(`📨 Broadcasting message ${messageId} to chat ${chatId}`);
//   broadcastToChat(chatId, messageWithSender);
// }

// function handleCallUser(msg, callerId) {
//   const { targetUserId, callId, callerName } = msg;
//   broadcastToUser(targetUserId, {
//     type: 'incoming_call',
//     callId,
//     callerUserId: callerId,
//     callerName
//   });
// }

// function handleAnswerCall(msg, userId) {
//   const { callId, targetUserId } = msg;
//   broadcastToUser(targetUserId, {
//     type: 'call_answered',
//     callId
//   });
// }

// function handleRejectCall(msg, userId) {
//   const { callId, targetUserId } = msg;
//   broadcastToUser(targetUserId, {
//     type: 'call_rejected',
//     callId
//   });
// }

// function handleEndCall(msg, userId) {
//   const { callId, targetUserId } = msg;
//   broadcastToUser(targetUserId, {
//     type: 'call_ended',
//     callId
//   });
// }

// function handleWebRTCSignal(msg, fromUserId) {
//   const { targetUserId, signal, callId } = msg;
//   broadcastToUser(targetUserId, {
//     type: 'webrtc-signal',
//     signal,
//     callId,
//     fromUserId
//   });
// }

// // Heartbeat for WebSocket connections
// setInterval(() => {
//   wss.clients.forEach(ws => {
//     if (ws.readyState === WebSocket.OPEN) {
//       ws.ping();
//     }
//   });
// }, 30000);

// // Error handling
// app.use((error, req, res, next) => {
//   console.error('Server error:', error);
//   res.status(500).json({ error: 'Internal server error' });
// });

// // Initialize and start
// async function startServer() {
//   try {
//     // Connect to MongoDB
//     await connectDB();
    
//     // Initialize system data
//     await initSystem();
    
//     // Start server
//     server.listen(PORT, () => {
//       console.log(`🚀 Hi Chat Ultimate Backend with MongoDB running on port ${PORT}`);
//       console.log(`📡 WebSocket server ready`);
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

// module.exports = { app, server, wss };






// // Ultimate Hi Chat Backend - Socket.IO + WebRTC + Messaging + MongoDB (Rooms Optimized)
// const express = require('express');
// const http = require('http');
// const { Server } = require('socket.io');
// const cors = require('cors');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcryptjs');
// const mongoose = require('mongoose');
// require('dotenv').config();

// // MongoDB models
// const User = require('./models/User');
// const Message = require('./models/Message');
// const Group = require('./models/Group');

// const app = express();
// const server = http.createServer(app);

// const io = new Server(server, {
//   cors: { origin: '*', methods: ['GET', 'POST'] },
//   maxHttpBufferSize: 10 * 1024 * 1024, // 10MB
// });

// const PORT = process.env.PORT || 3001;
// const JWT_SECRET = process.env.JWT_SECRET || 'hi-chat-ultimate-secret-2024';
// const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://ChatAppData:CHATAPPDATA@chatappdata.ua6pnti.mongodb.net/?retryWrites=true&w=majority&appName=ChatAppData';

// // MongoDB connection
// async function connectDB() {
//   try {
//     await mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
//     console.log('✅ MongoDB Connected Successfully');
//   } catch (error) {
//     console.error('❌ MongoDB Connection Error:', error.message);
//     process.exit(1);
//   }
// }

// // Initialize system
// async function initSystem() {
//   try {
//     let adminUser = await User.findOne({ username: 'admin' });
//     if (!adminUser) {
//       adminUser = new User({
//         name: 'Administrator',
//         username: 'admin',
//         email: 'admin@hichat.com',
//         password: await bcrypt.hash('admin123', 12),
//         role: 'admin',
//         status: 'active',
//       });
//       await adminUser.save();
//       console.log('✅ Admin user created');
//     }

//     const testUsers = [
//       { name: 'John Doe', username: 'john', email: 'john@test.com' },
//       { name: 'Jane Smith', username: 'jane', email: 'jane@test.com' },
//       { name: 'Bob Wilson', username: 'bob', email: 'bob@test.com' },
//     ];

//     for (const userData of testUsers) {
//       const exists = await User.findOne({ username: userData.username });
//       if (!exists) {
//         const user = new User({
//           ...userData,
//           password: await bcrypt.hash('password123', 12),
//           role: 'user',
//           status: 'active',
//         });
//         await user.save();
//         console.log(`✅ Test user created: ${userData.username}`);
//       }
//     }
//   } catch (error) {
//     console.error('❌ Error initializing system:', error);
//   }
// }

// // Middleware
// app.use(cors({ origin: '*', credentials: true }));
// app.use(express.json({ limit: '50mb' }));

// // Auth middleware
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

// // API Routes
// app.get('/api/health', async (req, res) => {
//   try {
//     const users = await User.countDocuments();
//     const messages = await Message.countDocuments();
//     const groups = await Group.countDocuments();
//     res.json({ status: 'OK', users, messages, groups, connections: io.sockets.sockets.size });
//   } catch (error) {
//     res.status(500).json({ status: 'ERROR', message: error.message });
//   }
// });

// app.post('/api/login', async (req, res) => {
//   try {
//     const { username, password } = req.body;
//     const user = await User.findOne({ $or: [{ username }, { email: username }] });
//     if (!user) return res.status(401).json({ error: 'Invalid credentials' });

//     const valid = await bcrypt.compare(password, user.password);
//     if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

//     user.isOnline = true;
//     user.lastSeen = new Date();
//     await user.save();

//     const token = jwt.sign({ userId: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
//     res.json({ success: true, token, user });
//   } catch (error) {
//     res.status(500).json({ error: 'Login failed' });
//   }
// });

// app.get('/api/users', auth, async (req, res) => {
//   try {
//     const users = await User.find({}, '-password');
//     res.json({ success: true, users });
//   } catch (error) {
//     res.status(500).json({ error: 'Failed to fetch users' });
//   }
// });

// // ========== Socket.IO Handlers ==========
// io.on('connection', (socket) => {
//   console.log('🔌 Socket connected');

//   let userId = null;

//   socket.on('user_connected', async (msg) => {
//     userId = msg.userId;
//     socket.userId = userId;

//     try {
//       await User.findByIdAndUpdate(userId, { isOnline: true, lastSeen: new Date() });
//     } catch (err) {
//       console.error(err);
//     }

//     socket.emit('connected', { userId });
//     console.log(`👤 User connected: ${msg.username}`);
//   });

//   socket.on('join_chat', async (msg) => {
//     const { chatId } = msg;
//     socket.join(chatId);
//     socket.emit('chat_joined', { chatId });
//     console.log(`💬 User joined chat: ${chatId}`);
//   });

//   socket.on('message', async (msg) => {
//     const { chatId, content } = msg;
//     if (!chatId || !content) return;

//     const newMessage = new Message({ chatId, senderId: userId, content, type: 'text', timestamp: new Date(), readBy: [userId] });
//     await newMessage.save();

//     io.to(chatId).emit('new_message', { ...newMessage.toObject(), senderName: (await User.findById(userId)).name });
//   });

//   socket.on('typing', (msg) => {
//     const { chatId, isTyping } = msg;
//     socket.to(chatId).emit('typing', { userId, isTyping });
//   });

//   // Calls & WebRTC
//   socket.on('call_user', (msg) => io.to(msg.targetUserId).emit('incoming_call', { ...msg, callerUserId: userId }));
//   socket.on('answer_call', (msg) => io.to(msg.targetUserId).emit('call_answered', msg));
//   socket.on('reject_call', (msg) => io.to(msg.targetUserId).emit('call_rejected', msg));
//   socket.on('end_call', (msg) => io.to(msg.targetUserId).emit('call_ended', msg));
//   socket.on('webrtc-signal', (msg) => io.to(msg.targetUserId).emit('webrtc-signal', { ...msg, fromUserId: userId }));

//   socket.on('disconnect', async () => {
//     if (userId) {
//       await User.findByIdAndUpdate(userId, { isOnline: false, lastSeen: new Date() });
//       console.log(`👤 User disconnected: ${userId}`);
//     }
//   });
// });

// // Start server
// async function startServer() {
//   await connectDB();
//   await initSystem();
//   server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
// }

// startServer();

// module.exports = { app, server, io };




















require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

// Models
const User = require('./models/User');
const Message = require('./models/Message');
const Group = require('./models/Group');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  maxHttpBufferSize: 10 * 1024 * 1024, // 10MB
});

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'hi-chat-ultimate-secret-2024';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/hichat';

// ---------- MongoDB Connection ----------
async function connectDB() {
  try {
    await mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
    console.log('✅ MongoDB Connected');
  } catch (err) {
    console.error('❌ MongoDB Connection Error:', err.message);
    process.exit(1);
  }
}

// ---------- Initialize Admin & Test Users ----------
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
        status: 'active',
      });
      await admin.save();
      console.log('✅ Admin created');
    }

    const testUsers = [
      { name: 'John Doe', username: 'john', email: 'john@test.com' },
      { name: 'Jane Smith', username: 'jane', email: 'jane@test.com' },
      { name: 'Bob Wilson', username: 'bob', email: 'bob@test.com' },
    ];

    for (const u of testUsers) {
      const exists = await User.findOne({ username: u.username });
      if (!exists) {
        const user = new User({
          ...u,
          password: await bcrypt.hash('password123', 12),
          role: 'user',
          status: 'active',
        });
        await user.save();
        console.log(`✅ Test user created: ${u.username}`);
      }
    }
  } catch (err) {
    console.error('❌ Init Error:', err);
  }
}

// ---------- Middleware ----------
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '50mb' }));

// ---------- Auth Middleware ----------
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || user.status !== 'active') return res.status(401).json({ error: 'Invalid user' });

    req.user = { userId: decoded.userId, username: decoded.username, role: decoded.role };
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ---------- API Routes ----------
app.get('/api/health', async (req, res) => {
  try {
    const users = await User.countDocuments();
    const messages = await Message.countDocuments();
    const groups = await Group.countDocuments();
    res.json({ status: 'OK', users, messages, groups, connections: io.sockets.sockets.size });
  } catch (err) {
    res.status(500).json({ status: 'ERROR', message: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ $or: [{ username }, { email: username }] });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    user.isOnline = true;
    user.lastSeen = new Date();
    await user.save();

    const token = jwt.sign({ userId: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/users', auth, async (req, res) => {
  try {
    const users = await User.find({}, '-password');
    res.json({ success: true, users });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// ---------- Socket.IO Handlers ----------
io.on('connection', (socket) => {
  console.log('🔌 Socket connected');
  let userId = null;

  // User connected
  socket.on('user_connected', async (msg) => {
    userId = msg.userId;
    socket.userId = userId;
    try {
      await User.findByIdAndUpdate(userId, { isOnline: true, lastSeen: new Date() });
      socket.emit('connected', { userId });
      console.log(`👤 User connected: ${msg.username}`);
    } catch (err) { console.error(err); }
  });

  // Join chat room
  socket.on('join_chat', async ({ chatId }) => {
    socket.join(chatId);
    socket.emit('chat_joined', { chatId });
    console.log(`💬 User joined chat: ${chatId}`);
  });

  // Send message
  socket.on('message', async ({ chatId, content }) => {
    if (!chatId || !content) return;
    const newMessage = new Message({
      chatId,
      senderId: userId,
      content,
      type: 'text',
      timestamp: new Date(),
      readBy: [userId],
    });
    await newMessage.save();

    const sender = await User.findById(userId);
    io.to(chatId).emit('new_message', { ...newMessage.toObject(), senderName: sender.name });
  });

  // Typing indicator
  socket.on('typing', ({ chatId, isTyping }) => {
    socket.to(chatId).emit('typing', { userId, isTyping });
  });

  // Read message
  socket.on('read_message', async ({ chatId, messageId }) => {
    try {
      const message = await Message.findById(messageId);
      if (!message) return;
      if (!message.readBy.includes(userId)) {
        message.readBy.push(userId);
        await message.save();
      }
      io.to(chatId).emit('message_read', { messageId, userId });
    } catch (err) { console.error(err); }
  });

  // Create group
  socket.on('create_group', async ({ name, members }) => {
    try {
      if (!name || !members || !members.length) return;
      const group = new Group({ name, members: [...members, userId], createdBy: userId });
      await group.save();

      group.members.forEach(id => {
        const sockets = Array.from(io.sockets.sockets.values()).filter(s => s.userId === id);
        sockets.forEach(s => s.join(group._id.toString()));
      });

      group.members.forEach(id => {
        const sockets = Array.from(io.sockets.sockets.values()).filter(s => s.userId === id);
        sockets.forEach(s => s.emit('new_group', group));
      });
    } catch (err) { console.error(err); }
  });

  // WebRTC / Calls
  socket.on('call_user', (msg) => io.to(msg.targetUserId).emit('incoming_call', { ...msg, callerUserId: userId }));
  socket.on('answer_call', (msg) => io.to(msg.targetUserId).emit('call_answered', msg));
  socket.on('reject_call', (msg) => io.to(msg.targetUserId).emit('call_rejected', msg));
  socket.on('end_call', (msg) => io.to(msg.targetUserId).emit('call_ended', msg));
  socket.on('webrtc-signal', (msg) => io.to(msg.targetUserId).emit('webrtc-signal', { ...msg, fromUserId: userId }));

  // Disconnect
  socket.on('disconnect', async () => {
    if (userId) {
      await User.findByIdAndUpdate(userId, { isOnline: false, lastSeen: new Date() });
      console.log(`👤 User disconnected: ${userId}`);
    }
  });
});

// ---------- Start Server ----------
async function startServer() {
  await connectDB();
  await initSystem();
  server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
}

startServer();

module.exports = { app, server, io };

