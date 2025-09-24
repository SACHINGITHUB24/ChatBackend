// Ultimate Hi Chat Backend - WebSocket + WebRTC + Messaging
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

// WebSocket server with proper configuration
const wss = new WebSocket.Server({ 
  server,
  perMessageDeflate: false,
  clientTracking: true,
  maxPayload: 10 * 1024 * 1024 // 10MB
});

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'hi-chat-ultimate-secret-2024';

// Enhanced storage
const db = {
  users: new Map(),
  chats: new Map(),
  messages: new Map(),
  connections: new Map(),
  chatRooms: new Map()
};

// Initialize system
function initSystem() {
  // Admin
  const adminId = 'admin-' + Date.now();
  db.users.set(adminId, {
    id: adminId,
    name: 'Administrator',
    username: 'admin',
    email: 'admin@hichat.com',
    password: bcrypt.hashSync('admin123', 10),
    role: 'admin',
    isOnline: false,
    status: 'active',
    createdAt: new Date()
  });

  // Test users
  const users = [
    { name: 'John Doe', username: 'john', email: 'john@test.com' },
    { name: 'Jane Smith', username: 'jane', email: 'jane@test.com' },
    { name: 'Bob Wilson', username: 'bob', email: 'bob@test.com' }
  ];

  users.forEach(user => {
    const id = user.username + '-' + Date.now();
    db.users.set(id, {
      id,
      ...user,
      password: bcrypt.hashSync('password123', 10),
      role: 'user',
      isOnline: false,
      status: 'active',
      createdAt: new Date()
    });
  });

  console.log(`✅ Initialized ${db.users.size} users`);
}

// Middleware
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '50mb' }));

// Auth middleware
const auth = (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'No token' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = db.users.get(decoded.userId);
    
    if (!user || user.status !== 'active') {
      return res.status(401).json({ error: 'Invalid user' });
    }

    req.user = { userId: decoded.userId, username: decoded.username, role: decoded.role };
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// API Routes

app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Hi Chat Ultimate Backend',
    version: '2.0.0',
    users: db.users.size,
    chats: db.chats.size,
    messages: db.messages.size,
    connections: db.connections.size,
    timestamp: new Date().toISOString()
  });
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    let user = null;
    for (const [id, userData] of db.users) {
      if (userData.username === username || userData.email === username) {
        user = { id, ...userData };
        break;
      }
    }

    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    // Update user
    const userData = db.users.get(user.id);
    userData.isOnline = true;
    userData.lastSeen = new Date();
    db.users.set(user.id, userData);

    const { password: _, ...userResponse } = user;
    res.json({ success: true, token, user: userResponse });

  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/users', auth, (req, res) => {
  const users = Array.from(db.users.values()).map(({ password, ...user }) => user);
  res.json({ success: true, users });
});

app.post('/api/chats', auth, (req, res) => {
  try {
    const { participants, type = 'direct' } = req.body;

    if (!participants || participants.length < 2) {
      return res.status(400).json({ error: 'Need at least 2 participants' });
    }

    // Check for existing direct chat
    if (type === 'direct') {
      for (const [id, chat] of db.chats) {
        if (chat.type === 'direct' && 
            chat.participants.length === 2 &&
            chat.participants.includes(participants[0]) &&
            chat.participants.includes(participants[1])) {
          return res.json({ success: true, chat, existing: true });
        }
      }
    }

    const chatId = 'chat-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
    const chat = {
      id: chatId,
      participants,
      type,
      createdBy: req.user.userId,
      lastMessage: null,
      lastMessageTime: null,
      isActive: true,
      createdAt: new Date()
    };

    db.chats.set(chatId, chat);
    db.chatRooms.set(chatId, new Set());

    res.status(201).json({ success: true, chat });

  } catch (error) {
    res.status(500).json({ error: 'Failed to create chat' });
  }
});

app.get('/api/chats/:userId', auth, (req, res) => {
  try {
    const userId = req.params.userId;
    
    if (userId !== req.user.userId && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const chats = Array.from(db.chats.values())
      .filter(chat => chat.participants.includes(userId) && chat.isActive)
      .map(chat => {
        const participants = chat.participants.map(id => {
          const user = db.users.get(id);
          return user ? { id: user.id, name: user.name, username: user.username, isOnline: user.isOnline } : null;
        }).filter(Boolean);

        return { ...chat, participantDetails: participants };
      });

    res.json({ success: true, chats });

  } catch (error) {
    res.status(500).json({ error: 'Failed to get chats' });
  }
});

app.post('/api/messages', auth, (req, res) => {
  try {
    const { chatId, content, type = 'text' } = req.body;

    if (!chatId || !content) {
      return res.status(400).json({ error: 'Chat ID and content required' });
    }

    const chat = db.chats.get(chatId);
    if (!chat || !chat.participants.includes(req.user.userId)) {
      return res.status(403).json({ error: 'Invalid chat or access denied' });
    }

    const messageId = 'msg-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
    const message = {
      id: messageId,
      chatId,
      senderId: req.user.userId,
      content,
      type,
      timestamp: new Date(),
      isDeleted: false,
      readBy: [req.user.userId]
    };

    db.messages.set(messageId, message);

    // Update chat
    chat.lastMessage = content;
    chat.lastMessageTime = new Date();
    db.chats.set(chatId, chat);

    const sender = db.users.get(req.user.userId);
    const messageWithSender = {
      ...message,
      senderName: sender?.name || 'Unknown'
    };

    // Broadcast via WebSocket
    broadcastToChat(chatId, { type: 'new_message', ...messageWithSender });

    res.status(201).json({ success: true, data: messageWithSender });

  } catch (error) {
    res.status(500).json({ error: 'Failed to send message' });
  }
});

app.get('/api/messages/:chatId', auth, (req, res) => {
  try {
    const { chatId } = req.params;
    const { limit = 50 } = req.query;

    const chat = db.chats.get(chatId);
    if (!chat || !chat.participants.includes(req.user.userId)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const messages = Array.from(db.messages.values())
      .filter(msg => msg.chatId === chatId && !msg.isDeleted)
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
      .slice(-parseInt(limit))
      .map(msg => {
        const sender = db.users.get(msg.senderId);
        return { ...msg, senderName: sender?.name || 'Unknown' };
      });

    res.json({ success: true, messages });

  } catch (error) {
    res.status(500).json({ error: 'Failed to get messages' });
  }
});

// WebSocket handlers
function broadcastToChat(chatId, message, excludeUserId = null) {
  const chat = db.chats.get(chatId);
  if (!chat) return;

  chat.participants.forEach(userId => {
    if (userId !== excludeUserId) {
      const ws = db.connections.get(userId);
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(message));
      }
    }
  });
}

function broadcastToUser(userId, message) {
  const ws = db.connections.get(userId);
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(message));
  }
}

// WebSocket connection handling
wss.on('connection', (ws) => {
  console.log('🔌 WebSocket connected');
  
  let userId = null;

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data);
      
      switch (msg.type) {
        case 'user_connected':
          userId = msg.userId;
          db.connections.set(userId, ws);
          
          const user = db.users.get(userId);
          if (user) {
            user.isOnline = true;
            user.lastSeen = new Date();
            db.users.set(userId, user);
          }
          
          ws.send(JSON.stringify({ type: 'connected', userId }));
          console.log(`👤 User connected: ${msg.username}`);
          break;

        case 'join_chat':
          const { chatId } = msg;
          ws.currentChatId = chatId;
          
          if (!db.chatRooms.has(chatId)) {
            db.chatRooms.set(chatId, new Set());
          }
          db.chatRooms.get(chatId).add(userId);
          
          ws.send(JSON.stringify({ type: 'chat_joined', chatId }));
          console.log(`💬 User joined chat: ${chatId}`);
          break;

        case 'message':
          console.log(`📨 Handling message from ${userId}: ${msg.message}`);
          handleWSMessage(msg, userId);
          break;

        case 'typing':
          broadcastToChat(msg.chatId, {
            type: 'typing',
            userId,
            isTyping: msg.isTyping,
            chatId: msg.chatId
          }, userId);
          break;

        case 'call_user':
          handleCallUser(msg, userId);
          break;

        case 'answer_call':
          handleAnswerCall(msg, userId);
          break;

        case 'reject_call':
          handleRejectCall(msg, userId);
          break;

        case 'end_call':
          handleEndCall(msg, userId);
          break;

        case 'webrtc-signal':
          handleWebRTCSignal(msg, userId);
          break;
      }
    } catch (error) {
      console.error('WebSocket error:', error);
    }
  });

  ws.on('close', () => {
    if (userId) {
      const user = db.users.get(userId);
      if (user) {
        user.isOnline = false;
        user.lastSeen = new Date();
        db.users.set(userId, user);
      }
      db.connections.delete(userId);
    }
    console.log('🔌 WebSocket disconnected');
  });
});

function handleWSMessage(msg, senderId) {
  const { chatId, message, timestamp } = msg;
  
  console.log(`📨 Processing message: chatId=${chatId}, message="${message}", senderId=${senderId}`);
  
  if (!chatId || !message) {
    console.log('❌ Missing chatId or message content');
    return;
  }

  const chat = db.chats.get(chatId);
  if (!chat) {
    console.log(`❌ Chat not found: ${chatId}`);
    return;
  }

  if (!chat.participants.includes(senderId)) {
    console.log(`❌ User ${senderId} not in chat ${chatId}`);
    return;
  }
  
  const messageId = 'msg-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
  const newMessage = {
    id: messageId,
    chatId,
    senderId,
    content: message,
    type: 'text',
    timestamp: new Date(timestamp || Date.now()),
    isDeleted: false,
    readBy: [senderId]
  };

  db.messages.set(messageId, newMessage);

  chat.lastMessage = message;
  chat.lastMessageTime = new Date();
  db.chats.set(chatId, chat);

  const sender = db.users.get(senderId);
  const messageWithSender = {
    type: 'new_message',
    ...newMessage,
    senderName: sender?.name || 'Unknown'
  };

  console.log(`📨 Broadcasting message ${messageId} to chat ${chatId}`);
  broadcastToChat(chatId, messageWithSender);
}

function handleCallUser(msg, callerId) {
  const { targetUserId, callId, callerName } = msg;
  broadcastToUser(targetUserId, {
    type: 'incoming_call',
    callId,
    callerUserId: callerId,
    callerName
  });
}

function handleAnswerCall(msg, userId) {
  const { callId, targetUserId } = msg;
  broadcastToUser(targetUserId, {
    type: 'call_answered',
    callId
  });
}

function handleRejectCall(msg, userId) {
  const { callId, targetUserId } = msg;
  broadcastToUser(targetUserId, {
    type: 'call_rejected',
    callId
  });
}

function handleEndCall(msg, userId) {
  const { callId, targetUserId } = msg;
  broadcastToUser(targetUserId, {
    type: 'call_ended',
    callId
  });
}

function handleWebRTCSignal(msg, fromUserId) {
  const { targetUserId, signal, callId } = msg;
  broadcastToUser(targetUserId, {
    type: 'webrtc-signal',
    signal,
    callId,
    fromUserId
  });
}

// Heartbeat for WebSocket connections
setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.ping();
    }
  });
}, 30000);

// Error handling
app.use((error, req, res, next) => {
  console.error('Server error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// Initialize and start
initSystem();

server.listen(PORT, () => {
  console.log(`🚀 Hi Chat Ultimate Backend running on port ${PORT}`);
  console.log(`📡 WebSocket server ready`);
  console.log(`🌐 API: http://localhost:${PORT}/api`);
  console.log(`💾 Storage: ${db.users.size} users initialized`);
  console.log(`🔑 Admin: admin/admin123`);
});

module.exports = { app, server, wss };
