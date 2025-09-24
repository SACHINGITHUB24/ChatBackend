// Hi Chat Ultimate Backend - Node.js + Express + WebSocket + WebRTC + MongoDB
require("dotenv").config();
const express = require("express");
const http = require("http");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const WebSocket = require("ws");

// ---------------------------------
// Config
// ---------------------------------
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "hi-chat-ultimate-secret-2024";
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/hichat";

// ---------------------------------
// MongoDB Setup
// ---------------------------------
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
mongoose.connection.once("open", () => {
  console.log("✅ MongoDB connected");
});

// User schema
const UserSchema = new mongoose.Schema({
  name: String,
  username: { type: String, unique: true },
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: "user" },
  isOnline: { type: Boolean, default: false },
  status: { type: String, default: "active" },
  createdAt: { type: Date, default: Date.now },
  lastSeen: Date,
});
const User = mongoose.model("User", UserSchema);

// Chat schema
const ChatSchema = new mongoose.Schema({
  participants: [String], // store user IDs
  type: { type: String, default: "direct" },
  createdBy: String,
  lastMessage: String,
  lastMessageTime: Date,
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
});
const Chat = mongoose.model("Chat", ChatSchema);

// Message schema
const MessageSchema = new mongoose.Schema({
  chatId: String,
  senderId: String,
  content: String,
  type: { type: String, default: "text" },
  timestamp: { type: Date, default: Date.now },
  isDeleted: { type: Boolean, default: false },
  readBy: [String],
});
const Message = mongoose.model("Message", MessageSchema);

// ---------------------------------
// Express + Middleware
// ---------------------------------
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, clientTracking: true });

app.use(cors({ origin: "*", credentials: true }));
app.use(express.json({ limit: "50mb" }));

// Auth middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");
    if (!token) return res.status(401).json({ error: "No token" });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || user.status !== "active") {
      return res.status(401).json({ error: "Invalid user" });
    }

    req.user = { userId: user._id.toString(), username: user.username, role: user.role };
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// ---------------------------------
// API Routes
// ---------------------------------

// Health
app.get("/api/health", async (req, res) => {
  const users = await User.countDocuments();
  const chats = await Chat.countDocuments();
  const messages = await Message.countDocuments();
  res.json({
    status: "OK",
    version: "3.0.0",
    users,
    chats,
    messages,
    timestamp: new Date().toISOString(),
  });
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ $or: [{ username }, { email: username }] });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    user.isOnline = true;
    user.lastSeen = new Date();
    await user.save();

    const { password: _, ...userData } = user.toObject();
    res.json({ success: true, token, user: userData });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

// Get Users
app.get("/api/users", auth, async (req, res) => {
  const users = await User.find({}, "-password");
  res.json({ success: true, users });
});

// Create Chat
app.post("/api/chats", auth, async (req, res) => {
  try {
    const { participants, type = "direct" } = req.body;
    if (!participants || participants.length < 2) {
      return res.status(400).json({ error: "Need at least 2 participants" });
    }

    if (type === "direct") {
      const existing = await Chat.findOne({
        type: "direct",
        participants: { $all: participants, $size: 2 },
      });
      if (existing) return res.json({ success: true, chat: existing, existing: true });
    }

    const chat = new Chat({ participants, type, createdBy: req.user.userId });
    await chat.save();
    res.status(201).json({ success: true, chat });
  } catch (err) {
    res.status(500).json({ error: "Failed to create chat" });
  }
});

// Get Chats
app.get("/api/chats/:userId", auth, async (req, res) => {
  try {
    const { userId } = req.params;
    if (userId !== req.user.userId && req.user.role !== "admin") {
      return res.status(403).json({ error: "Access denied" });
    }

    const chats = await Chat.find({ participants: userId, isActive: true });
    res.json({ success: true, chats });
  } catch (err) {
    res.status(500).json({ error: "Failed to get chats" });
  }
});

// Send Message
app.post("/api/messages", auth, async (req, res) => {
  try {
    const { chatId, content, type = "text" } = req.body;
    if (!chatId || !content) return res.status(400).json({ error: "Chat ID and content required" });

    const chat = await Chat.findById(chatId);
    if (!chat || !chat.participants.includes(req.user.userId)) {
      return res.status(403).json({ error: "Invalid chat or access denied" });
    }

    const msg = new Message({
      chatId,
      senderId: req.user.userId,
      content,
      type,
      readBy: [req.user.userId],
    });
    await msg.save();

    chat.lastMessage = content;
    chat.lastMessageTime = new Date();
    await chat.save();

    const messageWithSender = { ...msg.toObject(), senderName: req.user.username };

    broadcastToChat(chatId, { type: "new_message", ...messageWithSender });
    res.status(201).json({ success: true, data: messageWithSender });
  } catch (err) {
    res.status(500).json({ error: "Failed to send message" });
  }
});

// Get Messages
app.get("/api/messages/:chatId", auth, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { limit = 50 } = req.query;

    const chat = await Chat.findById(chatId);
    if (!chat || !chat.participants.includes(req.user.userId)) {
      return res.status(403).json({ error: "Access denied" });
    }

    const messages = await Message.find({ chatId, isDeleted: false })
      .sort({ timestamp: 1 })
      .limit(parseInt(limit));

    res.json({ success: true, messages });
  } catch (err) {
    res.status(500).json({ error: "Failed to get messages" });
  }
});

// ---------------------------------
// WebSocket Logic
// ---------------------------------
const connections = new Map();

function broadcastToChat(chatId, message, excludeUserId = null) {
  connections.forEach((ws, uid) => {
    if (uid !== excludeUserId) {
      ws.send(JSON.stringify(message));
    }
  });
}

function broadcastToUser(userId, message) {
  const ws = connections.get(userId);
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(message));
  }
}

wss.on("connection", (ws) => {
  let userId = null;

  ws.on("message", async (data) => {
    try {
      const msg = JSON.parse(data);

      switch (msg.type) {
        case "user_connected":
          userId = msg.userId;
          connections.set(userId, ws);
          await User.findByIdAndUpdate(userId, { isOnline: true, lastSeen: new Date() });
          ws.send(JSON.stringify({ type: "connected", userId }));
          break;

        case "join_chat":
          ws.currentChatId = msg.chatId;
          ws.send(JSON.stringify({ type: "chat_joined", chatId: msg.chatId }));
          break;

        case "typing":
          broadcastToChat(msg.chatId, { type: "typing", userId, isTyping: msg.isTyping, chatId: msg.chatId }, userId);
          break;

        case "call_user":
          broadcastToUser(msg.targetUserId, {
            type: "incoming_call",
            callId: msg.callId,
            callerUserId: userId,
            callerName: msg.callerName,
          });
          break;

        case "answer_call":
          broadcastToUser(msg.targetUserId, { type: "call_answered", callId: msg.callId });
          break;

        case "reject_call":
          broadcastToUser(msg.targetUserId, { type: "call_rejected", callId: msg.callId });
          break;

        case "end_call":
          broadcastToUser(msg.targetUserId, { type: "call_ended", callId: msg.callId });
          break;

        case "webrtc-signal":
          broadcastToUser(msg.targetUserId, {
            type: "webrtc-signal",
            signal: msg.signal,
            callId: msg.callId,
            fromUserId: userId,
          });
          break;
      }
    } catch (err) {
      console.error("WebSocket error:", err);
    }
  });

  ws.on("close", async () => {
    if (userId) {
      await User.findByIdAndUpdate(userId, { isOnline: false, lastSeen: new Date() });
      connections.delete(userId);
    }
  });
});

// Heartbeat
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) ws.ping();
  });
}, 30000);

// ---------------------------------
// Start Server
// ---------------------------------
async function initAdmin() {
  const adminExists = await User.findOne({ username: "admin" });
  if (!adminExists) {
    const hashed = await bcrypt.hash("admin123", 10);
    await User.create({
      name: "Administrator",
      username: "admin",
      email: "admin@hichat.com",
      password: hashed,
      role: "admin",
    });
    console.log("🔑 Admin user created: admin / admin123");
  }
}

server.listen(PORT, async () => {
  await initAdmin();
  console.log(`🚀 Hi Chat Ultimate Backend running on port ${PORT}`);
  console.log(`📡 WebSocket server ready`);
  console.log(`🌐 API: http://localhost:${PORT}/api`);
});
