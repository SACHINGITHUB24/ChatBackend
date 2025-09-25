const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const mongoose = require('mongoose');
require('dotenv').config();

// Import DB and models
const { connectDB } = require('./config/database');
const User = require('./models/User');
const Message = require('./models/Message');
const Group = require('./models/Group');

// Connect to MongoDB
connectDB().then(() => console.log('MongoDB connected'))
           .catch(err => console.error('DB connection error:', err));

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET","POST"] }
});

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 50*1024*1024 } });

// JWT
const JWT_SECRET = process.env.JWT_SECRET || 'secret-key';
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// ------------------- ROUTES -------------------

// Health check
app.get('/api/health', async (req,res)=>{
  try{
    const userCount = await User.countDocuments();
    res.json({ status:'OK', userCount, timestamp:new Date() });
  } catch(e){
    res.status(500).json({ status:'ERROR', message:e.message });
  }
});

// Login
app.post('/api/login', async (req,res)=>{
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if(!user) return res.status(400).json({ error:'Invalid credentials' });
  const valid = await bcrypt.compare(password,user.password);
  if(!valid) return res.status(400).json({ error:'Invalid credentials' });
  user.isOnline = true; user.lastSeen = new Date(); await user.save();
  const token = jwt.sign({ userId:user._id, username:user.username }, JWT_SECRET);
  res.json({ token, user: { id:user._id, username:user.username, name:user.name, profilePic:user.profilePic } });
});

// ------------------- SOCKET.IO -------------------

const connectedUsers = new Map(); // socketId -> { userId, username }
const activeCalls = new Map(); // callId -> { caller, callee, status }

io.on('connection', socket => {
  console.log('Connected:', socket.id);

  socket.on('user_connected', async ({ token }) => {
    try{
      const payload = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(payload.userId);
      if(!user) return;
      connectedUsers.set(socket.id, { userId:user._id.toString(), username:user.username });
      await User.findByIdAndUpdate(user._id,{ isOnline:true });
      socket.broadcast.emit('user_online', { userId:user._id, username:user.username });
      console.log(`User connected: ${user.username}`);
    }catch(e){ console.error(e); }
  });

  // Send message
  socket.on('send_message', async ({ chatId, text, groupId }) => {
    try{
      const userData = connectedUsers.get(socket.id);
      if(!userData) return;
      const message = new Message({
        chatId,
        senderId: mongoose.Types.ObjectId(userData.userId),
        text,
        type:'text',
        groupId: groupId ? mongoose.Types.ObjectId(groupId) : undefined,
        timestamp: new Date()
      });
      await message.save();
      await message.populate('senderId','name username profilePic');
      if(groupId) io.to(groupId).emit('new_message', message);
      else io.emit('new_message', message);
    }catch(e){ console.error('Send message error:', e); }
  });

  // Join group
  socket.on('join_group', (groupId)=>{ socket.join(groupId); console.log(socket.id,'joined',groupId); });

  // Typing indicator
  socket.on('typing', ({ chatId, isTyping }) => {
    const userData = connectedUsers.get(socket.id);
    if(!userData) return;
    socket.broadcast.emit('typing',{ chatId, userId:userData.userId, isTyping });
  });

  // WebRTC signaling
  socket.on('webrtc-signal', data => {
    const { type, to, from, callId, signal } = data;
    const targetSocket = Array.from(connectedUsers.entries()).find(([id,u])=>u.userId===to)?.[0];
    if(!targetSocket) return;
    switch(type){
      case 'call-offer':
        activeCalls.set(callId,{ caller:from, callee:to, status:'calling' });
        io.to(targetSocket).emit('webrtc-signal',{ type:'call-offer', data });
        break;
      case 'call-answer':
        activeCalls.set(callId,{ ...activeCalls.get(callId), status:'connected' });
        io.to(targetSocket).emit('webrtc-signal',{ type:'call-answer', data });
        break;
      case 'ice-candidate': io.to(targetSocket).emit('webrtc-signal',{ type:'ice-candidate', data }); break;
      case 'call-end': case 'call-reject':
        io.to(targetSocket).emit('webrtc-signal',{ type, data });
        activeCalls.delete(callId); break;
    }
  });

  socket.on('disconnect', async () => {
    const user = connectedUsers.get(socket.id);
    if(user){
      await User.findByIdAndUpdate(user.userId,{ isOnline:false, lastSeen:new Date() });
      socket.broadcast.emit('user_offline',{ userId:user.userId });
      connectedUsers.delete(socket.id);

      // End active calls if disconnected
      for(const [callId,call] of activeCalls.entries()){
        if(call.caller===user.userId || call.callee===user.userId){
          const otherId = call.caller===user.userId?call.callee:call.caller;
          const otherSocket = Array.from(connectedUsers.entries()).find(([id,u])=>u.userId===otherId)?.[0];
          if(otherSocket) io.to(otherSocket).emit('webrtc-signal',{ type:'call-end', data:{ callId, reason:'user_disconnected' } });
          activeCalls.delete(callId);
        }
      }
    }
    console.log('Disconnected:', socket.id);
  });
});

// ------------------- SERVER -------------------

const PORT = process.env.PORT || 3000;
server.listen(PORT,()=>console.log(`Server running on port ${PORT}`));
