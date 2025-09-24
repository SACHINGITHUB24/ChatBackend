# Hi Chat Backend

A comprehensive Node.js backend server for the Hi Chat application, featuring real-time messaging, voice calls, file sharing, and group management.

## 🚀 Features

### Core Features
- **Real-time Messaging** - WebSocket-based instant messaging
- **One-to-One Chats** - Direct messaging between users
- **Group Chats** - Multi-user group conversations
- **Voice Calls** - WebRTC-based audio calling
- **File Sharing** - Upload and share images, documents, audio, and video
- **User Management** - Complete user registration, authentication, and profiles
- **Admin Panel** - Administrative controls for user and group management

### Advanced Features
- **Message Reactions** - Emoji reactions to messages
- **Message Editing** - Edit sent messages within time limit
- **Message Replies** - Reply to specific messages
- **Read Receipts** - Track message read status
- **Typing Indicators** - Real-time typing status
- **Online Presence** - User online/offline status
- **File Upload** - Multi-format file support with size limits
- **Search** - Search users and groups
- **Notifications** - Real-time push notifications

## 🛠️ Technology Stack

- **Runtime**: Node.js 16+
- **Framework**: Express.js
- **Database**: MongoDB with Mongoose ODM
- **Real-time**: Socket.IO for WebSocket connections
- **Authentication**: JWT (JSON Web Tokens)
- **File Upload**: Multer with local storage
- **Security**: bcryptjs for password hashing
- **CORS**: Cross-origin resource sharing enabled

## 📋 Prerequisites

- Node.js 16.0.0 or higher
- npm 8.0.0 or higher
- MongoDB database (local or cloud)

## 🚀 Quick Start

### 1. Installation

```bash
# Navigate to backend directory
cd backend

# Install dependencies
npm install
```

### 2. Environment Setup

```bash
# Copy environment template
cp .env.example .env

# Edit .env file with your configuration
nano .env
```

### 3. Database Configuration

Update the MongoDB URI in `.env`:

```env
# For local MongoDB
MONGODB_URI=mongodb://localhost:27017/hichat

# For MongoDB Atlas (cloud)
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/hichat
```

### 4. Start the Server

```bash
# Development mode (with auto-restart)
npm run dev

# Production mode
npm start
```

The server will start on `http://localhost:3000` (or your configured PORT).

## 📡 API Endpoints

### Authentication
- `POST /api/login` - User login
- `POST /api/logout` - User logout
- `GET /api/profile` - Get current user profile
- `PUT /api/profile` - Update user profile
- `PUT /api/change-password` - Change password
- `GET /api/verify-token` - Verify JWT token

### User Management
- `GET /api/users` - Get all users (with search)
- `GET /api/users/:userId` - Get user by ID
- `POST /api/admin/users` - Create new user (admin only)
- `PUT /api/admin/users/:userId` - Update user (admin only)
- `DELETE /api/admin/users/:userId` - Delete user (admin only)
- `PUT /api/admin/users/:userId/reset-password` - Reset user password (admin only)
- `GET /api/users/online` - Get online users
- `PUT /api/users/status` - Update user online status

### Chat Management
- `GET /api/chats/:userId` - Get user's chats
- `POST /api/chats` - Create new chat
- `GET /api/chats/details/:chatId` - Get chat details
- `PUT /api/chats/:chatId` - Update chat settings
- `DELETE /api/chats/:chatId` - Archive chat
- `POST /api/chats/:chatId/participants` - Add participant
- `DELETE /api/chats/:chatId/participants/:userId` - Remove participant

### Messages
- `GET /api/messages/:chatId` - Get chat messages
- `POST /api/messages` - Send new message
- `PUT /api/messages/:messageId` - Edit message
- `DELETE /api/messages/:messageId` - Delete message
- `POST /api/messages/:messageId/reactions` - Add reaction
- `DELETE /api/messages/:messageId/reactions` - Remove reaction
- `PUT /api/messages/:chatId/read` - Mark messages as read
- `GET /api/messages/:chatId/unread-count` - Get unread count

### Group Management
- `POST /api/groups` - Create new group
- `GET /api/groups/user/:userId` - Get user's groups
- `GET /api/groups/:groupId` - Get group details
- `PUT /api/groups/:groupId` - Update group
- `DELETE /api/groups/:groupId` - Delete group
- `POST /api/groups/:groupId/members` - Add member
- `DELETE /api/groups/:groupId/members/:userId` - Remove member
- `PUT /api/groups/:groupId/members/:userId/promote` - Promote to admin
- `GET /api/groups/search` - Search public groups

### File Upload
- `POST /api/upload` - Upload single file
- `POST /api/upload/multiple` - Upload multiple files
- `POST /api/upload/profile-picture` - Upload profile picture
- `POST /api/upload/group-avatar` - Upload group avatar
- `DELETE /api/upload/:filename` - Delete uploaded file
- `GET /api/upload/:filename/info` - Get file information

### System
- `GET /api/health` - Health check endpoint

## 🔌 WebSocket Events

### Client to Server
- `user_connected` - User connects to WebSocket
- `join_chat` - Join a chat room
- `join_group` - Join a group room
- `message` - Send a message
- `typing` - Send typing indicator
- `webrtc-signal` - WebRTC signaling for voice calls
- `call_user` - Initiate voice call
- `answer_call` - Answer incoming call
- `reject_call` - Reject incoming call
- `end_call` - End active call

### Server to Client
- `user_online` - User came online
- `user_offline` - User went offline
- `new_message` - New message received
- `typing` - User typing status
- `webrtc-signal` - WebRTC signaling response
- `incoming_call` - Incoming voice call
- `call_answered` - Call was answered
- `call_rejected` - Call was rejected
- `call_ended` - Call was ended

## 🗄️ Database Schema

### User Model
```javascript
{
  name: String,
  username: String (unique),
  email: String (unique),
  password: String (hashed),
  role: String (user/admin),
  profilePic: String,
  isOnline: Boolean,
  lastSeen: Date,
  status: String (active/inactive/banned),
  bio: String,
  phoneNumber: String,
  preferences: Object
}
```

### Chat Model
```javascript
{
  participants: [ObjectId],
  type: String (direct/group),
  name: String,
  description: String,
  avatar: String,
  lastMessage: String,
  lastMessageTime: Date,
  isActive: Boolean,
  settings: Object
}
```

### Message Model
```javascript
{
  chatId: ObjectId,
  senderId: ObjectId,
  content: String,
  type: String (text/image/audio/video/file/document),
  metadata: Object,
  replyTo: ObjectId,
  isEdited: Boolean,
  editedAt: Date,
  isDeleted: Boolean,
  readBy: [Object],
  reactions: [Object]
}
```

### Group Model
```javascript
{
  name: String,
  description: String,
  avatar: String,
  creatorId: ObjectId,
  admins: [ObjectId],
  members: [Object],
  settings: Object,
  lastMessage: String,
  lastMessageTime: Date,
  isActive: Boolean
}
```

## 🔒 Security Features

- **JWT Authentication** - Secure token-based authentication
- **Password Hashing** - bcryptjs with salt rounds
- **CORS Protection** - Configurable cross-origin policies
- **Rate Limiting** - Request rate limiting to prevent abuse
- **Input Validation** - Server-side input validation
- **File Type Validation** - Secure file upload with type checking
- **Admin Authorization** - Role-based access control

## 🚀 Deployment

### Environment Variables for Production

```env
NODE_ENV=production
PORT=3000
MONGODB_URI=your-production-mongodb-uri
JWT_SECRET=your-super-secure-jwt-secret
CORS_ORIGIN=https://your-frontend-domain.com
```

### Docker Deployment

```dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

### Render.com Deployment

1. Connect your GitHub repository to Render
2. Set environment variables in Render dashboard
3. Deploy with auto-deploy on git push

## 🧪 Testing

```bash
# Run tests
npm test

# Run with coverage
npm run test:coverage
```

## 📝 API Documentation

### Authentication Required

Most endpoints require authentication via JWT token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

### Error Responses

All endpoints return consistent error responses:

```json
{
  "error": "Error Type",
  "message": "Detailed error message"
}
```

### Success Responses

Success responses include relevant data and status messages:

```json
{
  "message": "Operation successful",
  "data": { ... }
}
```

## 🔧 Configuration

### File Upload Limits
- Maximum file size: 50MB
- Supported formats: Images, Audio, Video, Documents
- Maximum files per upload: 5

### Rate Limiting
- Window: 15 minutes
- Max requests: 100 per window per IP

### WebSocket Configuration
- CORS enabled for all origins (configurable)
- Connection timeout: 30 seconds
- Heartbeat interval: 25 seconds

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new features
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Check the API documentation
- Review the test files for usage examples

## 🔄 Version History

- **v1.0.0** - Initial release with core features
  - Real-time messaging
  - User authentication
  - File uploads
  - Voice calling support
  - Group management
