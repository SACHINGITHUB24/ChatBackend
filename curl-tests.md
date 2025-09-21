# MongoDB Connection and API Testing

## 1. Test MongoDB Connection Directly

```bash
# Run the connection test
node test-connection.js
```

## 2. Start the Backend Server

```bash
# Install dependencies first
npm install

# Start server
npm start
```

## 3. Test API Endpoints with curl

### Health Check
```bash
curl -X GET http://localhost:3000/api/health
```

### Create Admin User
```bash
node init-admin.js
```

### Login (Get JWT Token)
```bash
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\"}"
```

### Get All Users (Admin only - requires token)
```bash
# Replace YOUR_JWT_TOKEN with the token from login response
curl -X GET http://localhost:3000/api/users \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Create New User (Admin only)
```bash
curl -X POST http://localhost:3000/api/admin/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d "{
    \"name\": \"John Doe\",
    \"username\": \"johndoe\",
    \"email\": \"john@example.com\",
    \"password\": \"password123\",
    \"role\": \"user\"
  }"
```

### Test WebSocket Connection
```bash
# You can use a WebSocket client or browser console:
# const socket = io('http://localhost:3000');
# socket.emit('user_connected', {userId: 'test', username: 'testuser'});
```

## Expected Responses

### Successful Health Check:
```json
{
  "status": "OK",
  "message": "Server is running",
  "database": "Connected",
  "userCount": 1,
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

### Successful Login:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "65a1b2c3d4e5f6789012345",
    "name": "Administrator",
    "username": "admin",
    "email": "admin@hichat.com",
    "role": "admin",
    "profilePic": "",
    "isOnline": true
  }
}
```
