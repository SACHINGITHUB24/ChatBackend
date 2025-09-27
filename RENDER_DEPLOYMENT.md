# Hi Chat Backend - Render Deployment Guide

## 🚀 Quick Deploy to Render

### Step 1: Prepare Your Repository
```bash
# Navigate to backend directory
cd backend

# Initialize git if not already done
git init
git add .
git commit -m "Initial ZEGOCLOUD backend setup"

# Push to GitHub/GitLab
git remote add origin https://github.com/yourusername/hi-chat-backend.git
git push -u origin main
```

### Step 2: Deploy to Render

1. **Go to [Render Dashboard](https://render.com)**
2. **Click "New +" → "Web Service"**
3. **Connect your repository**
4. **Configure the service:**

```yaml
Name: hi-chat-backend
Environment: Node
Region: Oregon (US West)
Branch: main
Build Command: npm install
Start Command: npm start
```

### Step 3: Set Environment Variables

In Render dashboard, add these environment variables:

```bash
NODE_ENV=production
JWT_SECRET=<auto-generate-this>
ZEGO_APP_ID=640953410
ZEGO_SERVER_SECRET=3127e2f085cf98a0118601e8f6ad13e7
MONGODB_URI=<will-be-provided-by-render>
FRONTEND_URL=*
```

### Step 4: Add MongoDB Database

1. **In Render dashboard → "New +" → "PostgreSQL" or use MongoDB Atlas**
2. **For MongoDB Atlas:**
   - Create free cluster at [MongoDB Atlas](https://cloud.mongodb.com)
   - Get connection string
   - Add to `MONGODB_URI` environment variable

### Step 5: Update Flutter App

Update your Flutter app configuration:

```dart
// In lib/config/zego_config.dart
static const String tokenEndpoint = 'https://your-app-name.onrender.com/api/getZegoToken';
```

## 🔧 Environment Variables Reference

| Variable | Description | Example |
|----------|-------------|---------|
| `NODE_ENV` | Environment | `production` |
| `PORT` | Server port | `3000` (auto-set by Render) |
| `JWT_SECRET` | JWT signing key | Auto-generated |
| `ZEGO_APP_ID` | ZEGOCLOUD App ID | `640953410` |
| `ZEGO_SERVER_SECRET` | ZEGOCLOUD Server Secret | `your-secret` |
| `MONGODB_URI` | Database connection | MongoDB connection string |
| `FRONTEND_URL` | CORS origin | `*` or your domain |

## 📡 API Endpoints

Your deployed backend will have these endpoints:

- `GET /api/health` - Health check
- `POST /api/register` - User registration
- `POST /api/login` - User login
- `POST /api/getZegoToken` - ZEGOCLOUD token generation
- `GET /api/users` - Get all users
- `GET /api/user/me` - Get current user
- `POST /api/groups` - Create group
- `GET /api/groups` - Get user groups

## 🧪 Testing Your Deployment

### 1. Health Check
```bash
curl https://your-app-name.onrender.com/api/health
```

### 2. Test Token Generation
```bash
# First register a user
curl -X POST https://your-app-name.onrender.com/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test User",
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123"
  }'

# Then login to get JWT token
curl -X POST https://your-app-name.onrender.com/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'

# Use JWT token to get ZEGOCLOUD token
curl -X POST https://your-app-name.onrender.com/api/getZegoToken \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "userId": "USER_ID_FROM_LOGIN"
  }'
```

## 🔒 Security Considerations

1. **Environment Variables**: Never commit secrets to git
2. **CORS**: Set specific origins in production
3. **Rate Limiting**: Configured for 100 requests per 15 minutes
4. **JWT Expiry**: Tokens expire in 7 days
5. **ZEGOCLOUD Tokens**: Expire in 24 hours

## 📊 Monitoring

- **Render Dashboard**: Monitor deployments, logs, and metrics
- **Health Endpoint**: `/api/health` for uptime monitoring
- **Logs**: View in Render dashboard or via CLI

## 🚨 Troubleshooting

### Common Issues:

1. **Build Fails**
   - Check Node.js version (>=18.0.0)
   - Verify package.json syntax

2. **Database Connection**
   - Verify MONGODB_URI is correct
   - Check database service is running

3. **ZEGOCLOUD Token Issues**
   - Verify APP_ID and SERVER_SECRET
   - Check token generation logs

4. **CORS Errors**
   - Update FRONTEND_URL environment variable
   - Check allowed origins

## 📞 Support

- **Render Docs**: https://render.com/docs
- **ZEGOCLOUD Docs**: https://docs.zegocloud.com
- **MongoDB Atlas**: https://docs.atlas.mongodb.com

## 🎉 Success!

Once deployed, your Flutter app will have:
- ✅ Secure token-based ZEGOCLOUD authentication
- ✅ User management and authentication
- ✅ Group creation and management
- ✅ Real-time messaging capabilities
- ✅ Voice calling functionality
- ✅ Production-ready backend infrastructure
