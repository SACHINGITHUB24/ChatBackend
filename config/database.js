const { MongoClient, ServerApiVersion } = require('mongodb');
const mongoose = require('mongoose');

// MongoDB Atlas connection string
const uri = "mongodb+srv://ChatAppData:<db_password>@chatappdata.ua6pnti.mongodb.net/ChatAppData?retryWrites=true&w=majority&appName=ChatAppData";

// Replace <db_password> with your actual password
const MONGODB_URI = process.env.MONGODB_URI || uri.replace('<db_password>', process.env.DB_PASSWORD || 'your_password_here');

const connectDB = async () => {
  try {
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('✅ Connected to MongoDB Atlas - ChatAppData');
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    process.exit(1);
  }
};

// Test connection function
const testConnection = async () => {
  const client = new MongoClient(MONGODB_URI, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    }
  });

  try {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    console.log("✅ Pinged your deployment. You successfully connected to MongoDB!");
    return true;
  } catch (error) {
    console.error("❌ MongoDB connection test failed:", error);
    return false;
  } finally {
    await client.close();
  }
};

module.exports = { connectDB, testConnection };
