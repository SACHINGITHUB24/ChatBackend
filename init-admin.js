const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// Import database connection
const { connectDB } = require('./config/database');
const User = require('./models/User');

const createAdminUser = async () => {
  try {
    // Connect to database
    await connectDB();

    // Check if admin already exists
    const existingAdmin = await User.findOne({ role: 'admin' });
    if (existingAdmin) {
      console.log('✅ Admin user already exists:', existingAdmin.username);
      process.exit(0);
    }

    // Create admin user
    const hashedPassword = await bcrypt.hash('admin123', 10);
    
    const adminUser = new User({
      name: 'Administrator',
      username: 'admin',
      email: 'admin@hichat.com',
      password: hashedPassword,
      role: 'admin',
      profilePic: '',
      isOnline: false
    });

    await adminUser.save();
    
    console.log('✅ Admin user created successfully!');
    console.log('📧 Username: admin');
    console.log('🔑 Password: admin123');
    console.log('⚠️  Please change the password after first login');
    
    process.exit(0);
  } catch (error) {
    console.error('❌ Error creating admin user:', error);
    process.exit(1);
  }
};

createAdminUser();
