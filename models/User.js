const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  username: { type: String, required: true, unique: true }, 
  email: String,
  password: { type: String, required: true },
  role: { type: String, enum: ["admin", "user"], default: "user" },
  profilePic: { type: String, default: "" },
  isOnline: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("User", userSchema);
