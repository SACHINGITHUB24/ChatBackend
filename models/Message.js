const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  chatId: { type: String, required: true, index: true },
  groupId: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' },
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  text: { type: String, required: true },
  type: { 
    type: String, 
    enum: ['text', 'image', 'video', 'audio', 'document', 'voice', 'file'], 
    default: 'text' 
  },
  metadata: {
    filePath: { type: String },
    fileName: { type: String },
    fileSize: { type: Number },
    fileType: { type: String },
    url: { type: String },
    audioDuration: { type: Number }, // for voice messages
    thumbnailUrl: { type: String }, // for images/videos
    width: { type: Number }, // for images
    height: { type: Number }, // for images
  },
  isRead: { type: Boolean, default: false },
  readBy: [{ 
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    readAt: { type: Date, default: Date.now }
  }],
  replyTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
  isEdited: { type: Boolean, default: false },
  editedAt: { type: Date },
  isDeleted: { type: Boolean, default: false },
  deletedAt: { type: Date },
  deliveredTo: [{ 
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    deliveredAt: { type: Date, default: Date.now }
  }],
  timestamp: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Index for efficient queries
messageSchema.index({ chatId: 1, createdAt: -1 });
messageSchema.index({ groupId: 1, createdAt: -1 });
messageSchema.index({ senderId: 1 });
messageSchema.index({ recipientId: 1 });
messageSchema.index({ timestamp: -1 });
messageSchema.index({ isDeleted: 1 });

module.exports = mongoose.model('Message', messageSchema);
