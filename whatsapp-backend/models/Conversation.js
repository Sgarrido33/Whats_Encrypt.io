const mongoose = require('mongoose');

const conversationSchema = new mongoose.Schema({
  participants: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User', 
    required: true,
  }],

  lastMessage: {
    type: mongoose.Schema.Types.Mixed,
    default: null,
  },
  lastMessageSender: {
    type: String, 
    default: null,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
}, {
  timestamps: true 
});

conversationSchema.index({ participants: 1 });

const Conversation = mongoose.model('Conversation', conversationSchema);

module.exports = Conversation;