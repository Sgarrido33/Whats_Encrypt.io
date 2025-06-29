const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    conversationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Conversation', 
      required: true,
    },
    message: {
      type: mongoose.Schema.Types.Mixed,
      required: true,
    },
    name: String, 
    senderId: { 
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    timestamp: String,
    received: Boolean, 
});

module.exports = mongoose.model('messagecontents', messageSchema);