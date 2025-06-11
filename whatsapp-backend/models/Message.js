const mongoose = require('mongoose');

const messageSchema = mongoose.Schema({
    conversationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Conversation', 
      required: true,
    },
    message: String,
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