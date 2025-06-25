const mongoose = require('mongoose');

const signalKeySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true, 
  },

  identityKey: {
    type: String,
    required: true,
  },

  signedPreKey: {
    keyId: Number,
    publicKey: String,
    signature: String, 
  },
  
  oneTimePreKeys: [{
    keyId: Number,
    publicKey: String,
  }],
}, {
  timestamps: true
});

const SignalKey = mongoose.model('SignalKey', signalKeySchema);

module.exports = SignalKey;