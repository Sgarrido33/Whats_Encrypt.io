// whatsapp-backend/models/Keys.js

const mongoose = require('mongoose');

const keySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true,
  },
  // Ahora solo guardamos una única clave pública por usuario
  publicKey: {
    type: Buffer,
    required: true,
  }
}, {
  timestamps: true
});

const Keys = mongoose.model('Keys', keySchema);

module.exports = Keys;