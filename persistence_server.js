// models.js
const mongoose = require('mongoose');
const connection_url = process.env.CONNECTION_URL; // Usar una variable de entorno

// DB config
mongoose.connect(connection_url)
    .then(() => console.log("MongoDB connected"))
    .catch(err => console.error("MongoDB connection error:", err));

const messageSchema = new mongoose.Schema({
    message: String,
    name: String,
    timestamp: String,
    received: Boolean
});

const keysSchema = new mongoose.Schema({
    userId:String,
    username:String,
    publicIdentityKey:String,
    publicSignedPrekey:String,
    signature:String,
    timestamp: String,
});

const sessionSchema = new mongoose.Schema({
    username: String,
    identityKey: String,
    ephimeralKey: String,
});

const Message = mongoose.model('messagecontents', messageSchema);
// const User = mongoose.model('usercontents', userSchema);
const Keys = mongoose.model('keys', keysSchema);
module.exports = {
    Message,
    // User
    Keys
};
