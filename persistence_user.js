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

const userKeysSchema = new mongoose.Schema({
    userId:String,
    username:String,
    privateIdentityKey:String,
    privateSignedPrekey:String,
    timestamp: String,
});

const sessionSchema = new mongoose.Schema({
    username: String,
    identityKey: String,
    ephimeralKey: String,
});

const Message = mongoose.model('messagecontents', messageSchema);
// const User = mongoose.model('usercontents', userSchema);
const UserKeys = mongoose.model('userkeys', keysSchema);
module.exports = {
    Message,
    // User
    UserKeys
};
