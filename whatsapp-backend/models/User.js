const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); 

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,   
    minlength: 3  
  },
  password: {
    type: String,
    required: true,
    minlength: 6 
  }
}, {
  timestamps: true 
});

userSchema.pre('save', async function(next) {
  if (this.isModified('password')) { 
    const salt = await bcrypt.genSalt(10); 
    this.password = await bcrypt.hash(this.password, salt); 
  }
  next(); 
});

userSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password); 
};

const User = mongoose.model('User', userSchema);

module.exports = User;