const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true },
  
  // Dashboard Data (Dynamic!)
  balance:      { type: Number, default: 0 },
  totalSpent:   { type: Number, default: 0 },
  totalOrders:  { type: Number, default: 0 },
  
  createdAt:    { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', UserSchema);