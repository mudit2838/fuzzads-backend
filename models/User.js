const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  // Dashboard Data
  balance: { type: Number, default: 0 },
  totalSpent: { type: Number, default: 0 },
  totalOrders: { type: Number, default: 0 },
  // Account Status
  role: { type: String, default: 'user' }, // 'user' or 'admin'
  isVerified: { type: Boolean, default: false }, // NEW - for OTP verification
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', UserSchema);