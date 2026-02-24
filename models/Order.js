const mongoose = require('mongoose');

const OrderSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'users' // Connects this order to a specific user
  },
  service: { type: String, required: true },
  link: { type: String, required: true },
  quantity: { type: Number, required: true },
  charge: { type: Number, required: true },
  status: { type: String, default: 'Pending' }, // Pending, Processing, Completed
  date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Order', OrderSchema);