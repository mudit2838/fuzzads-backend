const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const User = require('../models/User');
const crypto = require('crypto');
const Razorpay = require('razorpay');

const rzp = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Create Razorpay Order
router.post('/create-order', auth, async (req, res) => {
  const { amount } = req.body;

  if (!amount || amount < 100) {
    return res.status(400).json({ msg: 'Minimum amount ₹100' });
  }

  const options = {
    amount: amount * 100, // paise
    currency: "INR",
    receipt: `receipt_${Date.now()}`,
    notes: {
      userId: req.user.id,
    },
  };

  try {
    const order = await rzp.orders.create(options);
    res.json(order);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Failed to create order' });
  }
});

// Verify Payment
router.post('/verify', auth, async (req, res) => {
  const { razorpay_payment_id, razorpay_order_id, razorpay_signature } = req.body;

  const shasum = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET);
  shasum.update(`${razorpay_order_id}|${razorpay_payment_id}`);
  const digest = shasum.digest('hex');

  if (digest === razorpay_signature) {
    const payment = await rzp.payments.fetch(razorpay_payment_id);
    const amount = payment.amount / 100;

    const user = await User.findById(req.user.id);
    if (user) {
      user.balance += amount;
      await user.save();
      res.json({ success: true, msg: 'Payment verified, balance updated' });
    } else {
      res.status(404).json({ success: false, msg: 'User not found' });
    }
  } else {
    res.status(400).json({ success: false, msg: 'Invalid signature' });
  }
});

module.exports = router;