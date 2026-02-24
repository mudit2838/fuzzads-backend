// server/routes/auth.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const otpGenerator = require('otp-generator');
const User = require('../models/User');
const Otp = require('../models/Otp');
const auth = require('../middleware/auth');

// Email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Send OTP email
const sendOtpEmail = async (email, otp) => {
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'FuzzAds - OTP Verification',
    text: `Your OTP is: ${otp}\nValid for 5 minutes.`,
    html: `
      <h2>FuzzAds Verification</h2>
      <p>Your OTP code is:</p>
      <h1 style="letter-spacing: 10px; color: #2563eb;">${otp}</h1>
      <p>This OTP expires in 5 minutes.</p>
      <p>If you didn't request this, ignore this email.</p>
    `,
  });
};

// REGISTER
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ msg: 'This email is already registered' });

    user = await User.findOne({ username });
    if (user) return res.status(400).json({ msg: 'Username already taken' });

    user = new User({
      username,
      email,
      password,
      isVerified: false,
    });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);
    await user.save();

    const otp = otpGenerator.generate(6, {
      digits: true,
      lowerCaseAlphabets: false,
      upperCaseAlphabets: false,
      specialChars: false,
    });

    await Otp.create({ email, otp });
    await sendOtpEmail(email, otp);

    res.json({
      msg: 'Registration successful. Check your email for OTP to verify.',
      email,
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// VERIFY OTP
router.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  try {
    const otpRecord = await Otp.findOne({ email, otp });
    if (!otpRecord) return res.status(400).json({ msg: 'Invalid or expired OTP' });

    await User.updateOne({ email }, { isVerified: true });
    await Otp.deleteOne({ email });

    res.json({ msg: 'Email verified. You can now login.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// LOGIN - with username OR email
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({
      $or: [{ username }, { email: username }],
    });

    if (!user) return res.status(400).json({ msg: 'Invalid Credentials' });

    if (!user.isVerified) {
      return res.status(403).json({ msg: 'Please verify your email first' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid Credentials' });

    const payload = { user: { id: user.id } };
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' }, (err, token) => {
      if (err) throw err;

      res.json({
        token,
        user: {
          username: user.username,
          balance: user.balance || 0,
          totalOrders: user.totalOrders || 0,
          totalSpent: user.totalSpent || 0,
        },
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// GET current user
router.get('/user', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(
      'username balance totalOrders totalSpent'
    );
    if (!user) return res.status(404).json({ msg: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// FORGOT PASSWORD - Send OTP
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: 'No account found with this email' });

    const otp = otpGenerator.generate(6, {
      digits: true,
      lowerCaseAlphabets: false,
      upperCaseAlphabets: false,
      specialChars: false,
    });

    await Otp.create({ email, otp });
    await sendOtpEmail(email, otp);

    res.json({ msg: 'OTP sent to your email.', email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// RESET PASSWORD
router.post('/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  try {
    const otpRecord = await Otp.findOne({ email, otp });
    if (!otpRecord) return res.status(400).json({ msg: 'Invalid or expired OTP' });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: 'User not found' });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    await Otp.deleteOne({ email });

    res.json({ msg: 'Password reset successful. You can now login.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

module.exports = router;