// server/index.js
require('dotenv').config(); // MUST be the very first line

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const jwt = require('jsonwebtoken');

// Load Passport AFTER dotenv is configured
require('./config/passport');

const app = express();

// CORS - Allow frontend (dynamic for dev and production)
const allowedOrigins = [
  'http://localhost:5173', // Development
  process.env.CLIENT_URL, // Production
];
app.use(
  cors({
    origin: allowedOrigins.filter(Boolean), // Filters out undefined
    credentials: true,
    // Allow custom auth header used by frontend
    allowedHeaders: ['Content-Type', 'Authorization', 'x-auth-token'],
    // Expose headers back to the browser if needed
    exposedHeaders: ['x-auth-token'],
  })
);

app.use(express.json());

// Session middleware - required for Passport + Google OAuth
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-do-not-use-in-prod',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production', // true for https in production
      maxAge: 24 * 60 * 60 * 1000, // 1 day
      httpOnly: true,
      sameSite: 'lax',
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Simple test route
app.get('/', (req, res) => {
  res.send('FuzzAds Backend is Running! 🚀');
});

// Google OAuth Routes
app.get(
  '/api/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get(
  '/api/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: `${process.env.CLIENT_URL || 'http://localhost:5173'}/login`,
    failureMessage: true,
  }),
  (req, res) => {
    // Successful authentication → generate JWT
    const payload = { user: { id: req.user.id } };
    const token = jwt.sign(payload, process.env.JWT_SECRET || 'secrettoken', {
      expiresIn: '7d',
    });

    // Redirect to frontend dashboard with token in URL
    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/panel?token=${token}`);
  }
);

// All other auth routes (register, login, verify-otp, forgot/reset password, /user)
app.use('/api/auth', require('./routes/auth'));

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected Successfully ✅'))
  .catch((err) => {
    console.error('MongoDB Connection Error:', err.message);
    process.exit(1); // Exit if DB fails
  });

// Global error handler (catches everything)
app.use((err, req, res, next) => {
  console.error('Global server error:', err.stack);
  res.status(500).json({ msg: 'Something went wrong on the server' });
});

// Start server
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT} in ${NODE_ENV} mode`);
});