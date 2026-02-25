// server/config/passport.js
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/User');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ email: profile.emails[0].value });

        if (user) {
          // User already exists → login
          return done(null, user);
        }

        // New user → auto create
        // Generate a random 16-character dummy password and hash it
        // This satisfies the MongoDB User model requirement of `password: { required: true }`
        const randomString = crypto.randomBytes(16).toString('hex');
        const dummyPassword = await bcrypt.hash(randomString, 10);

        const newUser = new User({
          username: profile.emails[0].value.split('@')[0] + Math.floor(Math.random() * 1000),
          email: profile.emails[0].value,
          password: dummyPassword, 
          isVerified: true, // Google verified
          balance: 0,
          totalSpent: 0,
          totalOrders: 0,
        });

        await newUser.save();
        return done(null, newUser);
      } catch (err) {
        console.error("Passport Error:", err);
        return done(err, null);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

module.exports = passport;
