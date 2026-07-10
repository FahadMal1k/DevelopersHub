// middleware/rateLimiter.js
const rateLimit = require('express-rate-limit');

// Global limiter – applies to all requests
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again after 15 minutes',
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Stricter limiter for login/authentication endpoints
const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10, // 10 attempts per 5 minutes
  message: 'Too many authentication attempts, please try again later',
});

module.exports = { globalLimiter, authLimiter };