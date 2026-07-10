// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser'); // <-- NEW
const csrf = require('csurf');                 // <-- NEW
const rateLimiter = require('./middleware/rateLimiter');
const authMiddleware = require('./middleware/auth');
const apiRoutes = require('./routes/api');

const app = express();
const PORT = process.env.PORT || 3000;

// ----- Security Headers (Helmet + CSP) -----
app.use(helmet());
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);
if (process.env.NODE_ENV === 'production') {
  app.use(
    helmet.hsts({
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    })
  );
}

// ----- CORS Configuration -----
const corsOptions = {
  origin: process.env.ALLOWED_ORIGIN ? process.env.ALLOWED_ORIGIN.split(',') : 'http://localhost:3000',
  optionsSuccessStatus: 200,
  credentials: true, // <-- Required to send cookies with CSRF token
};
app.use(cors(corsOptions));

// ----- Body Parser & Cookie Parser -----
app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET || 'my-super-secret-cookie-key')); // <-- NEW: signed cookies

// ----- CSRF Protection Setup -----
// We exclude GET, HEAD, OPTIONS from CSRF checks (standard practice)
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    signed: true, // ensures the cookie hasn't been tampered with
  },
});
// Apply CSRF protection to all state-changing routes (POST, PUT, DELETE, PATCH)
// We will apply it per-route in the API section.

// ----- Rate Limiting (global) -----
app.use(rateLimiter.globalLimiter);

// ----- Authentication Middleware (for protected routes) -----
app.use('/api/protected', authMiddleware);

// ----- Routes (apply CSRF to POST/PUT/DELETE) -----
// We need a route to get a CSRF token (for frontend forms)
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  // Send the token to the client so they can include it in the next request
  res.json({ csrfToken: req.csrfToken() });
});

// Apply CSRF protection to the login route (POST) and any other POST/PUT/DELETE
app.post('/api/login', csrfProtection, apiRoutes); // <-- NEW: CSRF wrapped
// For other routes, we can wrap them individually or use a global middleware.
// Let's keep it simple and apply to the main router for POST/PUT/DELETE.
// We'll use a custom wrapper function in the routes file.

// For simplicity, let's just apply it to our specific actions in routes/api.js
// BUT to ensure everything works, let's apply CSRF globally to all non-GET routes
// We'll use a small middleware to skip GET/HEAD/OPTIONS
app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }
  // Apply CSRF protection to all other methods
  return csrfProtection(req, res, next);
});

// Mount the main API routes (they will now have CSRF enforced for POST/PUT/DELETE)
app.use('/api', apiRoutes);

// ----- Error Handler for CSRF errors -----
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next(err);
});

// ----- Start Server -----
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});