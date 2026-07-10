// routes/api.js
const express = require('express');
const router = express.Router();
const { authLimiter } = require('../middleware/rateLimiter');
const authMiddleware = require('../middleware/auth');
const { logFailedAttempt } = require('../logger');
const db = require('../db'); // <-- NEW: import DB pool

// ----- Public Route -----
router.get('/public', (req, res) => {
  res.json({ message: 'Public endpoint - anyone can access this' });
});

// ----- Login Route (with logging) -----
router.post('/login', authLimiter, (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === 'secret') {
    return res.json({ message: 'Login successful', token: 'fake-jwt-token' });
  }
  logFailedAttempt(username, req.ip);
  return res.status(401).json({ error: 'Invalid credentials' });
});

// ----- Protected Route (API Key) -----
router.get('/protected', authMiddleware, (req, res) => {
  res.json({ message: 'You have a valid API key!' });
});

// ===============================================
//  VULNERABLE ROUTE (DO NOT USE IN PRODUCTION)
//  Purpose: To show how SQL injection works.
//  Attack: GET /users?userId=1 UNION SELECT ...
// ===============================================
router.get('/users', async (req, res) => {
  const userId = req.query.userId;
  try {
    // ❌ VULNERABLE: Direct concatenation (NEVER DO THIS)
    const [rows] = await db.query(`SELECT id, username, email FROM users WHERE id = ${userId}`);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===============================================
//  SECURE ROUTE (USES PREPARED STATEMENTS)
//  Prevents SQL injection completely.
// ===============================================
router.get('/safe-users', async (req, res) => {
  const userId = req.query.userId;
  try {
    // ✅ SECURE: Prepared statement using '?'
    const [rows] = await db.execute(
      'SELECT id, username, email FROM users WHERE id = ?',
      [userId] // The user input is safely bound here
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;