// ==============================================
// IMPORTS
// ==============================================
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const https = require('https');
const fs = require('fs');
const helmet = require('helmet');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const xss = require('xss');

// ==============================================
// WEEK 3: WINSTON LOGGING SETUP
// ==============================================
const winston = require('winston');

// Create the logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss'
    }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  defaultMeta: { service: 'secure-web-app' },
  transports: [
    // Log to console (for development)
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    // Log to file (for security auditing)
    new winston.transports.File({ 
      filename: 'security.log',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    }),
    // Separate error log file
    new winston.transports.File({ 
      filename: 'error.log', 
      level: 'error',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    })
  ]
});

// Log application startup
logger.info('🚀 Application starting...');
logger.info('📋 Environment: ' + (process.env.NODE_ENV || 'development'));

// ==============================================
// MIDDLEWARE
// ==============================================
dotenv.config();
const app = express();

// Security Headers (Helmet with relaxed CSP for lab)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-hashes'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
}));

app.use(express.json());

// Session Configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'secure-web-app-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: true
  }
}));

// ==============================================
// WEEK 3: REQUEST LOGGING MIDDLEWARE
// ==============================================
app.use((req, res, next) => {
  // Log all incoming requests
  logger.info(`📥 ${req.method} ${req.url} - IP: ${req.ip || req.connection.remoteAddress}`);
  
  // Log suspicious patterns (SQL injection attempts)
  const bodyString = JSON.stringify(req.body || {});
  if (bodyString.includes("' OR '1'='1") || 
      bodyString.includes("--") || 
      bodyString.includes("1=1")) {
    logger.warn(`⚠️ Potential SQL Injection attempt detected! IP: ${req.ip}`, {
      url: req.url,
      body: req.body
    });
  }
  
  // Log XSS attempts
  if (bodyString.includes("<script>") || 
      bodyString.includes("onerror=") || 
      bodyString.includes("alert(")) {
    logger.warn(`⚠️ Potential XSS attempt detected! IP: ${req.ip}`, {
      url: req.url,
      body: req.body
    });
  }
  
  next();
});

// ==============================================
// DATABASE SETUP
// ==============================================
const db = new sqlite3.Database('./database.sqlite');
const SALT_ROUNDS = 10;

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user',
    bio TEXT
  )`, (err) => {
    if (err) {
      logger.error('❌ Database creation error:', err);
    } else {
      logger.info('✅ Database initialized successfully');
    }
  });
});

// ==============================================
// ACCESS CONTROL MIDDLEWARES
// ==============================================
function requireLogin(req, res, next) {
  if (!req.session.user) {
    logger.warn(`🔒 Unauthorized access attempt to ${req.url} - IP: ${req.ip}`);
    return res.redirect('/login.html');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (req.session.user.role !== 'admin') {
    logger.warn(`⛔ Unauthorized admin access attempt by ${req.session.user.username} - IP: ${req.ip}`);
    return res.status(403).send(`
      <h2>Access Denied</h2>
      <p>You are authenticated, but you are not authorized to access the admin page.</p>
      <a href="/dashboard.html">Back to Dashboard</a>
    `);
  }
  next();
}

// ==============================================
// JWT AUTHENTICATION MIDDLEWARE
// ==============================================
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret-key';

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    logger.warn(`🔒 JWT missing - IP: ${req.ip}`);
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      logger.warn(`🔒 Invalid JWT token - IP: ${req.ip}`);
      return res.status(403).json({ error: 'Invalid or expired token.' });
    }
    req.user = user;
    next();
  });
}

// ==============================================
// PROTECTED ROUTES
// ==============================================
app.get('/admin.html', requireLogin, requireAdmin, (req, res) => {
  logger.info(`👑 Admin page accessed by ${req.session.user.username}`);
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.use(express.static('.'));

// ==============================================
// WEEK 3: HEALTH CHECK ENDPOINT (for Nmap/Testing)
// ==============================================
app.get('/health', (req, res) => {
  logger.info('💚 Health check requested');
  res.json({ 
    status: 'OK', 
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    security: {
      helmet: true,
      bcrypt: true,
      jwt: true,
      logging: true,
      ssl: true
    }
  });
});

// ==============================================
// REGISTER (with logging)
// ==============================================
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  
  logger.info(`📝 Registration attempt for username: ${username} - IP: ${req.ip}`);

  if (!username || username.length < 3 || !validator.isAlphanumeric(username)) {
    logger.warn(`❌ Invalid username format: ${username} - IP: ${req.ip}`);
    return res.status(400).json({ error: 'Username must be at least 3 characters and alphanumeric.' });
  }

  if (!validator.isStrongPassword(password, {
    minLength: 8,
    minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1,
    minSymbols: 1
  })) {
    logger.warn(`❌ Weak password attempt for ${username} - IP: ${req.ip}`);
    return res.status(400).json({ error: 'Password must be at least 8 characters with 1 uppercase, 1 lowercase, 1 number, and 1 symbol.' });
  }

  const sanitizedUsername = validator.escape(username);

  try {
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const sql = "INSERT INTO users (username, password) VALUES (?, ?)";
    
    db.run(sql, [sanitizedUsername, hashedPassword], (err) => {
      if (err) {
        logger.error(`❌ Registration failed for ${username}:`, err);
        return res.status(400).json({ message: "Error: User might already exist." });
      }
      logger.info(`✅ User registered successfully: ${sanitizedUsername} - IP: ${req.ip}`);
      res.json({ message: "User registered successfully with bcrypt!" });
    });
  } catch (error) {
    logger.error('❌ Server error during registration:', error);
    res.status(500).json({ message: "Server error" });
  }
});

// ==============================================
// JWT LOGIN (with logging)
// ==============================================
app.post('/login-jwt', async (req, res) => {
  const { username, password } = req.body;
  
  logger.info(`🔑 Login attempt for username: ${username} - IP: ${req.ip}`);

  if (!username || !password) {
    logger.warn(`❌ Missing credentials - IP: ${req.ip}`);
    return res.status(400).json({ message: "Username and password required." });
  }

  const sql = "SELECT * FROM users WHERE username = ?";
  db.get(sql, [username], async (err, user) => {
    if (err || !user) {
      logger.warn(`❌ Failed login attempt for non-existent user: ${username} - IP: ${req.ip}`);
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      logger.warn(`❌ Failed login attempt with wrong password: ${username} - IP: ${req.ip}`);
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '2h' }
    );

    logger.info(`✅ Successful JWT login: ${username} - Role: ${user.role} - IP: ${req.ip}`);
    res.json({
      message: "JWT Login successful",
      token: token,
      user: { id: user.id, username: user.username, role: user.role }
    });
  });
});

// ==============================================
// SESSION-BASED LOGIN (with logging)
// ==============================================
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  logger.info(`🔑 Session login attempt: ${username} - IP: ${req.ip}`);

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required." });
  }

  const sql = "SELECT * FROM users WHERE username = ?";
  db.get(sql, [username], async (err, user) => {
    if (err || !user) {
      logger.warn(`❌ Failed session login for: ${username} - IP: ${req.ip}`);
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const match = await bcrypt.compare(password, user.password);

    if (match) {
      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role
      };
      logger.info(`✅ Successful session login: ${username} - IP: ${req.ip}`);
      res.json({ message: "Login successful", role: user.role });
    } else {
      logger.warn(`❌ Failed session login (wrong password): ${username} - IP: ${req.ip}`);
      res.status(401).json({ message: "Invalid username or password" });
    }
  });
});

// ==============================================
// JWT PROTECTED DASHBOARD
// ==============================================
app.get('/dashboard-jwt', authenticateToken, (req, res) => {
  logger.info(`📊 JWT Dashboard accessed by: ${req.user.username} - IP: ${req.ip}`);
  res.json({
    message: `Welcome to the JWT protected dashboard, ${req.user.username}!`,
    userId: req.user.id,
    username: req.user.username,
    role: req.user.role
  });
});

// ==============================================
// SQL INJECTION VULNERABLE (Keep for demo with logging)
// ==============================================
app.post('/login_vulnerable', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  logger.warn(`⚠️ VULNERABLE LOGIN ENDPOINT USED: ${username} - IP: ${req.ip}`);

  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  logger.warn(`⚠️ SQL Query: ${query}`);

  db.get(query, (err, user) => {
    if (err) {
      logger.error('❌ Database error in vulnerable endpoint:', err);
      return res.status(500).json({ message: "Database error" });
    }

    if (user) {
      logger.warn(`⚠️ SQL Injection successful! User: ${user.username} - IP: ${req.ip}`);
      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role
      };
      return res.json({
        username: user.username,
        role: user.role
      });
    } else {
      return res.status(401).json({ message: "Invalid username or password" });
    }
  });
});

// ==============================================
// SQL INJECTION SECURE
// ==============================================
app.post('/login_secure', async (req, res) => {
  const { username, password } = req.body;

  logger.info(`🔒 Secure login attempt: ${username} - IP: ${req.ip}`);

  const query = "SELECT * FROM users WHERE username = ?";
  db.get(query, [username], async (err, row) => {
    if (err) {
      logger.error('❌ Database error in secure endpoint:', err);
      return res.status(500).json({ message: "Database error" });
    }

    if (!row) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const isValid = await bcrypt.compare(password, row.password);

    if (isValid) {
      req.session.user = {
        id: row.id,
        username: row.username,
        role: row.role
      };
      logger.info(`✅ Secure login successful: ${username} - IP: ${req.ip}`);
      return res.json({
        username: row.username,
        role: row.role
      });
    } else {
      return res.status(401).json({ message: "Invalid username or password" });
    }
  });
});

// ==============================================
// LOGOUT
// ==============================================
app.post('/logout', (req, res) => {
  if (req.session.user) {
    logger.info(`👋 Logout: ${req.session.user.username} - IP: ${req.ip}`);
  }
  req.session.destroy(() => {
    res.json({ message: "Logged out successfully" });
  });
});

// ==============================================
// XSS SECURE: UPDATE BIO
// ==============================================
app.post('/update-bio', requireLogin, (req, res) => {
  const { bio } = req.body;
  const userId = req.session.user.id;

  logger.info(`📝 Bio update by: ${req.session.user.username} - IP: ${req.ip}`);

  db.run(
    "UPDATE users SET bio = ? WHERE id = ?",
    [bio, userId],
    (err) => {
      if (err) {
        logger.error('❌ Bio update error:', err);
        return res.status(500).json({ message: "Error updating bio" });
      }
      logger.info(`✅ Bio updated by: ${req.session.user.username}`);
      res.json({ message: "Bio updated (secure)!" });
    }
  );
});

// ==============================================
// XSS SECURE: DISPLAY BIOS
// ==============================================
app.get('/all-bios', (req, res) => {
  logger.info(`📄 All bios accessed - IP: ${req.ip}`);

  db.all("SELECT username, bio FROM users", (err, rows) => {
    if (err) {
      logger.error('❌ Bios fetch error:', err);
      return res.send("Error (secure)");
    }

    let html = `
    <html>
    <head><title>SECURE</title></head>
    <body>
    <h1>Secure Version (Protected)</h1>
    <p style="color:green;"> This page is protected from XSS</p>
    <ul>
    `;

    rows.forEach(row => {
      const clean = xss(row.bio || '');
      html += `<li><b>${row.username}</b>: ${clean}</li>`;
    });

    html += `</ul></body></html>`;
    res.send(html);
  });
});

// ==============================================
// WEEK 3: ERROR LOGGING MIDDLEWARE
// ==============================================
app.use((err, req, res, next) => {
  logger.error('❌ Unhandled error:', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip
  });
  res.status(500).send('Something went wrong!');
});

// ==============================================
// HTTPS SERVER
// ==============================================
const sslOptions = {
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.cert')
};

https.createServer(sslOptions, app).listen(3000, () => {
  logger.info('='.repeat(60));
  logger.info('🔒 SECURE WEB APPLICATION - FULLY HARDENED');
  logger.info('='.repeat(60));
  logger.info('✅ Secure Server running at: https://localhost:3000');
  logger.info('✅ JWT Login: POST /login-jwt');
  logger.info('✅ Protected JWT route: GET /dashboard-jwt');
  logger.info('✅ Vulnerable SQLI: POST /login_vulnerable (for testing)');
  logger.info('✅ Secure SQLI: POST /login_secure');
  logger.info('📋 Logging to: security.log and error.log');
  logger.info('='.repeat(60));
});

// Handle process termination
process.on('SIGINT', () => {
  logger.info('🛑 Application shutting down...');
  process.exit();
});