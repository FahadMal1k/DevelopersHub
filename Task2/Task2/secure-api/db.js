// db.js
const mysql = require('mysql2/promise'); // Use /promise for async/await

// Replace with your actual DB credentials (use .env)
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'password',
  database: process.env.DB_NAME || 'testdb',
  waitForConnections: true,
  connectionLimit: 10,
});

module.exports = pool;