// logger.js
const fs = require('fs');
const path = require('path');

// This points EXACTLY to the log file Fail2Ban is watching
const logFilePath = '/var/log/api/access.log';

function logFailedAttempt(username, ip) {
  // Create a formatted log entry that matches our Fail2Ban filter
  const entry = `${new Date().toISOString()} Failed login attempt for username: ${username} from IP: ${ip}\n`;
  
  // Append the log to the file
  fs.appendFile(logFilePath, entry, (err) => {
    if (err) {
      console.error('Failed to write to log file:', err);
    }
  });
}

module.exports = { logFailedAttempt };