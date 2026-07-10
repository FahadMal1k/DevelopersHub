// middleware/auth.js
const apiKeys = process.env.API_KEYS ? process.env.API_KEYS.split(',') : ['default-key'];

function authMiddleware(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) {
    return res.status(401).json({ error: 'API key missing' });
  }
  if (!apiKeys.includes(apiKey)) {
    return res.status(403).json({ error: 'Invalid API key' });
  }
  next();
}

module.exports = authMiddleware;