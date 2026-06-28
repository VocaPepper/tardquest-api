const rateLimit = require('express-rate-limit');
const config = require('../config');

function normalizeIp(rawIp) {
  if (!rawIp) return 'unknown';
  const stripped = rawIp.replace(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+$/, '$1');
  return stripped;
}

function createLimiter(options) {
  const defaults = {
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => normalizeIp(req.ip),
    message: { error: 'Too many requests, please try again later.' },
  };
  return rateLimit({ ...defaults, ...options });
}

const defaultLimiter = createLimiter({
  windowMs: 60 * 60 * 1000,
  max: 100,
});

function limiter(options) {
  return createLimiter(options);
}

module.exports = { limiter, defaultLimiter, createLimiter };
