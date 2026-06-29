const rateLimit = require('express-rate-limit');
const config = require('../config');

function createLimiter(options) {
  const defaults = {
    standardHeaders: true,
    legacyHeaders: false,
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
