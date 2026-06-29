const { rateLimit, ipKeyGenerator } = require('express-rate-limit');

function createLimiter(options) {
  const defaults = {
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
      const raw = req.ip;
      return ipKeyGenerator(raw ? raw.replace(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+$/, '$1') : 'unknown');
    },
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
