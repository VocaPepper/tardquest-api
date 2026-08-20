const config = require('../config');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');

// DEPLOY_MODE=dev unlocks rate limits. Anything else (or unset) enforces them.
const RATE_LIMITS_ENABLED = config.deployMode !== 'dev';

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

  const merged = { ...defaults, ...options };

  // In dev mode, unlock rate limits entirely by skipping every request.
  // Note: max: 0 blocks ALL requests in express-rate-limit v7+ — use skip instead.
  if (!RATE_LIMITS_ENABLED) {
    merged.skip = () => true;
  }

  return rateLimit(merged);
}

const defaultLimiter = createLimiter({
  windowMs: 60 * 60 * 1000,
  max: 100,
});

function limiter(options) {
  return createLimiter(options);
}

module.exports = { limiter, defaultLimiter, createLimiter };
