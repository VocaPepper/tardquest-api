const config = require('../config');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');

// DEPLOY_MODE=dev skips limits; all other modes enforce them.
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

  // max: 0 blocks all requests in express-rate-limit v7+, so skip in dev mode.
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
