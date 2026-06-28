const fs = require('node:fs');
const path = require('node:path');
const config = require('../config');
const logger = require('../utils/logger');

let cachedWhitelist = null;
let lastLoad = 0;

function loadWhitelist() {
  const filepath = path.join(config.stateDir, 'whitelist.json');
  if (!fs.existsSync(filepath)) return [];
  try {
    const data = JSON.parse(fs.readFileSync(filepath, 'utf-8'));
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.ips)) return data.ips;
    return [];
  } catch (e) {
    logger.logError('loadWhitelist', e);
    return [];
  }
}

function isIpWhitelisted(ip) {
  if (!ip) return false;
  const whitelist = loadWhitelist();
  return whitelist.includes(ip);
}

function whitelistMiddleware(req, res, next) {
  if (isIpWhitelisted(req.ip)) {
    next();
  } else {
    logger.logError('abuse_status_unauthorized', new Error(`Unauthorized IP access: ${req.ip}`));
    res.status(403).json({ error: 'Unauthorized' });
  }
}

module.exports = { isIpWhitelisted, whitelistMiddleware, loadWhitelist };
