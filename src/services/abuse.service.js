const fs = require('node:fs');
const path = require('node:path');
const config = require('../config');
const logger = require('../utils/logger');

let flaggedIpsCache = null;
let lastFlaggedLoad = 0;

function flaggedFilePath() {
  return path.join(config.stateDir, 'flagged.json');
}

function whitelistFilePath() {
  return path.join(config.stateDir, 'whitelist.json');
}

function loadFlaggedIps() {
  const filepath = flaggedFilePath();
  if (!fs.existsSync(filepath)) return {};
  try {
    return JSON.parse(fs.readFileSync(filepath, 'utf-8'));
  } catch (e) {
    logger.logError('loadFlaggedIps', e);
    return {};
  }
}

function saveFlaggedIps(flagged) {
  const filepath = flaggedFilePath();
  const dir = path.dirname(filepath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  try {
    fs.writeFileSync(filepath, JSON.stringify(flagged, null, 2), 'utf-8');
  } catch (e) {
    logger.logError('saveFlaggedIps', e);
  }
}

function isFlagged(ip) {
  if (!ip) return { flagged: false, info: null };
  try {
    const flagged = loadFlaggedIps();
    const now = Math.floor(Date.now() / 1000);
    if (flagged[ip] && flagged[ip].until > now) {
      return { flagged: true, info: flagged[ip] };
    }
    if (flagged[ip]) {
      delete flagged[ip];
      saveFlaggedIps(flagged);
    }
    return { flagged: false, info: null };
  } catch (e) {
    logger.logError('isFlagged', e);
    return { flagged: false, info: null };
  }
}

function recordAbuse(metric, ip, sessionId, extra) {
  const loggerModule = require('../utils/logger');

  const event = { ip: ip || 'unknown', metric };
  event.ts = Math.floor(Date.now() / 1000);
  if (sessionId) event.sid = sessionId;
  if (extra) event.extra = { ...extra };
  loggerModule.logVocaguardEvent(event);

  const vocaguardEvents = loggerModule.loadVocaguardEvents(config.abuseEventWindowSeconds);
  const ipEvents = vocaguardEvents.filter(e => e.ip === (ip || 'unknown'));
  const counts = {};
  for (const e of ipEvents) {
    counts[e.metric] = (counts[e.metric] || 0) + 1;
  }

  const shouldFlag = (
    (counts.duplicate || 0) >= config.abuseDuplicateThreshold ||
    (counts.sanitize_reject || 0) >= config.abuseSanitizeRejectThreshold ||
    (counts.auth_fail || 0) >= config.abuseAuthFailThreshold
  );

  if (shouldFlag) {
    const flagged = loadFlaggedIps();
    const safeIp = ip || 'unknown';
    flagged[safeIp] = {
      until: Math.floor(Date.now() / 1000) + config.abuseFlagDurationSeconds,
      counts,
    };
    saveFlaggedIps(flagged);
  }
}

function calculateAuthBackoffSeconds(ip, username) {
  const safeIp = (ip || '').trim();
  const safeUsername = (username || '').trim().toLowerCase();
  if (!safeIp && !safeUsername) return 0;

  try {
    const loggerModule = require('../utils/logger');
    const events = loggerModule.loadVocaguardEvents(config.abuseEventWindowSeconds);
    const authFails = events.filter(e => e.metric === 'auth_fail');

    const ipFails = authFails.filter(e => safeIp && e.ip === safeIp);
    const userFails = authFails.filter(e => safeUsername && e.username === safeUsername);

    const effectiveFailures = Math.max(ipFails.length, userFails.length);
    if (effectiveFailures < config.authBackoffThreshold) return 0;

    const overThreshold = effectiveFailures - config.authBackoffThreshold;
    const backoffSeconds = Math.min(
      config.authBackoffMaxSeconds,
      config.authBackoffBaseSeconds * Math.pow(2, overThreshold),
    );

    let lastFailTs = 0;
    for (const e of ipFails) {
      const ts = parseInt(e.ts, 10);
      if (ts > lastFailTs) lastFailTs = ts;
    }
    for (const e of userFails) {
      const ts = parseInt(e.ts, 10);
      if (ts > lastFailTs) lastFailTs = ts;
    }

    if (lastFailTs <= 0) return 0;
    const remaining = (lastFailTs + backoffSeconds) - Math.floor(Date.now() / 1000);
    return Math.max(0, remaining);
  } catch (e) {
    logger.logError('calculateAuthBackoffSeconds', e, { ip: safeIp, username: safeUsername });
    return 0;
  }
}

module.exports = {
  isFlagged,
  recordAbuse,
  calculateAuthBackoffSeconds,
  loadFlaggedIps,
  saveFlaggedIps,
};
