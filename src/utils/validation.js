const crypto = require('node:crypto');
const config = require('../config');
const logger = require('../utils/logger');

function parseVersion(versionStr) {
  if (typeof versionStr !== 'string') return null;
  const parts = versionStr.split('.');
  if (parts.length !== 3 || parts.some(part => !/^\d+$/.test(part))) return null;
  const [major, minor, patch] = parts.map(Number);
  if (![major, minor, patch].every(Number.isSafeInteger)) return null;
  return { major, minor, patch };
}

function parseInteger(value) {
  if (typeof value === 'number') return Number.isSafeInteger(value) ? value : null;
  if (typeof value !== 'string' || !/^-?\d+$/.test(value.trim())) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function versionGte(a, b) {
  if (!a || !b) return false;
  if (a.major !== b.major) return a.major > b.major;
  if (a.minor !== b.minor) return a.minor > b.minor;
  return a.patch >= b.patch;
}

function versionGt(a, b) {
  if (!a || !b) return false;
  if (a.major !== b.major) return a.major > b.major;
  if (a.minor !== b.minor) return a.minor > b.minor;
  return a.patch > b.patch;
}

// Compare major.minor so patch releases do not block compatible clients.
function versionGteMajorMinor(a, b) {
  if (!a || !b) return false;
  if (a.major !== b.major) return a.major > b.major;
  return a.minor >= b.minor;
}

/** Reject clients below minSupportedClientVersion; supported legacy clients cannot submit scores. */
function validateClientVersion(clientVersion) {
  const clientTuple = parseVersion(clientVersion);
  const serverTuple = parseVersion(config.apiVersion);
  const minSupportedTuple = parseVersion(config.minSupportedClientVersion);

  if (!clientTuple || !serverTuple || !minSupportedTuple) {
    return { valid: false, error: 'Invalid version format', reason: 'Version must be in format: major.minor.patch' };
  }
  if (!versionGte(clientTuple, minSupportedTuple)) {
    return { valid: false, error: 'Client version too old', reason: `Update client to at least ${config.minSupportedClientVersion}` };
  }
  return { valid: true };
}

/** Whether a session may submit leaderboard scores. */
function isLeaderboardEligible(clientVersion) {
  if (!clientVersion) return true;
  const clientTuple = parseVersion(clientVersion);
  const minLeaderboardTuple = parseVersion(config.minClientVersion);
  if (!clientTuple || !minLeaderboardTuple) return false;
  // Patch-level server bumps do not block compatible clients.
  return versionGteMajorMinor(clientTuple, minLeaderboardTuple);
}

module.exports = { parseVersion, parseInteger, versionGte, versionGt, versionGteMajorMinor, validateClientVersion, isLeaderboardEligible };
