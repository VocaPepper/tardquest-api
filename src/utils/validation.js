const crypto = require('node:crypto');
const config = require('../config');
const logger = require('../utils/logger');

function parseVersion(versionStr) {
  try {
    const parts = versionStr.split('.');
    const major = parseInt(parts[0], 10);
    const minor = parseInt(parts[1], 10);
    const patch = parseInt(parts[2], 10);
    if (isNaN(major) || isNaN(minor) || isNaN(patch)) return null;
    return { major, minor, patch };
  } catch (e) {
    return null;
  }
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

/**
 * Validate that a client version is new enough to connect at all.
 * Clients must be >= minSupportedClientVersion; anything older is rejected.
 * Clients between minSupportedClientVersion and minClientVersion may still play
 * (pigeons, gravestones, progress) but cannot use leaderboard features.
 */
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

/**
 * True when a session's client version is new enough for full features,
 * including leaderboard submissions.
 */
function isLeaderboardEligible(clientVersion) {
  if (!clientVersion) return true;
  const clientTuple = parseVersion(clientVersion);
  const minLeaderboardTuple = parseVersion(config.minClientVersion);
  if (!clientTuple || !minLeaderboardTuple) return false;
  return versionGte(clientTuple, minLeaderboardTuple);
}

module.exports = { parseVersion, versionGte, versionGt, validateClientVersion, isLeaderboardEligible };
