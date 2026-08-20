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

module.exports = { parseVersion, versionGte, versionGt, versionGteMajorMinor, validateClientVersion, isLeaderboardEligible };
