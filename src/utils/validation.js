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

function validateClientVersion(clientVersion) {
  const clientTuple = parseVersion(clientVersion);
  const serverTuple = parseVersion(config.apiVersion);
  const minClientTuple = parseVersion(config.minClientVersion);

  if (!clientTuple || !serverTuple || !minClientTuple) {
    return { valid: false, error: 'Invalid version format', reason: 'Version must be in format: major.minor.patch' };
  }
  if (!versionGte(clientTuple, minClientTuple)) {
    return { valid: false, error: 'Client version too old', reason: `Update client to at least ${config.minClientVersion}` };
  }
  return { valid: true };
}

module.exports = { parseVersion, versionGte, validateClientVersion };
