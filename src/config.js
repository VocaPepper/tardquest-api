const path = require('node:path');
const dotenv = require('dotenv');

dotenv.config();

const defaults = require('../server.config');
const ROOT = process.cwd();

function envInt(key, fallback) {
  const v = process.env[key];
  if (v === undefined || v === '') return fallback;
  const n = parseInt(v, 10);
  return isNaN(n) ? fallback : n;
}

function envBool(key, fallback) {
  const v = process.env[key];
  if (v === undefined || v === '') return fallback;
  return ['true', '1', 'yes'].includes(v.toLowerCase());
}

function envList(key, fallback) {
  const v = process.env[key];
  if (v === undefined || v === '') return fallback;
  return v.split(',').map(s => s.trim()).filter(Boolean);
}

// Merge private defaults when requested; the static require keeps esbuild bundling
// and public-only builds working when private sources are absent.
let merged = { ...defaults };
if ((process.env.API_PROFILE || defaults.profile).toLowerCase() === 'private') {
  try {
    const privateDefaults = require('./private/server.config.js');
    merged = { ...merged, ...privateDefaults };
  } catch (e) {
    console.warn('Private profile selected but private config could not be loaded:', e.message);
  }
}

const config = {
  ...merged,

  // Sensitive values — only from .env, no committed defaults
  accountDbUrl: process.env.TQ_DATABASE_URL || '',
  recoveryCodePepper: process.env.RECOVERY_CODE_PEPPER || '',

  profile: (process.env.API_PROFILE || merged.profile).toLowerCase(),
  // 'prod' enforces rate limits; 'dev' skips them. Defaults to 'prod'.
  deployMode: (process.env.DEPLOY_MODE || merged.deployMode || 'prod').toLowerCase(),
  host: process.env.HOST || merged.host,
  port: envInt('PORT', merged.port),
  apiVersion: process.env.API_VERSION || merged.apiVersion,
  minClientVersion: process.env.MIN_CLIENT_VERSION || merged.minClientVersion,
  minSupportedClientVersion: process.env.MIN_SUPPORTED_CLIENT_VERSION || merged.minSupportedClientVersion,

  sqliteDbPath: path.resolve(ROOT, process.env.SQLITE_DB_PATH || merged.sqliteDbPath),
  dbConnectionTimeoutSeconds: envInt('DB_CONNECTION_TIMEOUT_SECONDS', merged.dbConnectionTimeoutSeconds),

  bcryptRounds: envInt('BCRYPT_ROUNDS', merged.bcryptRounds),
  onlineAuthSessionMinutes: envInt('ONLINE_AUTH_SESSION_MINUTES', merged.onlineAuthSessionMinutes),

  enableVocaguard: envBool('ENABLE_VOCAGUARD', merged.enableVocaguard),
  powDifficultyPrefixZeros: Math.max(1, Math.min(8, envInt('POW_DIFFICULTY_PREFIX_ZEROS', merged.powDifficultyPrefixZeros))),

  abuseAuthFailThreshold: envInt('ABUSE_AUTH_FAIL_THRESHOLD', merged.abuseAuthFailThreshold),
  authBackoffThreshold: envInt('AUTH_BACKOFF_THRESHOLD', merged.authBackoffThreshold),
  authBackoffBaseSeconds: envInt('AUTH_BACKOFF_BASE_SECONDS', merged.authBackoffBaseSeconds),
  authBackoffMaxSeconds: envInt('AUTH_BACKOFF_MAX_SECONDS', merged.authBackoffMaxSeconds),

  corsOrigins: merged.corsOrigins,

  stateDir: path.resolve(ROOT, merged.stateDir),
  logDir: path.resolve(ROOT, merged.logDir),
};

module.exports = config;
