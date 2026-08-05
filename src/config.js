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

// Merge private config on top of public defaults when profile is "private".
// Use a static require() path so esbuild can bundle it at build time.
// The try/catch handles the case where src/private/ doesn't exist
// (e.g. public-only checkout or CI build without private sources).
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
  manifestoApiKey: process.env.MANIFESTO_API_KEY || '',

  // Deployment-specific overrides (fallbacks from merged defaults)
  profile: (process.env.API_PROFILE || merged.profile).toLowerCase(),
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

  rateLimitStorageUri: process.env.RATE_LIMIT_STORAGE_URI || merged.rateLimitStorageUri,

  // Resolve relative paths to absolute
  stateDir: path.resolve(ROOT, merged.stateDir),
  logDir: path.resolve(ROOT, merged.logDir),
};

module.exports = config;
