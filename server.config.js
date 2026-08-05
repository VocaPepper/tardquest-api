// TardQuest API — Server Configuration
// Non-sensitive defaults. Override sensitive or
// deployment-specific values via .env at runtime.

module.exports = {
  // ── Profile ──────────────────────────────────────────────
  profile: 'public',

  // ── Server ───────────────────────────────────────────────
  host: '0.0.0.0',
  port: 9601,
  apiVersion: require('./package.json').version,
  minClientVersion: require('./package.json').version,
  // Minimum client version that may connect at all. Older clients are rejected
  // outright. Clients between this and minClientVersion can still play (pigeons,
  // gravestones, progress updates) but cannot submit to the leaderboard.
  minSupportedClientVersion: '3.0.251113',
  bodyLimit: '100kb',

  // ── Directories (relative to project root) ───────────────
  stateDir: './json',
  logDir: './logs',

  // ── Database ─────────────────────────────────────────────
  sqliteDbPath: './data/tardquest.db',
  dbConnectionTimeoutSeconds: 30,

  // ── Session ──────────────────────────────────────────────
  sessionTimeoutMinutes: 43200,
  sessionPurgeAgeDays: 7,
  backgroundWorkerSleepSeconds: 86400,

  // ── VocaGuard ────────────────────────────────────────────
  enableVocaguard: true,
  powDifficultyPrefixZeros: 4,

  // ── Leaderboard ──────────────────────────────────────────
  maxLeaderboardNameLength: 5,

  // ── Pigeon ───────────────────────────────────────────────
  allowedCharsPattern: /[^A-Za-z0-9 .,!?;:'\-_/()\[\]@#%&*+=$\\\"]+/,
  maxPigeonMessageLen: 420,
  maxPigeonsPerSession: 20,
  pigeonRateLimit: '20 per hour',
  floorProximityRange: 2,
  priorityHighFloorWeight: 0.05,
  priorityVerifiedMultiplier: 1.5,
  ageBoostFullSeconds: 600,
  ageBoostMax: 0.5,
  randomJitterMin: 0.85,
  randomJitterMax: 1.15,
  repeatSenderPenalty: 0.5,

  // ── Abuse ────────────────────────────────────────────────
  abuseEventWindowSeconds: 3600,
  abuseDuplicateThreshold: 2,
  abuseSanitizeRejectThreshold: 2,
  abuseFlagDurationSeconds: 3600,
  abuseAuthFailThreshold: 12,
  authBackoffThreshold: 3,
  authBackoffBaseSeconds: 5,
  authBackoffMaxSeconds: 300,

  // ── CORS ─────────────────────────────────────────────────
  corsOrigins: [
    'http://localhost:3000',
  ],

  // ── Rate Limiting ────────────────────────────────────────
  rateLimitStorageUri: 'memory://',
};
