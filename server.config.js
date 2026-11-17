// TardQuest API — Server Configuration
// Non-sensitive defaults. Override sensitive or
// deployment-specific values via .env at runtime.

module.exports = {
  // ── Profile ──────────────────────────────────────────────
  profile: 'public',

  // ── Deploy Mode ─────────────────────────────────────────
  // 'prod' enforces rate limits; 'dev' unlocks them.
  // Override at runtime with DEPLOY_MODE (defaults to prod if unset).
  deployMode: 'prod',

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
  // Purge sessions created more than this many days ago (keyed on created_at, an
  // absolute age cap). Kept in step with the 30-day session TTL
  // (sessionTimeoutMinutes, the idle window that refreshes on activity) so rows
  // are no longer deleted ~4x before their expiry could ever apply.
  sessionPurgeAgeDays: 30,
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

  // ── Pigeon drawings (handdrawn picture messages) ─────────
  // Bounded vector strokes on a fixed canvas — never image bytes, so payloads
  // stay tiny, stay server-validatable, and never touch the text sanitizer.
  drawingCanvasSize: 100,          // coordinate space is 0..drawingCanvasSize
  drawingMaxStrokes: 24,
  drawingMaxPointsPerStroke: 64,
  drawingMaxColors: 8,             // color index range 0..drawingMaxColors-1
  drawingMaxPayloadBytes: 8192,    // serialized {v,strokes:[...]} upper bound
  // Only clients at/above this (major.minor) may send or receive drawings.
  // The API line is 4.1.X and picture-capable clients report 4.1, so 4.1.0 is
  // the rendering floor: clients still on the 4.0.x line never receive a
  // picture, and it lights up exactly when they update to a 4.1.X client.
  // Override via PIGEON_DRAWING_MIN_CLIENT_VERSION to raise/lower the cutoff.
  // Must be major.minor.patch so it parses; comparison is major.minor only.
  pigeonDrawingMinClientVersion: '4.1.0',

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

};
