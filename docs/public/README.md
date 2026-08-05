# TardQuest API

Game API server for TardQuest, a JavaScript dungeon-crawler web game. Node.js/Express rewrite (v4) of the original Python/Flask server.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Database](#database)
- [Security](#security)

---

## Quick Start

### Requirements

- Node.js 16+
- SQLite database (auto-created)

### Setup

```bash
npm install
npm run build:public
node dist/public.js
```

Health check: `curl http://localhost:9601/status`

### Production

Run behind a reverse proxy (IIS, nginx) handling HTTPS termination, IP forwarding, and protocol detection. The `/status` endpoint serves as a load-balancer health check.

Log files are written to `logs/`. The native `better-sqlite3` dependency must be compiled for the target platform.

---

## Configuration

No configuration required — all defaults work out of the box.

**`server.config.js`** (project root) contains all default settings. Edit it to adjust server, gameplay, or abuse thresholds.

| Key | Default | Description |
|-----|---------|-------------|
| `host` | `0.0.0.0` | Listen address |
| `port` | `9601` | Listen port |
| `apiVersion` | *(from `package.json`)* | Reported in status endpoint |
| `minClientVersion` | *(from `package.json`)* | Minimum client version for full features |
| `minSupportedClientVersion` | `3.0.251113` | Minimum client version for limited features |
| `bodyLimit` | `100kb` | Max JSON/URL-encoded payload size |
| `sqliteDbPath` | `./data/tardquest.db` | SQLite database file |
| `dbConnectionTimeoutSeconds` | `30` | Database connection timeout |
| `enableVocaguard` | `true` | Master switch for anti-cheat |
| `powDifficultyPrefixZeros` | `4` | Leading zero bits required (1–8) |
| `sessionTimeoutMinutes` | `43200` | Game session TTL (30 days) |
| `sessionPurgeAgeDays` | `7` | Purge sessions older than this |
| `backgroundWorkerSleepSeconds` | `86400` | Interval between purge runs (24h) |
| `maxLeaderboardNameLength` | `5` | Max in-game leaderboard name length |
| `maxPigeonMessageLen` | `420` | Max pigeon message length |
| `maxPigeonsPerSession` | `20` | Max pigeon inventory capacity |
| `pigeonRateLimit` | `20 per hour` | Pigeon purchase rate limit |
| `abuseEventWindowSeconds` | `3600` | Lookback window for abuse counting |
| `abuseDuplicateThreshold` | `2` | Duplicate messages before flagging |
| `abuseSanitizeRejectThreshold` | `2` | Sanitization failures before flagging |
| `abuseFlagDurationSeconds` | `3600` | IP block duration |
| `abuseAuthFailThreshold` | `12` | Auth failures before IP flagging |
| `authBackoffThreshold` | `3` | Failures before backoff starts |
| `authBackoffBaseSeconds` | `5` | Initial backoff delay |
| `authBackoffMaxSeconds` | `300` | Maximum backoff delay |
| `corsOrigins` | *(6 origins)* | Allowed CORS origins |
| `rateLimitStorageUri` | `memory://` | Rate-limit backend (`redis://` for multi-process) |

**Default CORS origins:** `http://localhost:3000`

### VocaGuard Thresholds (in `vocaguard.service.js`)

| Constant | Default | Description |
|----------|---------|-------------|
| `MIN_FLOOR_INCREMENT_SECONDS` | `10` | Minimum seconds between floor increments |
| `POW_CHALLENGE_EXPIRY_SECONDS` | `86400` | PoW challenge lifespan (24h) |
| `MAX_LEVELUPS_PER_MINUTE` | `4` | Max level-ups in a 60s window |
| Suspicion threshold | `0.75` | Behavioral score above this is rejected |
| Behavioral profile TTL | `2 hours` | Fingerprinting data lifetime |

---

## API Reference

All endpoints return JSON. Standard HTTP status codes: 200 (success), 400 (bad request), 401 (unauthorized), 429 (rate-limited), 500 (server error).

All protected endpoints accept a session ID via the **`X-Session-Id` HTTP header**.

### Python-compatible `/api` prefix

Every route is also served under the `/api` prefix for drop-in compatibility with the production (Python) server and the TardQuest Online client/gameServer:

- `POST /api/auth/login`, `/api/auth/online/login`, `/api/auth/online/verify`, etc.
- `POST /api/start`, `/api/update`
- `GET|POST /api/leaderboard`
- `GET|POST /api/pigeon/*`, `GET /api/abuse`
- `GET|POST /api/launcher-win64`, `GET /api/launcher-linux`

So both `POST /start` and `POST /api/start` work, and the TQO gameServer can verify bearer tokens against `POST /api/auth/online/verify`.

### `GET /status`

Server health check.

**Response:** `{ "status": "ok", "version": "x.y.z" }`

### `POST /start`

Create a new game session.

**Request:** `{ "version": "x.y.z" }`

**Response:** `{ "session_id": "uuid", "server_version": "x.y.z" }`

Returns a PoW challenge (challenge_id, challenge_salt, challenge_difficulty) when VocaGuard is enabled.

**Client version compatibility:** clients `>= minSupportedClientVersion` (default `3.0.251113`) are accepted. Legacy 3.x clients can play, update progress, use pigeons, and fetch the leaderboard (gravestones), but **cannot submit to the leaderboard** — `POST /leaderboard` returns `400` with an `update_required` error telling them to update their client. Clients below `minSupportedClientVersion` are rejected outright.

### `POST /update`

Update session progress (floor, level, EXP).

**Headers:** `X-Session-Id: <session_id>`

**Rate limit:** 10 per minute.

### `GET /leaderboard`

Retrieve current leaderboard entries sorted by floor DESC, level DESC.

### `POST /leaderboard`

Submit a leaderboard entry. Validates progress against VocaGuard session and verifies PoW.

**Headers:** `X-Session-Id: <session_id>`

**Name validation:** 1–5 alphanumeric characters, no spaces.

### `POST /pigeon/purchase`

Purchase a carrier pigeon. Limited to `maxPigeonsPerSession` (default 20).

**Rate limit:** 20 per hour.

### `POST /pigeon/send`

Send a pigeon message. Consumes one carrier pigeon from inventory.

**Message sanitization:** NFC normalization, HTML entity/tag removal, protocol URL stripping, zero-width/control character removal, character whitelist, length cap (420 chars), repeated punctuation collapse.

### `POST /pigeon/delivery`

Retrieve a pending pigeon message for the session. Weighted random selection (floor proximity, message age, repeat-sender penalty, jitter).

### `GET /pigeon/murder`

Global pigeon murder statistics. Scope to session via `X-Session-Id` header.

### `POST /pigeon/murder`

Report a pigeon murder.

**Rate limit:** 30 per hour.

### `GET /abuse`

Admin endpoint. Requires whitelisted IP (see `json/whitelist.json`). Returns flagged IPs, event counts, VocaGuard events, and optional behavioral fingerprinting data.

---

## Database

The application uses **SQLite** via `better-sqlite3` for storing game data:

| Table | Purpose |
|-------|---------|
| `sessions` | Player game sessions |
| `leaderboard` | Submitted scores |
| `pigeon_messages` | Player-to-player messages |
| `pigeon_inventory` | Carrier pigeon ownership |
| `murder_stats` | Pigeon murder tracking |
| `vocaguard_profiles` | Behavioral fingerprint data |
| `pow_challenges` | Proof-of-Work challenge state |

The database is auto-created at startup using `CREATE TABLE IF NOT EXISTS`. No migrations are needed.

**Pragmas:** `journal_mode = WAL`, `synchronous = NORMAL`, `foreign_keys = ON`

---

## Security

### Anti-Cheat (VocaGuard)

Three-layer built-in protection:

1. **Proof of Work** — SHA-256 challenge for new sessions; find a nonce producing N leading zero bits
2. **Progress Validation** — Rejects floor/level/EXP regression, floor skips, speed hacks, level-jumps, insufficient EXP, and level-up spam
3. **Behavioral Fingerprinting** — Tracks update timing, floor durations, level-up intervals; computes coefficient of variation to detect bot-like mechanical patterns

### Input Sanitization

- **Pigeon messages** — HTML entity decoding, protocol URL stripping, zero-width Unicode removal, configurable character whitelist
- **Leaderboard names** — HTML entity decoding, character restriction `[A-Za-z0-9_ ]`, XSS keyword blacklist
- **HTTP body limit** — 100kb JSON/URL-encoded payload cap

### Additional Protections

- **Rate limiting** — Per-IP throttling on all endpoints
- **CORS** — Restricted to whitelisted origins
- **Security headers** — Applied via standard `helmet` middleware
- **Session expiry** — Automatic cleanup of old sessions (7-day retention)
- **IP flagging** — Automatic blocking after abuse thresholds
- **Auth backoff** — Exponential backoff on repeated auth failures
- **Audit logging** — All requests logged with IP, method, path, status, user-agent, referer; sensitive fields redacted
