# TardQuest API

Node.js/Express API server for the TardQuest dungeon-crawler. This document covers the public gameplay API.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Database](#database)
- [Security](#security)
- [License](#license)

---

## Quick Start

### Requirements

- Node.js 18+
- SQLite database (created automatically)

### Setup

```bash
npm install
npm run build:public
npm run start:public
```

Health check: `curl http://localhost:9601/status`

### Production

Run behind a reverse proxy (IIS, nginx, or equivalent) that handles HTTPS termination and forwarded headers. The `/status` endpoint can serve as a load-balancer health check.

The native `better-sqlite3` dependency must be compiled for the target platform. Runtime state is stored under `data/`, JSON state under `json/`, and logs under `logs/`.

---

## Internal profile

An internal-only profile extends the public gameplay API with account authentication and (deprecated) launcher-manifest endpoints. It is not part of the public release because those capabilities depend on private infrastructure and administrative authorization. Build and deployment details are intentionally omitted from this public documentation.

---

## Configuration

The server works with the committed defaults. Copy the values you need into `.env` to override them at runtime.

**`server.config.js`** (project root) contains all default settings. Edit it to adjust server, gameplay, or abuse thresholds.

| Key | Default | Description |
|-----|---------|-------------|
| `deployMode` | `prod` | `prod` enforces rate limits; `dev` unlocks them (set via `DEPLOY_MODE` env; defaults to `prod` if unset) |
| `host` | `0.0.0.0` | Listen address |
| `port` | `9601` | Listen port |
| `apiVersion` | *(from `package.json`)* | Reported in status endpoint |
| `minClientVersion` | *(from `package.json`)* | Minimum client version for full features |
| `minSupportedClientVersion` | `3.0.251113` | Minimum client version for limited features |
| `bodyLimit` | `100kb` | Max JSON/URL-encoded payload size |
| `sqliteDbPath` | `./data/tardquest.db` | SQLite database file |
| `dbConnectionTimeoutSeconds` | `30` | Database connection timeout |
| `enableVocaguard` | `true` | Master switch for anti-cheat |
| `powDifficultyPrefixZeros` | `4` | Leading zero hexadecimal characters required (1–8) |
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
| `corsOrigins` | `http://localhost:3000` | Allowed CORS origin list |

Rate limiting currently uses the default in-memory store from `express-rate-limit`, so limits are local to each Node process.

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

All endpoints return JSON. Common status codes are 200 (success), 201 (created), 400 (bad request), 401 (unauthorized), 403 (forbidden), 429 (rate-limited), 500 (server error), and 503 (dependency unavailable).

Session identifiers are supplied per endpoint: most POST routes use a JSON `session_id`, while pigeon inventory and the GET murder-statistics route use `X-Session-Id`.

### `/api` compatibility prefix

Every registered public route is also mounted under `/api`. For example, both `POST /start` and `POST /api/start` work.

### `GET /status`

Server health check.

**Response:** `{ "status": "ok", "version": "x.y.z" }`

### `POST /start`

Create a new game session.

**Request:** `{ "version": "x.y.z" }`

**Response:** `{ "session_id": "uuid", "server_version": "x.y.z" }`

Returns `challenge_id`, `challenge_salt`, and `challenge_difficulty` when VocaGuard is enabled. The challenge is used for guest leaderboard submissions and death submissions.

**Client version compatibility:** clients `>= minSupportedClientVersion` (default `3.0.251113`) are accepted. Legacy 3.x clients can play, update progress, use pigeons, and fetch the leaderboard (gravestones), but **cannot submit to the leaderboard** — `POST /leaderboard` returns `400` with an `update_required` error telling them to update their client. Clients below `minSupportedClientVersion` are rejected outright.

### `POST /update`

Update session progress (floor, level, EXP). Send `session_id`, `floor`, `level`, and `exp` in the JSON body. Set `died` to `true` for a final death submission and include the PoW challenge fields when VocaGuard is enabled.

**Body:** `{ "session_id": "uuid", "floor": 2, "level": 1, "exp": 50 }`

**Rate limit:** 10 per minute.

### `GET /leaderboard`

Retrieve current leaderboard entries sorted by floor DESC, level DESC.

### `POST /leaderboard`

Submit a leaderboard entry. Validates progress against VocaGuard session and verifies PoW.

**Body:** `{ "session_id": "uuid", "name": "PLAYER", "floor": 2, "level": 1 }`

Guest names are limited to five alphanumeric characters or spaces.

### `POST /pigeon/purchase`

Purchase a carrier pigeon. Limited to `maxPigeonsPerSession` (default 20).

**Rate limit:** 20 per hour.

### `GET /pigeon/inventory`

Return the current carrier-pigeon count. Requires `X-Session-Id: <session_id>`.

### `POST /pigeon/send`

Send a pigeon message. Consumes one carrier pigeon from inventory.

**Message sanitization:** NFC normalization, HTML entity/tag removal, protocol URL stripping, zero-width/control-character removal, character whitelist, length cap (420 chars), and repeated-punctuation collapse.

**Rate limit:** 5 per minute.

### `POST /pigeon/delivery`

Retrieve a pending pigeon message for the session. Weighted random selection (floor proximity, message age, repeat-sender penalty, jitter).

**Rate limit:** 5 per minute.

### `GET /pigeon/murder`

Global pigeon murder statistics. Scope to session via `X-Session-Id` header.

### `POST /pigeon/murder`

Report a pigeon murder.

**Rate limit:** 30 per hour.

### `GET /abuse`

Admin endpoint. Requires whitelisted IP (see `json/whitelist.json`). Returns flagged IPs, event counts, VocaGuard events, and optional behavioral fingerprinting data.

---

## Database

The public gameplay profile uses **SQLite** via `better-sqlite3`:

| Table | Purpose |
|-------|---------|
| `sessions` | Player game sessions |
| `leaderboard` | Submitted scores |
| `pigeons` | Player-to-player messages and delivery state |
| `pigeon_murders` | Pigeon murder reports |

The database and tables are created at startup with `CREATE TABLE IF NOT EXISTS`. Existing `sessions` tables receive the `client_version` and `died_at` columns when needed.

**Pragmas:** `journal_mode = WAL`, `synchronous = NORMAL`, `foreign_keys = ON`

---

## Security

### Anti-Cheat (VocaGuard)

Three-layer built-in protection:

1. **Proof of Work** — SHA-256 challenge for new sessions; find a nonce producing N leading zero hexadecimal characters
2. **Progress Validation** — Rejects floor/level/EXP regression, floor skips, speed hacks, level-jumps, insufficient EXP, and level-up spam
3. **Behavioral Fingerprinting** — Tracks update timing, floor durations, level-up intervals; computes coefficient of variation to detect bot-like mechanical patterns

### Input Sanitization

- **Pigeon messages** — HTML entity/tag removal, protocol URL stripping, zero-width Unicode removal, configurable character whitelist
- **Leaderboard names** — entity/tag removal, character restriction, and dangerous-term filtering
- **HTTP body limit** — 100kb JSON/URL-encoded payload cap

### Additional Protections

- **Rate limiting** — Per-IP throttling on all endpoints
- **CORS** — Restricted to whitelisted origins
- **Security headers** — Applied via standard `helmet` middleware
- **Session expiry** — Automatic cleanup of old sessions (7-day retention)
- **IP flagging** — Automatic blocking after abuse thresholds
- **Auth backoff** — Exponential backoff on repeated auth failures
- **Audit logging** — All requests logged with IP, method, path, status, user-agent, referer; sensitive fields redacted

---

## License

This project is licensed under the [MIT License](../../LICENSE). You may use, modify, and redistribute it under those terms.
