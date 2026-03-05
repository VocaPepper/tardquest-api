# TardQuest API

A Flask-based REST API for the TardQuest game featuring anti-cheat protection, leaderboard management, and a carrier pigeon messaging system.

## Features

- **VocaGuard Anti-Cheat**: Server-enforced game progress validation with proof-of-work challenges and behavioral fingerprinting
- **Leaderboard**: Player rankings with captcha protection
- **Carrier Pigeon Messaging**: Proximity-based message delivery between players
- **Launcher Manifests**: Versioned launcher distribution for Win64 and Linux
- **SQLite Database**: Persistent storage for sessions, leaderboard, and messages
- **Structured Logging**: Rotating plain-text log files for access, abuse, and errors
- **Rate Limiting**: Protection against spam and abuse
- **Reverse Proxy Support**: Trusted `X-Forwarded-For` via Werkzeug `ProxyFix`
- **Version Tracking**: API version validation on session creation

## Quick Start

### Prerequisites

- Python 3.8+
- pip

### Quick Start (Development Server)

1. **Clone the repository**
   
   ```bash
   git clone https://github.com/VocaPepper/tardquest-api.git
   cd tardquest-api
   ```

2. **Install dependencies**
   
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the API**
   
   ```bash
   python TardQuest_API.py
   ```
   
   The API will start on `http://0.0.0.0:9601`
   
### Reverse Proxy (Production)

SSL/TLS is expected to be terminated by a reverse proxy (e.g. nginx, Caddy). The app trusts one hop of `X-Forwarded-For` via Werkzeug `ProxyFix`, so `request.remote_addr` will reflect the real client IP. Adjust `x_for` in `ProxyFix(...)` if you have multiple proxy layers.

## Configuration

### Environment Variables

Create a `.env` file in the root directory to configure the API:

```env
# Cloudflare Turnstile secret for captcha verification
TURNSTILE_SECRET=your_turnstile_secret_key

# Enable/disable VocaGuard anti-cheat validation (default: true)
ENABLE_VOCAGUARD=true

# API key for launcher manifest POST updates (optional)
MANIFESTO_API_KEY=your_launcher_api_key
```

### Core Settings

The following constants are configured in `TardQuest_API.py`:

| Setting                  | Value                                                     | Purpose                                                 |
| ------------------------ | --------------------------------------------------------- | ------------------------------------------------------- |
| **API Port**             | 9601                                                      | Server listening port                                   |
| **API Version**          | 3.2.260304                                                | Format: MAJOR.MINOR.YYMMDD                              |
| **Min Client Version**   | 3.0.251113                                                | Minimum supported client version for session creation   |
| **Session Timeout**      | 120 minutes                                               | Duration before session expires (resets on each update)  |
| **Session Purge Age**    | 7 days                                                    | Old sessions automatically deleted                      |
| **Max Pigeons**          | 20 per session                                            | Maximum carrier pigeons a player can hold                |
| **Message Length**       | 420 characters                                            | Maximum message length via pigeon                       |
| **Rate Limits**          | 10/min (update), 5/min (message), 20/hr (pigeon purchase) | Per IP address                                          |
| **PoW Challenge Expiry** | 24 hours                                                  | Challenge validity window before expiration              |

### Directory Layout

```
tardquest-api/
├── TardQuest_API.py          # Main application
├── vocaguard.py              # Anti-cheat module
├── tardquest.db              # SQLite database (auto-created)
├── json/                     # Runtime JSON state/config
│   ├── flagged.json          # Flagged IPs with abuse metrics
│   ├── whitelist.json        # Admin whitelisted IPs
│   ├── launcher-win64.json   # Win64 launcher manifest (optional)
│   └── launcher-linux.json   # Linux launcher manifest (optional)
└── logs/                     # Rotating log files (auto-created)
    ├── access.log            # Every HTTP request
    ├── vocaguard.log         # Abuse events, rejections, anti-cheat detections
    └── error.log             # Server errors with tracebacks
```

### Logging

All logs are written as plain-text rotating files under `logs/` (10 MB max, 5 backups). Format varies per logger:

| Log File              | Format                                                        | Purpose                                             |
| --------------------- | ------------------------------------------------------------- | --------------------------------------------------- |
| `logs/access.log`     | `TIMESTAMP IP METHOD PATH USER_AGENT STATUS REFERER`          | Every HTTP request (via `@app.after_request`)       |
| `logs/vocaguard.log`  | `TIMESTAMP\|IP\|METRIC\|key=value ...` (pipe-delimited)       | Abuse events, VocaGuard rejections, anti-cheat hits |
| `logs/error.log`      | `TIMESTAMP\|FUNCTION\|ERROR_TYPE\|MESSAGE\|TRACEBACK context` | Server errors with full stack traces                |

## API Endpoints

### Health & Status

- `GET /api/status` - Health check with API version information

### Session Management

- `POST /api/start` - Create new session with version validation and PoW challenge
  - **Required**: `version` field (client API version, major.minor must match server)
  - **Returns**: `session_id`, `server_version`, and optionally `challenge_id` + `challenge_secret` if PoW enabled
- `POST /api/update` - Update game progress with anti-cheat validation
  - **Required**: `session_id`, `floor`, `level`, `exp`
  - **Returns**: `{"status": "updated"}` on success

### Leaderboard

- `GET /api/leaderboard` - Retrieve ranked list of player scores
- `POST /api/leaderboard` - Submit score to leaderboard
  - **Required**: `session_id`, `name`, `floor`, `level`
  - **Optional**: `challenge_id`, `challenge_proof` (required if session created via `/api/start`)
  - **Note**: Validates submission matches session progress if PoW enabled

### Launcher Manifests

- `GET /api/launcher-win64` - Retrieve the Win64 launcher manifest
- `POST /api/launcher-win64` - Update the Win64 launcher manifest (requires `MANIFESTO_API_KEY`)
  - **Operations**: `upsert_version` (default) or `replace_manifest`
  - **Auth**: `X-API-Key` header or `Authorization: Bearer <key>`
- `GET /api/launcher-linux` - Retrieve the Linux launcher manifest

### Carrier Pigeon (Messaging)

- `GET /api/pigeon/inventory?session_id={id}` - Check pigeon count for session
- `POST /api/pigeon/purchase` - Purchase a carrier pigeon
- `POST /api/pigeon/send` - Send a message via pigeon
- `POST /api/pigeon/delivery` - Receive pending messages

### Admin (IP Whitelisted Only)

- `GET /api/abuse` - View detailed abuse metrics, flagged IPs, and behavioral fingerprint scores (requires whitelisted IP)
  - **Optional query param**: `session_id` to include that session's behavioral suspicion score

## VocaGuard Anti-Cheat System

### Overview

VocaGuard is a modular anti-cheat system that validates game progress through multiple layers:

1. **Proof-of-Work Challenge**: Cryptographic validation that client has server-issued secret
2. **Progress Validation**: Detects impossible game states (regression, speed hacks, floor skips)
3. **Behavioral Fingerprinting**: Timing-pattern analysis to detect bot-like activity
4. **Submission Validation**: Ensures leaderboard submissions match session-tracked progress

### How It Works

#### Session Creation Flow

```
Client: POST /api/start with version "3.2.260304"
         ↓
Server: Version check (major.minor must match)
         ↓
Server: Generate challenge_id (32-char hex) and challenge_secret (64-char hex)
         ↓
Server: Store challenge in memory with 24-hour expiration
         ↓
Server: Return session_id, challenge_id, challenge_secret to client
```

#### Submission Flow

```
Client: Compute proof = SHA256(challenge_secret + session_id)
         ↓
Client: POST /api/leaderboard with challenge_id, challenge_proof, floor, level
         ↓
Server: verify_challenge_proof() → constant-time comparison
         ↓
Server: validate_submission() → verify submitted progress matches session progress
         ↓
Server: Delete challenge from memory (single-use)
         ↓
Server: Post to leaderboard if all checks pass
```

### Anti-Cheat Rules

The validator enforces these rules during `/api/update` calls:

| Rule | Description |
|------|-------------|
| **Floor Regression** | Floor cannot decrease from current value |
| **Level Regression** | Level cannot decrease on the same floor |
| **EXP Regression** | EXP cannot decrease from current value |
| **Floor Skips** | Can only advance 1 floor at a time (no jumping) |
| **Level Jumps** | Can only advance 1 level at a time on the same floor |
| **EXP Validation** | Each level costs more EXP. Level N requires `(N-1)*N/2 * 10` total EXP (Level 1→2=10, Level 2→3=20, Level 3→4=30...) |
| **Floor Speed Hack** | Minimum 10 seconds required between floor increments |
| **Level-Up Spam** | Maximum 4 level-ups per 60 seconds (prevents `/giveexp` abuse) |
| **Behavioral Fingerprinting** | Detects mechanical timing patterns (update-interval regularity, floor-time uniformity, level-up rhythm, burst patterns). Suspicion score ≥ 0.75 rejects the update |

Violations are logged to `logs/vocaguard.log` with detailed metadata for analysis.

### Behavioral Fingerprinting

The `BehavioralFingerprinter` class analyzes server-side timing data to detect bot-like behavior with no client cooperation required. Four signals are tracked:

| Signal | What It Measures | Bot Indicator |
|--------|-----------------|---------------|
| **Update-interval regularity** | Coefficient of variation of time between `/api/update` calls | CV < 0.05 → mechanical |
| **Floor-completion-time uniformity** | CV of time spent on each floor | CV < 0.08 → mechanical |
| **Level-up rhythm** | CV of intervals between level-ups | CV < 0.05 → mechanical |
| **Burst detection** | Whether ≥60% of intervals cluster in the shortest 20% of range | High cluster ratio → scripted |

Signals are averaged into a 0.0–1.0 suspicion score. Analysis activates after 6+ update samples. Profiles are cleaned up after 2 hours (matching the session timeout).

### Enabling/Disabling VocaGuard

Control anti-cheat enforcement via `ENABLE_VOCAGUARD` environment variable:

```env
# Enable full validation (default)
ENABLE_VOCAGUARD=true
```

- **When `true`** (default): All `/api/update` and `/api/leaderboard` requests enforce VocaGuard rules
- **When `false`**: Skip all anti-cheat validation (implement your own or allow unrestricted access)

## Database

### Schema

The API automatically creates `tardquest.db` with the following tables:

#### sessions

```sql
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    floor INTEGER NOT NULL,
    level INTEGER NOT NULL,
    expires TEXT NOT NULL,
    created TEXT NOT NULL,
    inv TEXT NOT NULL,
    last_level_update TEXT,
    last_floor_update TEXT,
    last_message_received_at TEXT,
    last_from_session_delivered TEXT,
    verified INTEGER DEFAULT 0,
    created_via TEXT DEFAULT 'api_start'  -- 'api_start' (PoW enabled) or 'vocaguard_legacy' (legacy)
)
```

#### leaderboard

```sql
CREATE TABLE leaderboard (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    floor INTEGER NOT NULL,
    level INTEGER NOT NULL
)
```

#### pigeons

```sql
CREATE TABLE pigeons (
    id TEXT PRIMARY KEY,
    text TEXT NOT NULL,
    from_session TEXT NOT NULL,
    from_floor INTEGER NOT NULL,
    from_level INTEGER NOT NULL,
    from_verified INTEGER NOT NULL,
    created TEXT NOT NULL,
    delivered INTEGER DEFAULT 0,
    delivered_at TEXT,
    delivered_to TEXT
)
```

### Maintenance

- **Old sessions**: Automatically purged after 7 days by a background thread
- **PoW challenges**: Expired challenges and stale behavioral profiles cleaned up during purge cycle
- **Database optimization**: WAL mode enabled, pragma optimizations applied
- **Backup**: Manually backup `tardquest.db` for production deployments

## Development

### Using VocaGuardValidator Directly

Developers can import and use the `VocaGuardValidator` class directly for custom validation logic:

```python
from vocaguard import VocaGuardValidator

validator = VocaGuardValidator()
```

#### Progress Update Validation

Validate a player's progress update during gameplay:

```python
is_valid, error_message, abuse_details = validator.validate_progress_update(
    current_floor=1,
    current_level=5,
    current_exp=150,
    new_floor=1,
    new_level=6,
    new_exp=210,
    session_id='e8267255-85a8-4175-bd39-5823f6a3faca',
    last_floor_update='2025-11-08T11:00:00.000000'
)

if not is_valid:
    print(f"Validation failed: {error_message}")
    print(f"Details: {abuse_details}")
    # Example abuse_details:
    # {"cheat_type": "levelup_spam", "levelups_in_window": 5, "max_allowed": 4, "window_seconds": 60}
    # {"cheat_type": "behavioral_anomaly", "suspicion_score": 0.82, "interval_cv": 0.03, ...}
```

**Return values:**

- `is_valid` (bool): Whether update passed all checks
- `error_message` (str): Human-readable error description
- `abuse_details` (dict): Cheat detection metadata with `cheat_type` and relevant values

#### Behavioral Scoring

Query the current behavioral suspicion score for a session:

```python
score, details = validator.get_behavior_score(session_id='abc123')
# score: 0.0 (natural) to 1.0 (mechanical)
# details: {'interval_cv': 0.23, 'interval_verdict': 'natural', ...}
```

Clean up a session's behavioral data (e.g. on deletion):

```python
validator.remove_behavior_profile(session_id='abc123')
```

#### Submission Validation

Validate a final submission before posting to leaderboard:

```python
is_valid, error_message = validator.validate_submission(
    session_floor=1,
    session_level=6,
    submitted_floor=1,
    submitted_level=6
)

if not is_valid:
    print(f"Submission rejected: {error_message}")
    # "Progress mismatch: submitted values don't match tracked session progress"
```

#### Challenge Generation & Verification

Generate challenges for sessions:

```python
challenge_id, challenge_secret = validator.generate_challenge(session_id='abc123')
# Returns: ('a1b2c3d4...', 'secret789xyz...')
```

Verify client proof-of-work:

```python
is_valid, error_message = validator.verify_challenge_proof(
    session_id='abc123',
    challenge_id='a1b2c3d4...',
    client_proof='sha256_hex_digest_here'
)
```

#### Cleanup Expired Challenges

Periodically remove expired challenges, stale behavioral profiles, and old level-up history from memory:

```python
expired_count = validator.cleanup_expired_challenges()
print(f"Removed {expired_count} expired items")
```

## Client Integration

### Architecture

The client consists of three separate modules that work together:

1. **TardAPI** - Core session management and progress tracking
2. **TardBoard** - Leaderboard submission and captcha verification  
3. **PigeonMessaging** - Carrier pigeon message system

Each module is independent and can be extended or replaced with custom implementations.

### Module: TardAPI (Session Management)

**File**: `tardAPI.js`

Provides centralized session management, PoW challenge handling, and progress updates.

#### Configuration

Edit `tardAPI.js` to set the API endpoint and client version:

```javascript
// --- Configuration ---

/** @const {string} Base URL for all API endpoints */
const API_BASE = 'http://your-domain-or-ip:9601';

/** @const {string} Client API version (must match server minimum) */
const CLIENT_API_VERSION = '3.2.YYMMDD';

/** @const {string} LocalStorage key for session ID persistence */
const LS_SESSION_KEY = 'tardquestSID';

/** @const {string} LocalStorage key for PoW challenge data */
const LS_CHALLENGE_KEY = 'vocaguardChallengeData';
```

#### Key Features

- **Automatic session creation** - Creates session on first progress update
- **PoW challenge handling** - Generates proof for leaderboard submissions
- **Progress monitoring** - Tracks floor/level changes automatically
- **Session persistence** - Stores session ID in localStorage
- **Version validation** - Sends client version to server for compatibility check

#### Public API

```javascript
// Session Management
await TardAPI.createSession()           // Create new session
await TardAPI.validateSession()         // Validate current session
await TardAPI.updateProgress()          // Send progress to server (automatic)

// Submission
await TardAPI.submitScore(name, options) // Submit leaderboard score

// Leaderboard
await TardAPI.getLeaderboard(options)   // Fetch leaderboard

// Utilities
TardAPI.checkApiStatus()                // Check if API is accessible
TardAPI.getGameState()                  // Get current floor/level
TardAPI.loadSessionFromStorage()        // Restore session from storage
TardAPI.clearSession()                  // Clear session and storage

// Properties
TardAPI.sessionId                       // Get current session ID
TardAPI.hasActiveSession                // Check if session exists
TardAPI.hasChallenge                    // Check if PoW challenge exists
TardAPI.challenge                       // Get challenge data
```

#### Usage Example

```javascript
// Session is created automatically on first progress update
// For manual creation:
const result = await TardAPI.createSession();
if (result.success) {
    console.log('Session created:', result.session_id);
}

// Progress updates are sent automatically every second
// Progress is monitored in the background and sent when floor/level changes

// Submit a score (with automatic PoW proof computation)
const submission = await TardAPI.submitScore('ABC', { captcha_token: token });
if (submission.success) {
    console.log('Score submitted!');
}
```

### Module: TardBoard (Leaderboard)

**File**: `tardboard.js`

Handles leaderboard submission UI and captcha integration.

#### Configuration

Edit `tardboard.js` to set the captcha site key:

```javascript
// --- Constants ---

/** @const {string} Cloudflare Turnstile site key for captcha verification */
const TURNSTILE_SITE_KEY = 'your_turnstile_site_key';
```

### Script Loading Order

**Critical**: Load scripts in this order to ensure all dependencies are satisfied:

```html
<script src="scripts/tardAPI.js"></script>      <!-- Must be first -->
<script src="scripts/tardboard.js"></script>    <!-- Depends on TardAPI -->
<script src="scripts/pigeon.js"></script>       <!-- Depends on TardAPI -->
<!-- ... other scripts ... -->
```

## Access Control

### IP Whitelisting for Admin Endpoints

The `/api/abuse` endpoint is protected by IP whitelisting. Only requests from whitelisted IPs can access admin functionality.

#### Configure Whitelist

Edit `json/whitelist.json`:

```json
{
  "ips": [
    "127.0.0.1",
    "::1",
    "192.168.1.100"
  ],
  "updated": "2025-11-04T00:00:00.000000",
  "_comment": "Add your admin IP addresses here. Only these IPs can access /api/abuse endpoint."
}
```

#### Usage

Retrieve abuse metrics from whitelisted IP:

```bash
curl http://your-api:9601/api/abuse -H "Accept: application/json"
```

Query behavioral score for a specific session:

```bash
curl "http://your-api:9601/api/abuse?session_id=SESSION_UUID" -H "Accept: application/json"
```

Unauthorized access attempts are logged to `logs/error.log`.

## License

MIT
