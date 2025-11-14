# TardQuest API

A Flask-based REST API for the TardQuest game featuring anti-cheat protection, leaderboard management, and a carrier pigeon messaging system.

## Features

- **VocaGuard Anti-Cheat**: Server-enforced game progress validation with proof-of-work challenges
- **Leaderboard**: Player rankings with captcha protection
- **Carrier Pigeon Messaging**: Proximity-based message delivery between players
- **SQLite Database**: Persistent storage for sessions, leaderboard, and messages
- **Rate Limiting**: Protection against spam and abuse
- **Version Tracking**: API version validation on session creation

## Quick Start

### Prerequisites

- Python 3.8+
- pip

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/VocaPepper/tardquest-api.git
   cd tardquest-api
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the API (Development Server)**
   ```bash
   python TardQuest_API.py
   ```

   The API will start on `http://0.0.0.0:9601`

## Configuration

### Environment Variables

Create a `.env` file in the root directory to configure the API:

```env
# Cloudflare Turnstile secret for captcha verification
TURNSTILE_SECRET=your_turnstile_secret_key

# Enable/disable VocaGuard anti-cheat validation (default: true)
ENABLE_VOCAGUARD=true
```

### Core Settings

The following constants are configured in `TardQuest_API.py`:

| Setting | Value | Purpose |
|---------|-------|---------|
| **API Port** | 9601 | Server listening port |
| **API Version** | 3.0.251109 | Format: MAJOR.MINOR.YYMMDD for backward compatibility |
| **Session Timeout** | 120 minutes | Duration before session expires (resets on each update) |
| **Session Purge Age** | 7 days | Old sessions automatically deleted |
| **Max Pigeons** | 20 per session | Maximum carrier pigeons a player can hold |
| **Message Length** | 420 characters | Maximum message length via pigeon |
| **Rate Limits** | 10/min (update), 5/min (message), 20/hr (pigeon purchase) | Per IP address |
| **PoW Challenge Expiry** | 24 hours | Challenge validity window before expiration |

### Logging & Configuration Files

All runtime data and logs are stored as JSON files:

| File | Purpose |
|------|---------|
| `tardquest.db` | SQLite database (auto-created) |
| `vocaguard.json` | VocaGuard validation errors, rejections, and anti-cheat detections |
| `log.json` | General server errors and non-VocaGuard issues |
| `flagged.json` | Flagged IP addresses with abuse metrics and expiration times |
| `whitelist.json` | Whitelisted admin IP addresses for `/api/abuse` endpoint |

## API Endpoints

### Health & Status
- `GET /api/status` - Health check with API version information

### Session Management
- `POST /api/start` - Create new session with version validation and PoW challenge
  - **Required**: `version` field (client API version, major.minor must match server)
  - **Returns**: `session_id`, `server_version`, and optionally `challenge_id` + `challenge_secret` if PoW enabled
- `POST /api/update` - Update game progress with anti-cheat validation
  - **Required**: `session_id`, `floor`, `level`
  - **Returns**: `{"status": "updated"}` on success

### Leaderboard
- `GET /api/leaderboard` - Retrieve ranked list of player scores
- `POST /api/leaderboard` - Submit score to leaderboard
  - **Required**: `session_id`, `name`, `floor`, `level`
  - **Optional**: `challenge_id`, `challenge_proof` (required if session created via `/api/start`)
  - **Note**: Validates submission matches session progress if PoW enabled

### Carrier Pigeon (Messaging)
- `GET /api/pigeon/inventory?session_id={id}` - Check pigeon count for session
- `POST /api/pigeon/purchase` - Purchase a carrier pigeon
- `POST /api/pigeon/send` - Send a message via pigeon
- `POST /api/pigeon/delivery` - Receive pending messages

### Admin (IP Whitelisted Only)
- `GET /api/abuse` - View detailed abuse metrics and flagged IPs (requires whitelisted IP)

### Legacy VocaGuard Endpoints (Deprecated, use `/api/start` and `/api/update`)
- `POST /api/vocaguard/start` - Legacy session creation
- `POST /api/vocaguard/update` - Legacy progress update
- `POST /api/vocaguard/validate` - Legacy submission validation

> [!WARNING]
> These endpoints will be removed after client API updates hit production.

## VocaGuard Anti-Cheat System

### Overview

VocaGuard is a modular anti-cheat system that validates game progress through multiple layers:

1. **Proof-of-Work Challenge**: Cryptographic validation that client has server-issued secret
2. **Progress Validation**: Detects impossible game states (regression, speed hacks, floor skips)
3. **Submission Validation**: Ensures leaderboard submissions match session-tracked progress

### How It Works

#### Session Creation Flow
```
Client: POST /api/start with version "3.0.251109"
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
| **Floor Skips** | Can only advance 1 floor at a time (no jumping) |
| **Level Jumps** | Can only advance 1 level at a time on same floor |
| **Level Speed Hack** | Minimum 10 seconds required between level increments |
| **Floor Speed Hack** | Minimum 10 seconds required between floor increments |

Violations are logged to `vocaguard.json` with detailed metadata for analysis.

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
    floor INTEGER,
    level INTEGER,
    expires TEXT,
    created TEXT,
    inv TEXT,
    last_level_update TEXT,
    last_floor_update TEXT,
    last_message_received_at TEXT,
    last_from_session_delivered TEXT,
    verified INTEGER,
    created_via TEXT  -- 'api_start' (PoW enabled) or 'vocaguard_legacy' (legacy)
)
```

#### leaderboard
```sql
CREATE TABLE leaderboard (
    name TEXT,
    floor INTEGER,
    level INTEGER
)
```

#### pigeons
```sql
CREATE TABLE pigeons (
    from_session_id TEXT,
    to_session_id TEXT,
    message TEXT,
    expires TEXT
)
```

### Maintenance

- **Old sessions**: Automatically purged after 7 days of inactivity
- **Database optimization**: WAL mode enabled, pragma optimizations applied
- **Backup**: Manually backup `tardquest.db` for production deployments

## Deployment

### Development Server

```bash
python TardQuest_API.py
```

Starts unencrypted HTTP server on `http://0.0.0.0:9601`. Suitable for local testing only.

### HTTPS/SSL (Production)

For HTTPS support, place SSL certificates in the `ssl/` directory:

```
ssl/
  ├── certificate.pem    # SSL certificate
  └── priv-key.pem       # Private key
```

The API will automatically detect these files and enable HTTPS. Update client configuration to use `https://` URLs.

### Port Configuration

Change the default port by editing `TardQuest_API.py`:

```python
if __name__ == '__main__':
    # Change 9601 to desired port
    app.run(host='0.0.0.0', port=9601, ssl_context=ssl_context if ssl_required else None)
```

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
    new_floor=1,
    new_level=6,
    last_level_update='2025-11-08T12:00:00.000000',
    last_floor_update='2025-11-08T11:00:00.000000'
)

if not is_valid:
    print(f"Validation failed: {error_message}")
    print(f"Details: {abuse_details}")
    # Returns: {
    #   "cheat_type": "level_speed_hack",
    #   "time_since_last_seconds": 5.2,
    #   "min_required_seconds": 10
    # }
```

**Return values:**
- `is_valid` (bool): Whether update passed all checks
- `error_message` (str): Human-readable error description
- `abuse_details` (dict): Cheat detection metadata with `cheat_type` and relevant values

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

Periodically remove expired challenges from memory (call during maintenance):

```python
expired_count = validator.cleanup_expired_challenges()
print(f"Removed {expired_count} expired challenges")
```

## Client Integration

### Configuration Overview

Each client component requires configuration with the API base URL. Update the following files in your TardQuest client:

| Component | File | Config Variable |
|-----------|------|-----------------|
| Leaderboard & Anti-Cheat | `tardboard.js` | `API_BASE`, `TURNSTILE_SITE_KEY` |
| Carrier Pigeon Messaging | `pigeon.js` | `API_BASE` |
| Game Merchant | `game.html` | Fetch URL in merchant code |
| API Test Suite | `APITest.html` | `API_BASE`, `CLIENT_API_VERSION`, `TURNSTILE_SITE_KEY` |

### TardBoard (Leaderboard + Anti-Cheat)

Edit `tardboard.js`:

```javascript
// API Configuration
const API_BASE = 'http://your-domain-or-ip:9601';

// Cloudflare Turnstile Captcha
const TURNSTILE_SITE_KEY = 'your-site-key';
```

When creating a session, the client sends:
```javascript
fetch(`${API_BASE}/api/start`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ version: '3.0.251109' })  // Must match server major.minor
})
```

On submission, if PoW is enabled, client computes:
```javascript
const proof = SHA256(challengeSecret + sessionId);
// Include proof in leaderboard submission
```

### Carrier Pigeon (Messaging System)

Edit `pigeon.js`:

```javascript
// API Configuration
const API_BASE = 'http://your-domain-or-ip:9601';
```

> [!WARNING]
> Carrier Pigeon is currently dependent on `tardboard.js` for session management!

### Game Merchant (Pigeon Purchase)

Edit `game.html` and update the merchant's pigeon purchase code:

```javascript
fetch('http://your-domain-or-ip:9601/api/pigeon/purchase', {
   method: 'POST',
   headers: { 'Content-Type': 'application/json' },
   body: JSON.stringify({ session_id: sessionId })
})
```

### API Test Suite

Edit `APITest.html` for local testing:

```javascript
// API Configuration
const API_BASE = 'http://your-domain-or-ip:9601';
const CLIENT_API_VERSION = '3.0.x';  // Must match server major.minor version

// Cloudflare Turnstile Captcha
const TURNSTILE_SITE_KEY = 'your-site-key';
```

When starting a new session in tests:
```javascript
fetch(`${API_BASE}/api/start`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ version: CLIENT_API_VERSION })
})
```

The test suite automatically handles PoW computation, challenge storage, and verification.

## Access Control

### IP Whitelisting for Admin Endpoints

The `/api/abuse` endpoint is protected by IP whitelisting. Only requests from whitelisted IPs can access admin functionality.

#### Configure Whitelist

Edit `whitelist.json`:

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

Unauthorized access attempts are logged to `log.json`.

## License

MIT
