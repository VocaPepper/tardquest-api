# TardQuest API

A Flask-based REST API for the TardQuest game featuring anti-cheat protection, leaderboard management, and a carrier pigeon messaging system.

## Features

- **VocaGuard Anti-Cheat**: Session-based progress validation with rate limiting
- **Leaderboard**: Player rankings with captcha protection
- **Carrier Pigeon Messaging**: Proximity-based message delivery between players
- **SQLite Database**: Persistent storage for sessions, leaderboard, and messages.
- **Rate Limiting**: Protection against spam and abuse

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

3. **Configure environment variables**
   
   Create a `.env` file in the root directory:
   ```env
   TURNSTILE_SECRET=your_turnstile_secret_key
   ```

4. **Run the API (Development Server)**
   ```bash
   python TardQuest_API.py
   ```

   The API will start on `http://0.0.0.0:9601`

### SSL/HTTPS (Optional)

For HTTPS support, place SSL certificates in the `ssl/` directory:
- `ssl/certificate.pem`
- `ssl/priv-key.pem`

## API Endpoints

### VocaGuard (Anti-Cheat)
- `POST /api/vocaguard/start` - Start new session
- `POST /api/vocaguard/update` - Update progress
- `POST /api/vocaguard/validate` - Validate final submission

### Leaderboard
- `GET /api/leaderboard/status` - API health check
- `GET /api/leaderboard` - Get rankings
- `POST /api/leaderboard` - Submit score (requires captcha)

### Carrier Pigeon
- `GET /api/pigeon/inventory` - Check pigeon count
- `POST /api/pigeon/purchase` - Buy a pigeon
- `POST /api/pigeon/send` - Send a message
- `POST /api/pigeon/delivery` - Receive a message

### Admin (Whitelisted IPs Only)
- `GET /api/abuse/status` - View abuse metrics (requires whitelisted IP)

## Access Control

### IP Whitelisting

The `/api/abuse/status` endpoint is protected by IP whitelisting. Whitelisted IPs are stored in `whitelist.json`:

```json
{
  "ips": [
    "127.0.0.1",
    "::1"
  ],
  "updated": "2025-11-04T00:00:00.000000",
  "_comment": "Add your admin IP addresses here to grant access to /api/abuse/status. Only requests from these IPs will be allowed."
}
```

Only requests from whitelisted IP addresses will be granted access to abuse metrics. Unauthorized access attempts are logged to `log.json`.

## Client Configuration

The TardQuest client (JavaScript) communicates with this API and requires the following configuration:

### Enable TardBoard (Leaderboard + Anti-Cheat Integration)

Edit `tardboard.js` client module:

```javascript
// API Configuration
const API_BASE = 'http://your-domain-or-ip:9601';

// Cloudflare Turnstile Captcha
const TURNSTILE_SITE_KEY = 'your-site-key';
```

### Enable Carrier Pigeon (Messaging System)

Edit `pigeon.js` client module:

```javascript
// API Configuration
const API_BASE = 'http://your-domain-or-ip:9601';
```
### Enable Carrier Pigeon Purchase on Merchant

Edit `game.html` and under `const merchant` look for the following:

```javascript
fetch('http://your-domain-or-ip:9601/api/pigeon/purchase', {
   method: 'POST',
   headers: { 'Content-Type': 'application/json' },
   body: JSON.stringify({ session_id: sessionId })
})
```

Key settings in `TardQuest_API.py`:

- **Session Timeout**: 120 minutes (resets on update)
- **Max Pigeons**: 20 per session
- **Message Length**: 420 characters max
- **Rate Limits**: Configurable per endpoint
- **Port**: 9601

## Database

The API automatically creates `tardquest.db` with the following tables:
- `leaderboard` - Player rankings
- `sessions` - Active game sessions
- `pigeons` - Message queue

Old sessions are automatically purged after 30 days.

## Logging & Configuration Files

Error and rejection logs are stored as JSON files:
- `vocaguard.json` - VocaGuard-related errors and rejections (session validation, submission rejections, etc.)
- `log.json` - General server errors and other non-VocaGuard issues
- `flagged.json` - Flagged IP addresses with expiration times and abuse metric counts
- `whitelist.json` - IP addresses allowed to access admin endpoints (e.g., `/api/abuse/status`)

## License

MIT
