# TardQuest API

A Flask-based REST API for the TardQuest game featuring anti-cheat protection, leaderboard management, and a carrier pigeon messaging system.

## Features

- **VocaGuard Anti-Cheat**: Session-based progress validation with rate limiting
- **Leaderboard**: Player rankings with captcha protection
- **Carrier Pigeon Messaging**: Proximity-based message delivery between players
- **SQLite Database**: Persistent storage for sessions, messages, and abuse tracking
- **Rate Limiting**: Protection against spam and abuse

## Quick Start

### Prerequisites

- Python 3.8+
- pip

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd tardquest-api
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   
   Create a `.env` file in the root directory:
   ```env
   HCAPTCHA_SECRET=your_hcaptcha_secret_key
   TURNSTILE_SECRET=your_turnstile_secret_key
   TARDQUEST_ABUSE_KEY=your_admin_key_for_abuse_metrics
   ```

4. **Run the API**
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

### Admin
- `GET /api/abuse/status?key=<admin_key>` - View abuse metrics

## Configuration

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
- `abuse_events` - Abuse tracking
- `abuse_flagged` - Flagged IPs

Old sessions are automatically purged after 30 days.

## Development

Run in debug mode (for development only):
```python
app.run(debug=True, host='0.0.0.0', port=9601)
```

## License

MIT
