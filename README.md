# TardQuest API

A Flask-based REST API server for [TardQuest](https://github.com/packardbell95/tardquest)

## Features

- Session Management (VocaGuard) with anti-cheat checks
- Leaderboard (sorted by floor then level)
- Pigeon Messaging with weighted, progress-aware delivery
- Abuse Protection & Rate Limiting (Flask-Limiter)
- Captcha Verification (hCaptcha and Cloudflare Turnstile)
- HTTPS Support (self-signed or CA certificates)
- CORS with an allowlist of origins
- SQLite-backed persistence (no more JSON file storage)

## What's new

- Storage migrated to SQLite (`tardquest.db`) for sessions, pigeons, leaderboard, and abuse data.
- Pigeon delivery now uses weighted selection favoring similar progress, older messages, and verified senders with anti-repetition.

## Installation

1) Clone the repository
```powershell
git clone https://github.com/VocaPepper/tardquest-api.git
cd tardquest-api
```

2) Install dependencies
```powershell
pip install -r requirements.txt
```

3) Configure environment
Create a `.env` file in the project root:
```dotenv
HCAPTCHA_SECRET=your_hcaptcha_secret_here
TURNSTILE_SECRET=your_turnstile_secret_here
TARDQUEST_ABUSE_KEY=your_admin_key_here
```

## SSL certificate setup (development)

Generate self-signed certs for local HTTPS.

1) Create the `ssl` directory (PowerShell)
```powershell
New-Item -ItemType Directory -Force ssl | Out-Null
Set-Location ssl
```

2) Generate a private key
```powershell
openssl genrsa -out priv-key.pem 2048
```

3) Generate a certificate signing request (CSR)
```powershell
openssl req -new -key priv-key.pem -out certificate.csr
```

4) Generate a self-signed certificate (valid for 365 days)
```powershell
openssl x509 -req -days 365 -in certificate.csr -signkey priv-key.pem -out certificate.pem
```

5) Optional: remove the CSR
```powershell
Remove-Item certificate.csr
```

Paths expected by the app:
- `ssl/certificate.pem`
- `ssl/priv-key.pem`

Note: Browsers will warn on self-signed certs. Use a trusted CA for production.

## Running the server

The app binds to all interfaces on port 9601 and requires SSL certs.

```powershell
# From the project root
python .\TardQuest_API.py
```

- URL: `https://<your-hostname-or-ip>:9601`
- For local testing: `https://localhost:9601`

## API endpoints

### VocaGuard (session management)
- POST `/api/vocaguard/start` – Create a session ID
- POST `/api/vocaguard/update` – Update floor/level with anti-cheat checks
- POST `/api/vocaguard/validate` – Validate final submission before leaderboard post

### Leaderboard
- GET `/api/leaderboard/status` – Health check
- GET `/api/leaderboard` – Sorted leaderboard data
- POST `/api/leaderboard` – Submit an entry (requires captcha + valid session)

### Pigeons
- GET `/api/pigeon/inventory` – Get session’s pigeon count
- POST `/api/pigeon/purchase` – Buy a pigeon (rate-limited)
- POST `/api/pigeon/send` – Send a sanitized message (uses inventory)
- POST `/api/pigeon/delivery` – Receive one message
  - Delivery uses weighted random selection with:
    - Preference for similar floors (±2 by default)
    - Age boost for older messages
    - Bonus for verified senders
    - Penalty to avoid delivering from the same sender twice in a row

### Abuse monitoring
- GET `/api/abuse/status?key=...` – Admin-only metrics if `TARDQUEST_ABUSE_KEY` is set

## Configuration

- CORS origins (in code):
  - `http://localhost:5500`, `http://localhost:9599`, `https://vocapepper.com`, `https://milklounge.wang`
  - Adjust in `TardQuest_API.py` where `CORS(app, origins=[...])` is configured.
- Rate limits:
  - Default: 100/hour per IP
  - Pigeon purchase: 20/hour per IP
  - Pigeon send: 5/minute per IP
  - Delivery: 5/minute per IP
- Session settings:
  - Timeout: 120 minutes (renews on updates)
  - Inventory cap: 20 pigeons per session

## Data storage (SQLite)

Data is stored in `tardquest.db` in the project directory with the following tables:
- `sessions(session_id, floor, level, expires, created, inv, last_level_update, last_floor_update, last_message_received_at, last_from_session_delivered, verified)`
- `leaderboard(id, name, floor, level)`
- `pigeons(id, text, from_session, from_floor, from_level, from_verified, created, delivered, delivered_at, delivered_to)`
- `abuse_events(id, ts, ip, metric, sid, extra)`
- `abuse_flagged(ip, until, counts)`

Note: Earlier JSON files are no longer used. If you have legacy data, create a one-time migration script to import into SQLite.

## Security notes

- Captcha is required for leaderboard submissions (hCaptcha or Turnstile)
- Inputs are sanitized, and rate limits help mitigate abuse
- For production, use a trusted TLS certificate and consider a persistent rate-limit storage backend (e.g., Redis)

## Troubleshooting

- SSL file not found: ensure `ssl/certificate.pem` and `ssl/priv-key.pem` exist.
- CORS errors: add your frontend origin to the CORS allowlist in code.
