# TardQuest API

A Flask-based REST API server for [TardQuest](https://github.com/packardbell95/tardquest)

## Features

- **Session Management**: VocaGuard system for secure session handling
- **Leaderboard**: Track and display player rankings
- **Pigeon Messaging**: In-game messaging system with purchase and delivery mechanics
- **Abuse Protection & Rate Limiting**: Monitors and flags suspicious activity, with configurable limits to prevent spam and abuse
- **Captcha Verification**: Supports hCaptcha and Cloudflare Turnstile for bot prevention
- **HTTPS Support**: Secure communication with SSL/TLS certificates

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/VocaPepper/tardquest-api.git
   cd tardquest-api
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file in the root directory with your configuration:
   ```env
   HCAPTCHA_SECRET=your_hcaptcha_secret_here
   TURNSTILE_SECRET=your_turnstile_secret_here
   TARDQUEST_ABUSE_KEY=your_admin_key_here
   ```

## SSL Certificate Setup

The API requires SSL certificates for HTTPS. You can generate self-signed certificates for development/testing purposes.

### Generating Self-Signed Certificates

1. Ensure you have OpenSSL installed on your system.

2. Create the `ssl` directory if it doesn't exist:
   ```bash
   mkdir ssl
   cd ssl
   ```

3. Generate a private key:
   ```bash
   openssl genrsa -out priv-key.pem 2048
   ```

4. Generate a certificate signing request (CSR):
   ```bash
   openssl req -new -key priv-key.pem -out certificate.csr
   ```
   Fill in the required information when prompted (you can use dummy values for development).

5. Generate the self-signed certificate:
   ```bash
   openssl x509 -req -days 365 -in certificate.csr -signkey priv-key.pem -out certificate.pem
   ```

6. Clean up the CSR file (optional):
   ```bash
   rm certificate.csr
   ```

Your certificates will be saved as:
- `ssl/certificate.pem` (public certificate)
- `ssl/priv-key.pem` (private key)

**Note**: Self-signed certificates will show security warnings in browsers. For production, use certificates from a trusted Certificate Authority (CA).

## Running the Server

1. Ensure the SSL certificates are in place in the `ssl/` directory.

2. Run the server:
   ```bash
   python TardQuest_API.py
   ```

The server will start on `https://localhost:9601` by default.  
If accessed from another machine on your network, use your server's local IP address instead of `localhost`.
> [!NOTE]
> You will want to append a port on `CORS(app, origins=["http://localhost"])` to match your local development server.

## API Endpoints

### Session Management (Vocaguard)
- `POST /api/vocaguard/start` - Start a new session
- `POST /api/vocaguard/update` - Update session data
- `POST /api/vocaguard/validate` - Validate session

### Leaderboard
- `GET /api/leaderboard/status` - Get leaderboard status
- `GET /api/leaderboard` - Retrieve leaderboard data
- `POST /api/leaderboard` - Submit leaderboard entry

### Pigeon Messaging
- `GET /api/pigeon/inventory` - Get pigeon inventory
- `POST /api/pigeon/purchase` - Purchase pigeons
- `POST /api/pigeon/send` - Send a pigeon message
- `POST /api/pigeon/delivery` - Mark pigeon as delivered

### Abuse Monitoring
- `GET /api/abuse/status` - Get abuse monitoring status (requires admin key)

## Configuration

### Environment Variables
- `HCAPTCHA_SECRET`: Your hCaptcha secret key
- `TURNSTILE_SECRET`: Your Cloudflare Turnstile secret key
- `TARDQUEST_ABUSE_KEY`: Admin key for accessing abuse metrics

### Rate Limits
- Default: 100 requests per hour per IP
- Pigeon purchases: 20 per hour per IP
- Configurable in the source code

### Session Settings
- Session timeout: 120 minutes (2 hours)
- Maximum pigeons per session: 20

### Abuse Protection
- Monitoring window: 1 hour
- Duplicate attempt threshold: 2
- Sanitize rejection threshold: 2
- Captcha failure threshold: 2
- Flag duration: 1 hour

## Data Files

The API stores data in JSON files in the root directory:
- `tardboard.json` - Leaderboard data
- `sessions.json` - Active sessions
- `pigeons.json` - Pigeon messages
- `abuse_events.json` - Abuse monitoring events

## Security Features

- **Input Sanitization**: All user inputs are sanitized to [prevent XSS and injection attacks](https://vocapepper.com/img/xss.png)
- **Rate Limiting**: Prevents abuse and spam
- **Captcha Verification**: Multiple captcha providers supported
- **Abuse Detection**: Automatic flagging of suspicious activity
- **HTTPS Only**: All communication is encrypted
- **CORS Protection**: Configurable origins allowed

## Development

For development, you can run the server without SSL by modifying the `app.run()` call in `TardQuest_API.py`. However, this is not recommended for production.
