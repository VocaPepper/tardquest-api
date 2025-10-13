# Import necessary modules
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import os
import uuid
import re
import requests
from datetime import datetime, timedelta
import unicodedata
from dotenv import load_dotenv
import random
import sqlite3
import threading
import time

# Load environment variables from .env file
load_dotenv()

# Initialize Flask application
app = Flask(__name__)
# Enable CORS for specified origins to allow cross-origin requests
CORS(app)

# --- SQLite setup ---
# Single DB file for all data
DB_FILE = os.path.join(os.path.dirname(__file__), "tardquest.db")

def get_db_connection():
    # Open an sqlite3 connection with recommended pragmas for better concurrency
    # Use this helper throughout the code instead of sqlite3.connect(DB_FILE)
    conn = sqlite3.connect(DB_FILE, timeout=30, detect_types=sqlite3.PARSE_DECLTYPES)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
    except Exception:
        # best-effort; do not fail if pragmas are unsupported
        pass
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        # Create leaderboard table if it doesn't exist
        """
        CREATE TABLE IF NOT EXISTS leaderboard (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            floor INTEGER NOT NULL,
            level INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        # Create sessions table if it doesn't exist
        """
        CREATE TABLE IF NOT EXISTS sessions (
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
            verified INTEGER DEFAULT 0
        )
        """
    )
    cur.execute(
        # Create pigeons table if it doesn't exist
        """
        CREATE TABLE IF NOT EXISTS pigeons (
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
        """
    )
    cur.execute(
        # Create abuse_events table if it doesn't exist
        """
        CREATE TABLE IF NOT EXISTS abuse_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            ip TEXT NOT NULL,
            metric TEXT NOT NULL,
            sid TEXT,
            extra TEXT
        )
        """
    )
    cur.execute(
        # Create abuse_flagged table if it doesn't exist
        """
        CREATE TABLE IF NOT EXISTS abuse_flagged (
            ip TEXT PRIMARY KEY,
            until INTEGER NOT NULL,
            counts TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()

# Initialize DB
init_db()

# Session management helper functions

# Load sessions from database
def load_sessions():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT session_id, floor, level, expires, created, inv, last_level_update, last_floor_update, last_message_received_at, last_from_session_delivered, verified FROM sessions')
    rows = cur.fetchall()
    conn.close()
    sessions = {}
    for r in rows:
        sessions[r[0]] = {
            'floor': int(r[1]),
            'level': int(r[2]),
            'expires': r[3],
            'created': r[4],
            'inv': (json.loads(r[5]) if r[5] else {}),
            'last_level_update': r[6],
            'last_floor_update': r[7],
            'last_message_received_at': r[8],
            'last_from_session_delivered': r[9],
            'verified': bool(r[10])
        }
    return sessions

# Save sessions to database
def save_sessions(sessions):
    # Replace-all approach keeps the rest of the code unchanged
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM sessions')
    for sid, s in sessions.items():
        cur.execute(
            'INSERT OR REPLACE INTO sessions (session_id, floor, level, expires, created, inv, last_level_update, last_floor_update, last_message_received_at, last_from_session_delivered, verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                sid,
                int(s.get('floor', 1)),
                int(s.get('level', 1)),
                s.get('expires', ''),
                s.get('created', ''),
                json.dumps(s.get('inv', {})),
                s.get('last_level_update'),
                s.get('last_floor_update'),
                s.get('last_message_received_at'),
                s.get('last_from_session_delivered'),
                1 if s.get('verified') else 0,
            )
        )
    conn.commit()
    conn.close()

# Load pigeons from database
def load_pigeons():
    conn = get_db_connection()
    cur = conn.cursor()
    # Preserve append order by created timestamp
    cur.execute('SELECT id, text, from_session, from_floor, from_level, from_verified, created, delivered, delivered_at, delivered_to FROM pigeons ORDER BY datetime(created) ASC')
    rows = cur.fetchall()
    conn.close()
    pigeons = []
    for r in rows:
        pigeons.append({
            'id': r[0],
            'text': r[1],
            'from_session': r[2],
            'from_floor': int(r[3]),
            'from_level': int(r[4]),
            'from_verified': bool(r[5]),
            'created': r[6],
            'delivered': bool(r[7]),
            'delivered_at': r[8],
            'delivered_to': r[9],
        })
    return pigeons

# Save pigeons to database
def save_pigeons(pigeons):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM pigeons')
    for p in pigeons:
        cur.execute(
            'INSERT OR REPLACE INTO pigeons (id, text, from_session, from_floor, from_level, from_verified, created, delivered, delivered_at, delivered_to) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                p.get('id') or str(uuid.uuid4()),
                p.get('text', ''),
                p.get('from_session', ''),
                int(p.get('from_floor', 0)),
                int(p.get('from_level', 0)),
                1 if p.get('from_verified') else 0,
                p.get('created', datetime.utcnow().isoformat()),
                1 if p.get('delivered') else 0,
                p.get('delivered_at'),
                p.get('delivered_to'),
            )
        )
    conn.commit()
    conn.close()

# Get pending (undelivered) pigeons
def _pending_pigeons(pigeons):
    return [p for p in pigeons if not p.get("delivered")]

# Session timeout in minutes
SESSION_TIMEOUT_MINUTES = 120 # 2 hours timeout for sessions (resets on vocaguard update)

# Configuration for pigeon message sanitation

# Regex pattern for allowed characters in messages
ALLOWED_CHARS_PATTERN = re.compile(r"[^A-Za-z0-9 .,!?;:'\-_/()\[\]@#%&*+=$\\\"]+")

# Maximum length for pigeon messages
MAX_PIGEON_MESSAGE_LEN = 420
# Maximum pigeons per session
MAX_PIGEONS_PER_SESSION = 20  # hard cap beyond rate limit
# Rate limit for pigeon purchases
PIGEON_RATE_LIMIT = "20 per hour"  # purchase spam guard

# Delivery prioritization config
FLOOR_PROXIMITY_RANGE = 2               # preferred ±2 floors
PRIORITY_HIGH_FLOOR_WEIGHT = 0.05       # +5% weight per sender floor
PRIORITY_VERIFIED_MULTIPLIER = 1.5      # 50% boost for verified sender sessions
AGE_BOOST_FULL_SECONDS = 600            # full age boost after 10 minutes
AGE_BOOST_MAX = 0.5                     # up to +50% boost for older messages
RANDOM_JITTER_MIN = 0.85                # randomness factor range
RANDOM_JITTER_MAX = 1.15
REPEAT_SENDER_PENALTY = 0.5             # de-prioritize same sender consecutively

# Configuration for abuse monitoring

# Time window for abuse events in seconds
ABUSE_EVENT_WINDOW_SECONDS = 3600  # 1 hour rolling window
# Threshold for duplicate attempts
ABUSE_DUPLICATE_THRESHOLD = 2
# Threshold for sanitize rejections
ABUSE_SANITIZE_REJECT_THRESHOLD = 2
# Threshold for captcha failures
ABUSE_CAPTCHA_FAIL_THRESHOLD = 2
# Duration for abuse flag (ban) in seconds
ABUSE_FLAG_DURATION_SECONDS = 3600  # 1 hour flag
# Admin key for viewing abuse metrics
ABUSE_ADMIN_KEY = os.environ.get("TARDQUEST_ABUSE_KEY")  # optional secret for viewing metrics

# Load abuse state from database
def _load_abuse_state():
    conn = get_db_connection()
    cur = conn.cursor()
    # Events
    cur.execute('SELECT ts, ip, metric, sid, extra FROM abuse_events')
    events = []
    for ts, ip, metric, sid, extra in cur.fetchall():
        events.append({
            'ts': int(ts),
            'ip': ip,
            'metric': metric,
            'sid': sid,
            'extra': (json.loads(extra) if extra else {}),
        })
    # Flagged
    cur.execute('SELECT ip, until, counts FROM abuse_flagged')
    flagged = {}
    for ip, until, counts in cur.fetchall():
        flagged[ip] = {
            'until': int(until),
            'counts': (json.loads(counts) if counts else {}),
        }
    conn.close()
    return {'events': events, 'flagged': flagged}

# Save abuse state to database
def _save_abuse_state(state):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM abuse_events')
    for e in state.get('events', []):
        cur.execute(
            'INSERT INTO abuse_events (ts, ip, metric, sid, extra) VALUES (?, ?, ?, ?, ?)',
            (
                int(e.get('ts', 0)),
                str(e.get('ip', '')),
                str(e.get('metric', '')),
                str(e.get('sid', '')),
                json.dumps(e.get('extra', {})),
            )
        )
    cur.execute('DELETE FROM abuse_flagged')
    for ip, info in (state.get('flagged', {}) or {}).items():
        cur.execute(
            'INSERT OR REPLACE INTO abuse_flagged (ip, until, counts) VALUES (?, ?, ?)',
            (str(ip), int(info.get('until', 0)), json.dumps(info.get('counts', {})))
        )
    conn.commit()
    conn.close()

# Prune old events and expired flags
def _prune_events(state, now_ts):
    cutoff = now_ts - ABUSE_EVENT_WINDOW_SECONDS
    state['events'] = [e for e in state['events'] if e.get('ts', 0) >= cutoff]
    # Remove expired flags
    expired_ips = [ip for ip, info in state.get('flagged', {}).items() if info.get('until', 0) < now_ts]
    for ip in expired_ips:
        state['flagged'].pop(ip, None)

# Record an abuse event
def _record_abuse(metric: str, ip: str, session_id: str = None, extra: dict = None):
    try:
        state = _load_abuse_state()
        now_ts = int(datetime.utcnow().timestamp())
        _prune_events(state, now_ts)
        event = {
            'ts': now_ts,
            'ip': ip,
            'metric': metric
        }
        if session_id:
            event['sid'] = session_id
        if extra:
            # avoid storing sensitive raw data
            safe_extra = {k: (v if k != 'raw' else None) for k, v in extra.items()}
            event['extra'] = safe_extra
        state['events'].append(event)
        # Recompute counts for this IP inside window
        window_events = [e for e in state['events'] if e['ip'] == ip]
        counts = {}
        for e in window_events:
            counts[e['metric']] = counts.get(e['metric'], 0) + 1
        should_flag = (
            counts.get('duplicate', 0) >= ABUSE_DUPLICATE_THRESHOLD or
            counts.get('sanitize_reject', 0) >= ABUSE_SANITIZE_REJECT_THRESHOLD or
            counts.get('captcha_fail', 0) >= ABUSE_CAPTCHA_FAIL_THRESHOLD
        )
        if should_flag:
            state.setdefault('flagged', {})[ip] = {
                'until': now_ts + ABUSE_FLAG_DURATION_SECONDS,
                'counts': counts
            }
        _save_abuse_state(state)
    except Exception as e:
        # Fail open; do not break main flow
        print(f"ABUSE RECORD ERROR: {e}")

# Check if an IP is flagged for abuse
def _is_flagged(ip: str):
    try:
        state = _load_abuse_state()
        now_ts = int(datetime.utcnow().timestamp())
        info = state.get('flagged', {}).get(ip)
        if info and info.get('until', 0) > now_ts:
            return True, info
        return False, None
    except Exception:
        return False, None

# Sanitize pigeon message content
def sanitize_pigeon_message(raw: str) -> str:
    if not isinstance(raw, str):
        return ""
    # Normalize unicode (NFC)
    txt = unicodedata.normalize('NFC', raw)
    # Remove HTML tags
    txt = re.sub(r'<[^>]*>', '', txt)
    # Remove control characters
    txt = ''.join(ch for ch in txt if ch == '\n' or (ord(ch) >= 32 and ord(ch) != 127))
    # Collapse whitespace
    txt = re.sub(r'[ \t]+', ' ', txt)
    txt = re.sub(r'\n{3,}', '\n\n', txt)  # limit blank lines
    # Filter disallowed characters
    txt = ALLOWED_CHARS_PATTERN.sub('', txt)
    # Trim length
    if len(txt) > MAX_PIGEON_MESSAGE_LEN:
        txt = txt[:MAX_PIGEON_MESSAGE_LEN]
    txt = txt.strip()
    # Reduce repeated punctuation (e.g., !!!! -> !!)
    txt = re.sub(r'([!?*.])\1{2,}', r'\1\1', txt)
    # If resulting message is now too short or mostly punctuation, reject
    if len(txt) < 3 or re.fullmatch(r'[.!?* ]+', txt):
        return ""
    return txt

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"],
)

# API Endpoints

# Start a new anti-cheat session
@app.route('/api/vocaguard/start', methods=['POST'])
def vocaguard_start():
    # Starts a new anti-cheat session and returns session_id
    session_id = str(uuid.uuid4())
    sessions = load_sessions()
    expires = (datetime.utcnow() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)).isoformat()
    sessions[session_id] = _ensure_inventory({
        "floor": 1,
        "level": 1,
        "expires": expires,
        "created": datetime.utcnow().isoformat(),
        "inv": {"carrierPigeon": 0}
    })
    save_sessions(sessions)

    return jsonify({
        "session_id": session_id,
    }), 200

# Update session progress with anti-cheat checks
@app.route('/api/vocaguard/update', methods=['POST'])
@limiter.limit("10 per minute")  # 10 updates per minute per IP
def vocaguard_update():
    # Updates session progress
    data = request.get_json() or {}
    session_id = data.get('session_id')
    floor = data.get('floor')
    level = data.get('level')
    sessions = load_sessions()
    session = sessions.get(session_id)
    if not session:
        return jsonify({"error": "Invalid session token"}), 400
    # Check expiration
    if datetime.fromisoformat(session['expires']) < datetime.utcnow():
        sessions.pop(session_id, None)
        save_sessions(sessions)
        return jsonify({"error": "Session expired"}), 400
    current_floor = session['floor']
    current_level = session['level']
    # Floor cannot decrease
    if floor < current_floor:
        return jsonify({"error": "Floor regression detected", "detail": f"Current floor: {current_floor}, attempted: {floor}"}), 400
    # Level cannot decrease on same floor
    if floor == current_floor and level < current_level:
        return jsonify({"error": "Level regression detected on same floor", "detail": f"Current level: {current_level}, attempted: {level}"}), 400
    # Prevent skipping floors
    if floor > current_floor and floor - current_floor > 1:
        return jsonify({"error": "Abnormal floor jump detected", "detail": f"Current floor: {current_floor}, attempted: {floor}"}), 400
    # Prevent abnormal level jumps (must increment by 1 or stay the same)
    if level > current_level and level - current_level > 1 and floor == current_floor:
        return jsonify({"error": "Abnormal level jump detected", "detail": f"Current level: {current_level}, attempted: {level}"}), 400
    now = datetime.utcnow()
    last_level_update = session.get('last_level_update')
    last_floor_update = session.get('last_floor_update')

    # Enforce minimum 10 seconds between level increments
    if level > current_level:
        if last_level_update:
            last_level_update_dt = datetime.fromisoformat(last_level_update)
            if (now - last_level_update_dt).total_seconds() < 10:
                return jsonify({"error": "Level increment too fast!"}), 400
        session['last_level_update'] = now.isoformat()

    # Enforce minimum 10 seconds between floor increments
    if floor > current_floor:
        if last_floor_update:
            last_floor_update_dt = datetime.fromisoformat(last_floor_update)
            if (now - last_floor_update_dt).total_seconds() < 10:
                return jsonify({"error": "Floor increment too fast!"}), 400
        session['last_floor_update'] = now.isoformat()

    # Update session progress only if valid
    session['floor'] = floor
    session['level'] = level
    session['expires'] = (datetime.utcnow() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)).isoformat()
    sessions[session_id] = session
    save_sessions(sessions)

    return jsonify({"status": "updated"}), 200

# Validate final submission before leaderboard post
@app.route('/api/vocaguard/validate', methods=['POST'])
def vocaguard_validate():
    # Validates final submission before leaderboard post
    data = request.get_json() or {}
    session_id = data.get('session_id')
    floor = data.get('floor')
    level = data.get('level')
    sessions = load_sessions()
    session = sessions.get(session_id)
    if not session:
        return jsonify({"result": "fail", "reason": "Invalid session"}), 400
    if datetime.fromisoformat(session['expires']) < datetime.utcnow():
        sessions.pop(session_id, None)
        save_sessions(sessions)
        return jsonify({"result": "fail", "reason": "Session expired"}), 400
    if session['floor'] == floor and session['level'] == level:
        # Do NOT pop or save sessions here!
        return jsonify({"result": "pass"}), 200
    else:
        return jsonify({"result": "fail", "reason": "Mismatch with tracked progress"}), 400

# Get API status
@app.route('/api/leaderboard/status', methods=['GET'])
def leaderboard_status():
    # Returns API status
    return jsonify({"status": "ok"}), 200

# Handle leaderboard GET and POST requests
@app.route('/api/leaderboard', methods=['GET', 'POST'])
def leaderboard():
    # GET: Return the current leaderboard
    if request.method == 'GET':
        try:
            # Load from SQLite and sanitize like before
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('SELECT name, floor, level FROM leaderboard ORDER BY floor DESC, level DESC')
            leaderboard_data = [
                {'name': r[0], 'floor': int(r[1]), 'level': int(r[2])}
                for r in cur.fetchall()
            ]
            conn.close()
            leaderboard_data = clean_json(leaderboard_data)
            for entry in leaderboard_data:
                if isinstance(entry, dict) and 'name' in entry and isinstance(entry['name'], str):
                    entry['name'] = entry['name'].upper()
            return jsonify(leaderboard_data)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    # POST: Update the leaderboard
    elif request.method == 'POST':
        try:
            new_entry = request.get_json() or {}
            print("DEBUG: Received entry:", new_entry)
            if not new_entry or not isinstance(new_entry, dict):
                log_rejection("Invalid data format", new_entry)
                return jsonify({"error": "Invalid data format"}), 400
            # Core required fields (captcha token handled separately for backward compatibility)
            required_fields = ['name', 'floor', 'level', 'session_id']
            if not all(field in new_entry for field in required_fields):
                log_rejection("Missing required core fields", new_entry)
                return jsonify({"error": f"Missing required fields: {required_fields}"}), 400
            # Accept multiple possible captcha token keys: legacy 'hcaptcha_token', generic 'captcha_token'
            captcha_token = (new_entry.get('captcha_token') or new_entry.get('hcaptcha_token'))
            if not captcha_token:
                log_rejection("Captcha token missing", new_entry)
                return jsonify({"error": "Captcha token missing"}), 400
            if not verify_any_captcha(captcha_token, remote_ip=request.remote_addr):
                log_rejection("Captcha verification failed", new_entry)
                return jsonify({"error": "Captcha verification failed"}), 400
            raw_name = new_entry['name']
            filtered_name = re.sub(r'<.*?>', '', raw_name).strip()
            def clean_html(val):
                if isinstance(val, str):
                    val = re.sub(r'<.*?>', '', val)
                    val = re.sub(r'(script|meta|iframe|onerror|onload|javascript:|http-equiv|src|href|alert|document|window)', '', val, flags=re.IGNORECASE)
                    val = val.strip()
                    val = val[:5]
                    val = re.sub(r'[^A-Za-z0-9 ]', '', val)
                    return val
                return val
            new_entry['name'] = clean_html(new_entry['name'])
            filtered_name = new_entry['name']
            if not filtered_name:
                log_rejection("Name is required and must be valid", new_entry)
                return jsonify({"error": "Name is required and must be valid"}), 400
            if re.search(r'[^A-Za-z0-9 ]', filtered_name):
                log_rejection("Name contains invalid characters", new_entry)
                return jsonify({"error": "Name contains invalid characters"}), 400
            if len(filtered_name) > 5:
                log_rejection("Name must be at most 5 characters", new_entry)
                return jsonify({"error": "Name must be at most 5 characters"}), 400
            new_entry['name'] = filtered_name
            try:
                floor_val = int(new_entry['floor'])
                level_val = int(new_entry['level'])
            except (ValueError, TypeError):
                log_rejection("Floor and level must be valid numbers", new_entry)
                return jsonify({"error": "Floor and level must be valid numbers"}), 400
            new_entry['floor'] = floor_val
            new_entry['level'] = level_val
            sessions = load_sessions()
            session = sessions.get(new_entry['session_id'])
            if not session:
                log_rejection("VocaGuard session missing or invalid", new_entry)
                return jsonify({"error": "VocaGuard session missing or invalid"}), 400
            if datetime.fromisoformat(session['expires']) < datetime.utcnow():
                log_rejection("VocaGuard session expired", new_entry)
                sessions.pop(new_entry['session_id'], None)
                save_sessions(sessions)
                return jsonify({"error": "VocaGuard session expired"}), 400
            if session['floor'] != new_entry['floor'] or session['level'] != new_entry['level']:
                log_rejection("VocaGuard progress mismatch", new_entry)
                return jsonify({"error": "VocaGuard progress mismatch"}), 400
            sessions.pop(new_entry['session_id'], None)
            save_sessions(sessions)
            # Insert into SQLite and return sorted list
            entry_to_store = {k: v for k, v in new_entry.items() if k not in ('session_id', 'hcaptcha_token', 'captcha_token')}
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                'INSERT INTO leaderboard (name, floor, level) VALUES (?, ?, ?)',
                (entry_to_store['name'], int(entry_to_store['floor']), int(entry_to_store['level']))
            )
            conn.commit()
            cur.execute('SELECT name, floor, level FROM leaderboard ORDER BY floor DESC, level DESC')
            leaderboard_data = [
                {'name': r[0], 'floor': int(r[1]), 'level': int(r[2])}
                for r in cur.fetchall()
            ]
            conn.close()
            return jsonify({"message": "Leaderboard updated successfully", "data": leaderboard_data})
        except Exception as e:
            print("DEBUG: Exception occurred:", e)
            return jsonify({"error": str(e)}), 500

# Get carrier pigeon inventory for session
@app.route('/api/pigeon/inventory', methods=['GET'])
def pigeon_inventory():
    session_id = request.args.get('session_id')
    if not session_id:
        return jsonify({"error": "session_id required"}), 400
    # Abuse flag check
    flagged, info = _is_flagged(request.remote_addr)
    if flagged:
        return jsonify({"error": "Temporarily blocked due to abuse", "until": info.get('until')}), 429
    sessions = load_sessions()
    session = sessions.get(session_id)
    if not session:
        return jsonify({"error": "Invalid session"}), 400
    if datetime.fromisoformat(session["expires"]) < datetime.utcnow():
        return jsonify({"error": "Session expired"}), 400
    session = _ensure_inventory(session)
    return jsonify({"carrierPigeon": session['inv']['carrierPigeon']}), 200

# Purchase a carrier pigeon
@app.route('/api/pigeon/purchase', methods=['POST'])
@limiter.limit(PIGEON_RATE_LIMIT)
def pigeon_purchase():
    # Increments carrier pigeon inventory for this session.
    data = request.get_json() or {}
    session_id = data.get("session_id")
    if not session_id:
        return jsonify({"error": "session_id required"}), 400
    flagged, info = _is_flagged(request.remote_addr)
    if flagged:
        _record_abuse('blocked_request', request.remote_addr, session_id)
        return jsonify({"error": "Temporarily blocked due to abuse", "until": info.get('until')}), 429
    sessions = load_sessions()
    session = sessions.get(session_id)
    if not session:
        return jsonify({"error": "Invalid session"}), 400
    if datetime.fromisoformat(session["expires"]) < datetime.utcnow():
        return jsonify({"error": "Session expired"}), 400
    session = _ensure_inventory(session)
    cur = session['inv']['carrierPigeon']
    if cur >= MAX_PIGEONS_PER_SESSION:
        return jsonify({"error": "You've had enough pigeons for today!", "carrierPigeon": cur}), 400
    session['inv']['carrierPigeon'] = cur + 1
    # refresh expiry
    session['expires'] = (datetime.utcnow() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)).isoformat()
    sessions[session_id] = session
    save_sessions(sessions)
    return jsonify({
        "purchased": True,
        "carrierPigeon": session['inv']['carrierPigeon'],
        "remaining_capacity": MAX_PIGEONS_PER_SESSION - session['inv']['carrierPigeon']
    }), 200

# Send a pigeon message
@app.route('/api/pigeon/send', methods=['POST'])
@limiter.limit("5 per minute")
def pigeon_send():
    data = request.get_json() or {}
    session_id = data.get("session_id")
    raw_text = (data.get("message") or "").strip()

    if not session_id or not raw_text:
        return jsonify({"error": "session_id and message required"}), 400

    flagged, info = _is_flagged(request.remote_addr)
    if flagged:
        _record_abuse('blocked_request', request.remote_addr, session_id)
        return jsonify({"error": "Temporarily blocked due to abuse", "until": info.get('until')}), 429

    sessions = load_sessions()
    session = sessions.get(session_id)
    if not session:
        return jsonify({"error": "Invalid session"}), 400
    if datetime.fromisoformat(session["expires"]) < datetime.utcnow():
        return jsonify({"error": "Session expired"}), 400

    session = _ensure_inventory(session)
    if session['inv']['carrierPigeon'] <= 0:
        _record_abuse('no_inventory', request.remote_addr, session_id)
        return jsonify({"error": "No carrier pigeon in inventory"}), 400

    text = sanitize_pigeon_message(raw_text)
    if not text:
        _record_abuse('sanitize_reject', request.remote_addr, session_id)
        return jsonify({"error": "Message rejected (empty/invalid after sanitation)"}), 400

    pigeons = load_pigeons()
    # Treat missing delivered flag as undelivered
    session_messages = [p for p in pigeons if p.get('from_session') == session_id]
    if len(session_messages) >= MAX_PIGEONS_PER_SESSION:
        _record_abuse('message_cap', request.remote_addr, session_id)
        return jsonify({"error": "Session pigeon message limit reached"}), 429

    last_same_session = next((p for p in reversed(pigeons) if p.get('from_session') == session_id), None)
    if last_same_session and last_same_session.get('text') == text:
        _record_abuse('duplicate', request.remote_addr, session_id)
        return jsonify({"error": "Duplicate message"}), 400

    session['inv']['carrierPigeon'] -= 1
    sessions[session_id] = session
    save_sessions(sessions)

    pigeons.append({
        "id": str(uuid.uuid4()),
        "text": text,
        "from_session": session_id,
        "from_floor": int(session.get("floor", 0)),  # capture sender floor
        "from_level": int(session.get("level", 0)),  # capture sender level
        "from_verified": bool(session.get("verified", False)),  # capture sender verification
        "created": datetime.utcnow().isoformat(),
        "delivered": False,
        "delivered_at": None,
        "delivered_to": None
    })
    save_pigeons(pigeons)

    pending = len(_pending_pigeons(pigeons))

    _record_abuse('message_sent', request.remote_addr, session_id)

    return jsonify({
        "stored": True,
        "queue_length_pending": pending,
        "queue_length_total": len(pigeons),
        "sanitized_text": text,
        "carrierPigeon_remaining": session['inv']['carrierPigeon']
    }), 200

# Deliver a pigeon message to session
@app.route('/api/pigeon/delivery', methods=['POST'])
@limiter.limit("5 per minute")
def pigeon_delivery():
    data = request.get_json() or {}
    session_id = data.get('session_id')
    if not session_id:
        return jsonify({"error": "session_id required"}), 400
    sessions = load_sessions()
    session = sessions.get(session_id)
    if not session:
        return jsonify({"error": "Invalid session"}), 400
    if datetime.fromisoformat(session["expires"]) < datetime.utcnow():
        return jsonify({"error": "Session expired"}), 400

    pigeons = load_pigeons()
    # select a message using weighted, progress-based matching
    session["session_id"] = session_id  # help selector avoid self
    sel_idx, delivered_msg = _select_pigeon_for_delivery(pigeons, session, sessions)
    if delivered_msg is not None and sel_idx is not None:
        pigeons[sel_idx]['delivered'] = True
        pigeons[sel_idx]['delivered_at'] = datetime.utcnow().isoformat()
        pigeons[sel_idx]['delivered_to'] = session_id
        save_pigeons(pigeons)
        # store recipient's last sender to reduce repetition
        session['last_message_received_at'] = datetime.utcnow().isoformat()
        session['last_from_session_delivered'] = delivered_msg.get('from_session')
        sessions[session_id] = session
        save_sessions(sessions)

    remaining_pending = len(_pending_pigeons(pigeons))
    return jsonify({
        "delivered": bool(delivered_msg),
        "pigeon_message": delivered_msg["text"] if delivered_msg else None,
        "pigeon_id": delivered_msg["id"] if delivered_msg else None,
        "remaining_queue_pending": remaining_pending,
        "remaining_queue_total": len(pigeons)
    }), 200

# Get abuse status (admin only)
@app.route('/api/abuse/status', methods=['GET'])
def abuse_status():
    # Optional admin endpoint
    if not ABUSE_ADMIN_KEY:
        return jsonify({"error": "Disabled"}), 404
    key = request.args.get('key')
    if key != ABUSE_ADMIN_KEY:
        return jsonify({"error": "Forbidden"}), 403
    try:
        state = _load_abuse_state()
        now_ts = int(datetime.utcnow().timestamp())
        _prune_events(state, now_ts)
        # Aggregate counts per IP (exclude raw extras)
        agg = {}
        for e in state['events']:
            ip = e['ip']
            metric = e['metric']
            agg.setdefault(ip, {})[metric] = agg.setdefault(ip, {}).get(metric, 0) + 1
        return jsonify({
            'flagged': state.get('flagged', {}),
            'counts': agg,
            'window_seconds': ABUSE_EVENT_WINDOW_SECONDS
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Utility Functions

# Get hCaptcha secret from environment
HCAPTCHA_SECRET = os.environ.get("HCAPTCHA_SECRET", "")
# Get Turnstile secret from environment
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "")

# Verify hCaptcha token
def verify_hcaptcha(token: str) -> bool:
    if not token:
        return False
    url = "https://hcaptcha.com/siteverify"
    data = {"secret": HCAPTCHA_SECRET, "response": token}
    try:
        resp = requests.post(url, data=data, timeout=5)
        result = resp.json()
        return bool(result.get("success"))
    except Exception as e:
        print(f"hCaptcha verification error: {e}")
        return False

# Verify Cloudflare Turnstile token
def verify_turnstile(token: str, remote_ip: str = None) -> bool:
    if not token or not TURNSTILE_SECRET:
        return False
    url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    data = {"secret": TURNSTILE_SECRET, "response": token}
    if remote_ip:
        data["remoteip"] = remote_ip
    try:
        resp = requests.post(url, data=data, timeout=5)
        result = resp.json()
        return bool(result.get("success"))
    except Exception as e:
        print(f"Turnstile verification error: {e}")
        return False

# Verify captcha using either hCaptcha or Turnstile
def verify_any_captcha(token: str, remote_ip: str = None) -> bool:
    # Try hCaptcha (legacy) first; if fails, attempt Turnstile if configured
    if verify_hcaptcha(token):
        return True
    return verify_turnstile(token, remote_ip=remote_ip)

# Clean HTML and scripts from string, enforce 5 char limit
def clean_html(val):
    # Cleans HTML/script from string and enforces 5 char limit
    if isinstance(val, str):
        val = re.sub(r'<.*?>', '', val)
        val = re.sub(r'(script|meta|iframe|onerror|onload|javascript:|http-equiv|src|href|alert|document|window)', '', val, flags=re.IGNORECASE)
        val = val.strip()
        val = val[:5]
        val = re.sub(r'[^A-Za-z0-9 ]', '', val)
        return val
    return val

# Recursively clean JSON data
def clean_json(obj):
    # Recursively clean leaderboard JSON
    if isinstance(obj, dict):
        return {k: clean_html(v) if k == 'name' else clean_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [clean_json(item) for item in obj]
    else:
        return obj

# Log rejection reason to database
def log_rejection(reason, data):
    # Append rejection event into abuse tracking database
    try:
        state = _load_abuse_state()
        now_ts = int(datetime.utcnow().timestamp())
        _prune_events(state, now_ts)
        event = {
            'ts': now_ts,
            'ip': request.remote_addr,
            'metric': 'rejection',
            'reason': reason,
            'ua': request.headers.get('User-Agent'),
            'data_excerpt': {
                'name': (data.get('name') if isinstance(data, dict) else None),
                'floor': (data.get('floor') if isinstance(data, dict) else None),
                'level': (data.get('level') if isinstance(data, dict) else None)
            }
        }
        state['events'].append(event)
        # Count captcha failures separately for flagging
        if reason.lower().startswith('captcha'):
            # Recompute counts for this IP to decide flagging
            ip = request.remote_addr
            window_events = [e for e in state['events'] if e.get('ip') == ip]
            captcha_fails = sum(1 for e in window_events if (e.get('metric') == 'rejection' and str(e.get('reason','')).lower().startswith('captcha')))
            if captcha_fails >= ABUSE_CAPTCHA_FAIL_THRESHOLD:
                state.setdefault('flagged', {})[ip] = {
                    'until': now_ts + ABUSE_FLAG_DURATION_SECONDS,
                    'counts': {'captcha_fail': captcha_fails}
                }
        _save_abuse_state(state)
    except Exception as e:
        print(f"LOG REJECTION ERROR: {e}")

# Ensure session has inventory structure
def _ensure_inventory(session: dict):
    if 'inv' not in session or not isinstance(session['inv'], dict):
        session['inv'] = {}
    if 'carrierPigeon' not in session['inv']:
        session['inv']['carrierPigeon'] = 0
    return session

# Resolve sender progress/verification for a message, using captured fields if present
def _sender_progress_for_msg(msg: dict, sessions: dict):
    from_floor = msg.get("from_floor")
    from_level = msg.get("from_level")
    from_verified = msg.get("from_verified", False)
    if from_floor is None or from_level is None or msg.get("from_verified") is None:
        sid = msg.get("from_session")
        s = sessions.get(sid) if sid else None
        if from_floor is None:
            from_floor = (s.get("floor") if isinstance(s, dict) else 0) or 0
        if from_level is None:
            from_level = (s.get("level") if isinstance(s, dict) else 0) or 0
        if msg.get("from_verified") is None:
            from_verified = bool((s or {}).get("verified", False))
    return int(from_floor or 0), int(from_level or 0), bool(from_verified)

# Compute a 0..1 closeness factor within the preferred floor range
def _closeness_weight(sender_floor: int, recipient_floor: int) -> float:
    delta = abs(sender_floor - recipient_floor)
    if delta > FLOOR_PROXIMITY_RANGE:
        return 0.0
    return max(0.0, 1.0 - (delta / (FLOOR_PROXIMITY_RANGE + 1)))

# Age-based booster: up to +AGE_BOOST_MAX after AGE_BOOST_FULL_SECONDS
def _age_boost(created_iso: str) -> float:
    try:
        created_dt = datetime.fromisoformat(created_iso)
    except Exception:
        return 0.0
    age = (datetime.utcnow() - created_dt).total_seconds()
    if age <= 0:
        return 0.0
    return min(AGE_BOOST_MAX, AGE_BOOST_MAX * (age / AGE_BOOST_FULL_SECONDS))

# Compute composite weight for weighted-random selection
def _message_weight(msg: dict, recipient_session: dict, sessions: dict) -> float:
    sender_floor, sender_level, sender_verified = _sender_progress_for_msg(msg, sessions)
    recipient_floor = int(recipient_session.get("floor", 0))
    weight = 1.0
    close = _closeness_weight(sender_floor, recipient_floor)
    if close > 0:
        weight *= (1.0 + 0.5 * close)  # up to +50% for same floor
    weight *= (1.0 + PRIORITY_HIGH_FLOOR_WEIGHT * max(0, sender_floor))  # higher floors bias
    if sender_verified:
        weight *= PRIORITY_VERIFIED_MULTIPLIER  # verified sender boost
    weight *= (1.0 + _age_boost(msg.get("created", "")))  # older messages bias
    last_from = recipient_session.get("last_from_session_delivered")
    if last_from and last_from == msg.get("from_session"):
        weight *= REPEAT_SENDER_PENALTY  # avoid same sender twice in a row
    weight *= random.uniform(RANDOM_JITTER_MIN, RANDOM_JITTER_MAX)  # jitter
    return max(weight, 0.0)

# Select an undelivered pigeon (not from recipient) using weighted random with proximity preference
def _select_pigeon_for_delivery(pigeons: list, recipient_session: dict, sessions: dict):
    session_id = recipient_session.get("id") or recipient_session.get("session_id")
    all_candidates = []
    close_candidates = []
    rec_floor = int(recipient_session.get("floor", 0))
    for idx, p in enumerate(pigeons):
        if p.get("delivered"):
            continue
        if p.get("from_session") == session_id:
            continue
        all_candidates.append((idx, p))
        s_floor, _, _ = _sender_progress_for_msg(p, sessions)
        if abs(s_floor - rec_floor) <= FLOOR_PROXIMITY_RANGE:
            close_candidates.append((idx, p))
    pool = close_candidates if close_candidates else all_candidates
    if not pool:
        return None, None
    weights = [
        _message_weight(p, recipient_session, sessions)
        for _, p in pool
    ]
    if sum(weights) <= 0:
        return pool[0][0], pool[0][1]
    pick = random.choices(population=pool, weights=weights, k=1)[0]
    return pick[0], pick[1]

# Purge old sessions
def purge_old_sessions():
    # Delete sessions older than 30 days
    cutoff = (datetime.utcnow() - timedelta(days=30)).isoformat()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM sessions WHERE created < ?", (cutoff,))
    conn.commit()
    conn.close()

def session_purge_worker():
    # Background thread to purge old sessions every 24 hours
    while True:
        try:
            purge_old_sessions()
        except Exception as e:
            print(f"Session purge error: {e}")
        time.sleep(24 * 60 * 60)  # Sleep for 24 hours

# Start the purge thread when the app starts
purge_thread = threading.Thread(target=session_purge_worker, daemon=True)
purge_thread.start()

# Main entry point to run the Flask app
if __name__ == '__main__':
    # Check if SSL certificates are available
    cert_path = os.path.join(os.path.dirname(__file__), 'ssl', 'certificate.pem')
    key_path = os.path.join(os.path.dirname(__file__), 'ssl', 'priv-key.pem')
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        ssl_context = (cert_path, key_path)
        print("SSL certificates found. Running with HTTPS.")
    else:
        ssl_context = None
        print("WARNING: SSL certificates not found. Falling back to HTTP. This is insecure and should only be used for development.")
    
    # Use SSL context for HTTPS if available, otherwise HTTP
    app.run(
        debug=False,
        host='0.0.0.0',
        port=9601,
        ssl_context=ssl_context
    )