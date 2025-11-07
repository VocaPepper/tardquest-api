# Import necessary modules
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from typing import Dict, List, Tuple, Optional
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
import traceback
from threading import Lock

# Load environment variables from .env file
load_dotenv()

# Initialize Flask application
app = Flask(__name__)
# Enable CORS for specified origins to allow cross-origin requests
CORS(app, origins=["http://localhost:5500", "http://localhost:9599", "https://vocapepper.com", "https://milklounge.wang", "https://uploads.ungrounded.net"])
# 5500: Used for local development, change as needed
# 9599: Used for Electron app in production

# --- Thread Safety ---
# Locks for concurrent access to JSON log files
vocaguard_log_lock = Lock()
general_log_lock = Lock()
flagged_ips_lock = Lock()
whitelist_lock = Lock()
# Per-session lock to prevent race conditions on concurrent updates
session_ops_lock = Lock()

# --- Application Configuration Constants ---
# Database connection timeout in seconds
DB_CONNECTION_TIMEOUT_SECONDS = 30
# API rate limiting: default maximum requests
API_DEFAULT_RATE_LIMIT = "100 per hour"
# External API timeout in seconds (for Turnstile, etc)
EXTERNAL_API_TIMEOUT_SECONDS = 5
# Session age before auto-purge in days
SESSION_PURGE_AGE_DAYS = 30
# Background worker sleep interval in seconds
BACKGROUND_WORKER_SLEEP_SECONDS = 24 * 60 * 60  # 24 hours
# Maximum leaderboard name length
MAX_LEADERBOARD_NAME_LENGTH = 5

# --- SQLite setup ---
# Single DB file for all data
DB_FILE = os.path.join(os.path.dirname(__file__), "tardquest.db")

def get_db_connection():
    # Open an sqlite3 connection with recommended pragmas for better concurrency
    # Use this helper throughout the code instead of sqlite3.connect(DB_FILE)
    conn = sqlite3.connect(DB_FILE, timeout=DB_CONNECTION_TIMEOUT_SECONDS, detect_types=sqlite3.PARSE_DECLTYPES)
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
    conn.commit()
    conn.close()

# Initialize DB
init_db()

# Session management helper functions

# Save a single session to database (atomic operation, thread-safe)
def save_session(session_id: str, session: Dict[str, any]) -> None:
    """
    Save a single session to database using atomic INSERT OR REPLACE.
    
    Args:
        session_id: The session identifier
        session: Dictionary containing session data
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            'INSERT OR REPLACE INTO sessions (session_id, floor, level, expires, created, inv, last_level_update, last_floor_update, last_message_received_at, last_from_session_delivered, verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                session_id,
                int(session.get('floor', 1)),
                int(session.get('level', 1)),
                session.get('expires', ''),
                session.get('created', ''),
                json.dumps(session.get('inv', {})),
                session.get('last_level_update'),
                session.get('last_floor_update'),
                session.get('last_message_received_at'),
                session.get('last_from_session_delivered'),
                1 if session.get('verified') else 0,
            )
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log_error('save_session', e, {'session_id': session_id})

# Load pigeons from database

# Save a single pigeon to database (atomic operation, thread-safe)
def save_pigeon(pigeon: Dict[str, any]) -> None:
    """
    Save a single pigeon message to database using atomic INSERT OR REPLACE.
    
    Args:
        pigeon: Dictionary containing pigeon message data
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            'INSERT OR REPLACE INTO pigeons (id, text, from_session, from_floor, from_level, from_verified, created, delivered, delivered_at, delivered_to) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                pigeon.get('id') or str(uuid.uuid4()),
                pigeon.get('text', ''),
                pigeon.get('from_session', ''),
                int(pigeon.get('from_floor', 0)),
                int(pigeon.get('from_level', 0)),
                1 if pigeon.get('from_verified') else 0,
                pigeon.get('created', datetime.utcnow().isoformat()),
                1 if pigeon.get('delivered') else 0,
                pigeon.get('delivered_at'),
                pigeon.get('delivered_to'),
            )
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log_error('save_pigeon', e, {'pigeon_id': pigeon.get('id')})

# --- Optimized Per-Session Database Functions (No Full-Table Fetch) ---

def get_session_by_id(session_id: str) -> Optional[Dict]:
    """
    Fetch a single session from database without loading entire table.
    
    Args:
        session_id: The session identifier
        
    Returns:
        Session dictionary or None if not found
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT session_id, floor, level, expires, created, inv, last_level_update, last_floor_update, last_message_received_at, last_from_session_delivered, verified FROM sessions WHERE session_id = ?', (session_id,))
        row = cur.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return {
            'session_id': row[0],
            'floor': int(row[1]),
            'level': int(row[2]),
            'expires': row[3],
            'created': row[4],
            'inv': json.loads(row[5]) if row[5] else {},
            'last_level_update': row[6],
            'last_floor_update': row[7],
            'last_message_received_at': row[8],
            'last_from_session_delivered': row[9],
            'verified': bool(row[10])
        }
    except Exception as e:
        log_error('get_session_by_id', e, {'session_id': session_id})
        return None

def update_session(session_id: str, updates: Dict) -> bool:
    """
    Update a single session in database using atomic UPDATE.
    No full-table fetch needed.
    
    Args:
        session_id: The session identifier
        updates: Dictionary of fields to update (only these are modified)
        
    Returns:
        True if successful, False on error
    """
    try:
        with session_ops_lock:  # Prevent concurrent updates to same session
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Build dynamic UPDATE statement based on provided fields
            set_clauses = []
            params = []
            
            if 'floor' in updates:
                set_clauses.append('floor = ?')
                params.append(int(updates['floor']))
            if 'level' in updates:
                set_clauses.append('level = ?')
                params.append(int(updates['level']))
            if 'expires' in updates:
                set_clauses.append('expires = ?')
                params.append(updates['expires'])
            if 'inv' in updates:
                set_clauses.append('inv = ?')
                params.append(json.dumps(updates['inv']))
            if 'last_level_update' in updates:
                set_clauses.append('last_level_update = ?')
                params.append(updates['last_level_update'])
            if 'last_floor_update' in updates:
                set_clauses.append('last_floor_update = ?')
                params.append(updates['last_floor_update'])
            if 'last_message_received_at' in updates:
                set_clauses.append('last_message_received_at = ?')
                params.append(updates['last_message_received_at'])
            if 'last_from_session_delivered' in updates:
                set_clauses.append('last_from_session_delivered = ?')
                params.append(updates['last_from_session_delivered'])
            if 'verified' in updates:
                set_clauses.append('verified = ?')
                params.append(1 if updates['verified'] else 0)
            
            if not set_clauses:
                conn.close()
                return True  # Nothing to update
            
            # Add session_id as final parameter
            params.append(session_id)
            
            sql = f'UPDATE sessions SET {", ".join(set_clauses)} WHERE session_id = ?'
            cur.execute(sql, tuple(params))
            
            if cur.rowcount == 0:
                # Session doesn't exist, try INSERT instead
                conn.commit()
                conn.close()
                return False
            
            conn.commit()
            conn.close()
            return True
    except Exception as e:
        log_error('update_session', e, {'session_id': session_id, 'updates': list(updates.keys())})
        return False

def delete_session(session_id: str) -> bool:
    """
    Delete a single session from database.
    
    Args:
        session_id: The session identifier
        
    Returns:
        True if successful
    """
    try:
        with session_ops_lock:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
            conn.commit()
            conn.close()
            return True
    except Exception as e:
        log_error('delete_session', e, {'session_id': session_id})
        return False

# --- Optimized Per-Pigeon Database Functions (No Full-Table Fetch) ---

def get_pending_pigeon_for_delivery(recipient_floor: int, recipient_session_id: str, exclude_recent_sender: Optional[str] = None) -> Optional[Dict]:
    """
    Fetch a single undelivered pigeon optimized for delivery.
    Uses weighted random selection with proximity preference.
    Does NOT load entire table.
    
    Args:
        recipient_floor: Recipient's current floor
        recipient_session_id: Recipient's session ID
        exclude_recent_sender: Session ID to deprioritize (last sender)
        
    Returns:
        Single pigeon dictionary or None
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get undelivered pigeons not from this recipient
        cur.execute('''
            SELECT id, text, from_session, from_floor, from_level, from_verified, created, delivered, delivered_at, delivered_to
            FROM pigeons 
            WHERE delivered = 0 AND from_session != ?
            LIMIT 100
        ''', (recipient_session_id,))
        
        rows = cur.fetchall()
        conn.close()
        
        if not rows:
            return None
        
        # Convert to dicts
        candidates = []
        for r in rows:
            candidates.append({
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
        
        # Apply weighting logic (proximity, age, etc.)
        weights = [_message_weight(p, {'floor': recipient_floor}, {}) for p in candidates]
        
        if sum(weights) <= 0:
            return candidates[0] if candidates else None
        
        selected = random.choices(candidates, weights=weights, k=1)[0]
        return selected
    except Exception as e:
        log_error('get_pending_pigeon_for_delivery', e)
        return None

def mark_pigeon_delivered(pigeon_id: str, delivered_to_session: str) -> bool:
    """
    Mark a pigeon as delivered without rewriting entire dataset.
    Uses atomic UPDATE.
    
    Args:
        pigeon_id: The pigeon ID
        delivered_to_session: Session ID that received it
        
    Returns:
        True if successful
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            'UPDATE pigeons SET delivered = 1, delivered_at = ?, delivered_to = ? WHERE id = ?',
            (datetime.utcnow().isoformat(), delivered_to_session, pigeon_id)
        )
        conn.commit()
        conn.close()
        return cur.rowcount > 0
    except Exception as e:
        log_error('mark_pigeon_delivered', e, {'pigeon_id': pigeon_id})
        return False

def get_pending_pigeon_count(session_id: str) -> int:
    """
    Get count of undelivered pigeons from a specific session.
    Does NOT load full table.
    
    Args:
        session_id: The session identifier
        
    Returns:
        Count of pending pigeons
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM pigeons WHERE from_session = ? AND delivered = 0', (session_id,))
        count = cur.fetchone()[0]
        conn.close()
        return count
    except Exception as e:
        log_error('get_pending_pigeon_count', e, {'session_id': session_id})
        return 0

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

# --- Helper Functions for API Responses ---

# Log to vocaguard.json for VocaGuard-related errors and rejections
def log_to_vocaguard_json(event: Dict) -> None:
    """
    Log an abuse/VocaGuard event to vocaguard.json with thread-safe file locking.
    
    Args:
        event: Dictionary containing event data (ts, ip, metric, etc.)
    """
    vocaguard_log_file = os.path.join(os.path.dirname(__file__), "vocaguard.json")
    try:
        with vocaguard_log_lock:
            # Load existing logs or start fresh
            logs = []
            if os.path.exists(vocaguard_log_file):
                with open(vocaguard_log_file, 'r') as f:
                    logs = json.load(f)
            # Append new event
            logs.append(event)
            # Write back
            with open(vocaguard_log_file, 'w') as f:
                json.dump(logs, f, indent=2)
    except Exception as e:
        print(f"VOCAGUARD LOG ERROR: {e}")

# Log to log.json for general server errors
def log_to_general_json(event: Dict) -> None:
    """
    Log a general server error to log.json with thread-safe file locking.
    
    Args:
        event: Dictionary containing error event data (error, traceback, etc.)
    """
    log_file = os.path.join(os.path.dirname(__file__), "log.json")
    try:
        with general_log_lock:
            # Load existing logs or start fresh
            logs = []
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    logs = json.load(f)
            # Append new event
            logs.append(event)
            # Write back
            with open(log_file, 'w') as f:
                json.dump(logs, f, indent=2)
    except Exception as e:
        print(f"GENERAL LOG ERROR: {e}")

# Log an error to log.json with context
def log_error(function_name: str, error: Exception, context: Optional[Dict] = None) -> None:
    """
    Log an error with full stack trace and context to log.json.
    
    Args:
        function_name: Name of the function where error occurred
        error: The exception object
        context: Optional dictionary with contextual data (counts, session info, etc.)
    """
    try:
        error_event = {
            'ts': int(datetime.utcnow().timestamp()),
            'function': function_name,
            'error': str(error),
            'error_type': type(error).__name__,
            'traceback': traceback.format_exc()
        }
        if context:
            error_event['context'] = context
        log_to_general_json(error_event)
    except Exception as e:
        print(f"LOG ERROR FAILED: {e}")

def _load_vocaguard_events() -> List[Dict]:
    """
    Load recent vocaguard events within the time window from vocaguard.json.
    
    Returns:
        List of event dictionaries from the past ABUSE_EVENT_WINDOW_SECONDS
    """
    vocaguard_log_file = os.path.join(os.path.dirname(__file__), "vocaguard.json")
    events = []
    if os.path.exists(vocaguard_log_file):
        try:
            with open(vocaguard_log_file, 'r') as f:
                all_events = json.load(f)
            now_ts = int(datetime.utcnow().timestamp())
            cutoff = now_ts - ABUSE_EVENT_WINDOW_SECONDS
            # Filter events within the time window
            events = [e for e in all_events if e.get('ts', 0) >= cutoff]
        except Exception as e:
            log_error('load_vocaguard_events', e)
    return events

# Load flagged IPs from flagged.json
def _load_flagged_ips() -> Dict[str, Dict]:
    """
    Load flagged (banned) IPs from flagged.json with thread-safe file locking.
    
    Returns:
        Dictionary mapping IP addresses to their flag information (expiry, counts)
    """
    flagged_file = os.path.join(os.path.dirname(__file__), "flagged.json")
    flagged = {}
    try:
        with flagged_ips_lock:
            if os.path.exists(flagged_file):
                with open(flagged_file, 'r') as f:
                    flagged = json.load(f)
    except Exception as e:
        log_error('load_flagged_ips', e)
    return flagged

# Save flagged IPs to flagged.json
def _save_flagged_ips(flagged: Dict[str, Dict]) -> None:
    """
    Save flagged IPs dictionary to flagged.json with thread-safe file locking.
    
    Args:
        flagged: Dictionary mapping IPs to flag information
    """
    flagged_file = os.path.join(os.path.dirname(__file__), "flagged.json")
    try:
        with flagged_ips_lock:
            with open(flagged_file, 'w') as f:
                json.dump(flagged, f, indent=2)
    except Exception as e:
        log_error('save_flagged_ips', e)

# Load whitelisted IPs from whitelist.json
def _load_whitelist() -> List[str]:
    """
    Load admin whitelisted IPs from whitelist.json with thread-safe file locking.
    
    Returns:
        List of whitelisted IP address strings
    """
    whitelist_file = os.path.join(os.path.dirname(__file__), "whitelist.json")
    whitelist = []
    try:
        with whitelist_lock:
            if os.path.exists(whitelist_file):
                with open(whitelist_file, 'r') as f:
                    data = json.load(f)
                    # Support both list format and object format
                    if isinstance(data, list):
                        whitelist = data
                    elif isinstance(data, dict) and 'ips' in data:
                        whitelist = data['ips']
    except Exception as e:
        log_error('load_whitelist', e)
    return whitelist

# Save whitelisted IPs to whitelist.json
def _save_whitelist(whitelist: List[str]) -> None:
    """
    Save whitelisted IPs list to whitelist.json with thread-safe file locking.
    
    Args:
        whitelist: List of IP address strings to whitelist
    """
    whitelist_file = os.path.join(os.path.dirname(__file__), "whitelist.json")
    try:
        with whitelist_lock:
            with open(whitelist_file, 'w') as f:
                json.dump({'ips': whitelist, 'updated': datetime.utcnow().isoformat()}, f, indent=2)
    except Exception as e:
        log_error('save_whitelist', e)

# Check if an IP is whitelisted
def _is_ip_whitelisted(ip: str) -> bool:
    """
    Check if an IP address is in the whitelist.
    
    Args:
        ip: IP address string to check
        
    Returns:
        True if IP is whitelisted, False otherwise
    """
    whitelist = _load_whitelist()
    return str(ip) in whitelist

# Record an abuse event
def _record_abuse(metric: str, ip: str, session_id: Optional[str] = None, extra: Optional[Dict] = None) -> None:
    """
    Record an abuse event and evaluate if IP should be flagged.
    
    Args:
        metric: Type of abuse (e.g., 'duplicate', 'sanitize_reject', 'captcha_fail')
        ip: IP address of the abusive request
        session_id: Optional VocaGuard session ID
        extra: Optional dictionary with additional context
    """
    try:
        now_ts = int(datetime.utcnow().timestamp())
        # Create event for vocaguard.json logging
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
        # Log to vocaguard.json
        log_to_vocaguard_json(event)
        
        # Count recent abuse events from vocaguard.json to determine flagging
        recent_events = _load_vocaguard_events()
        ip_events = [e for e in recent_events if e.get('ip') == ip]
        
        # Count events by metric
        counts = {}
        for e in ip_events:
            metric_type = e.get('metric')
            counts[metric_type] = counts.get(metric_type, 0) + 1
        
        # Check if IP should be flagged
        should_flag = (
            counts.get('duplicate', 0) >= ABUSE_DUPLICATE_THRESHOLD or
            counts.get('sanitize_reject', 0) >= ABUSE_SANITIZE_REJECT_THRESHOLD or
            counts.get('captcha_fail', 0) >= ABUSE_CAPTCHA_FAIL_THRESHOLD
        )
        
        if should_flag:
            # Update flagged IPs in flagged.json
            flagged = _load_flagged_ips()
            flagged[ip] = {
                'until': int(now_ts + ABUSE_FLAG_DURATION_SECONDS),
                'counts': counts
            }
            _save_flagged_ips(flagged)
    except Exception as e:
        # Fail open; do not break main flow
        log_error('record_abuse', e)

# Check if an IP is flagged for abuse
def _is_flagged(ip: str) -> Tuple[bool, Optional[Dict]]:
    """
    Check if an IP is currently flagged for abuse, with auto-expiration of old flags.
    
    Args:
        ip: IP address to check
        
    Returns:
        Tuple of (is_flagged: bool, flag_info: dict or None)
    """
    try:
        flagged = _load_flagged_ips()
        now_ts = int(datetime.utcnow().timestamp())
        
        if ip in flagged:
            info = flagged[ip]
            if info.get('until', 0) > now_ts:
                return True, info
            # Flag has expired, remove it
            del flagged[ip]
            _save_flagged_ips(flagged)
        
        return False, None
    except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
        log_error('is_flagged_specific', e)
        return False, None
    except Exception as e:
        log_error('is_flagged_unexpected', e)
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
    default_limits=[API_DEFAULT_RATE_LIMIT],
)

# API Endpoints

# Start a new anti-cheat session
@app.route('/api/vocaguard/start', methods=['POST'])
def vocaguard_start():
    # Starts a new anti-cheat session and returns session_id
    session_id = str(uuid.uuid4())
    expires = (datetime.utcnow() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)).isoformat()
    
    # Use save_session (atomic) instead of load_sessions/save_sessions pattern
    new_session = {
        "session_id": session_id,
        "floor": 1,
        "level": 1,
        "expires": expires,
        "created": datetime.utcnow().isoformat(),
        "inv": {"carrierPigeon": 0},
        "last_level_update": None,
        "last_floor_update": None,
        "last_message_received_at": None,
        "last_from_session_delivered": None,
        "verified": False
    }
    save_session(session_id, new_session)

    return jsonify({
        "session_id": session_id,
    }), 200

# Update session progress with anti-cheat checks
@app.route('/api/vocaguard/update', methods=['POST'])
@limiter.limit("10 per minute")  # 10 updates per minute per IP
def vocaguard_update():
    # Updates session progress with anti-cheat validation
    data = request.get_json() or {}
    session_id = data.get('session_id')
    
    # VALIDATE TYPES EARLY to prevent TypeError (type safety fix)
    try:
        floor = int(data.get('floor', 0))
        level = int(data.get('level', 0))
    except (ValueError, TypeError):
        _record_abuse('invalid_progress_type', request.remote_addr, session_id,
                     {'floor_val': data.get('floor'), 'level_val': data.get('level')})
        return jsonify({"error": "Floor and level must be valid integers"}), 400
    
    # Fetch only this session (no full-table load)
    session = get_session_by_id(session_id)
    if not session:
        _record_abuse('invalid_session', request.remote_addr, session_id, 
                     {'attempted_session': session_id})
        return jsonify({"error": "Invalid session token"}), 400
    
    # Check expiration
    if datetime.fromisoformat(session['expires']) < datetime.utcnow():
        _record_abuse('session_expired', request.remote_addr, session_id)
        delete_session(session_id)
        return jsonify({"error": "Session expired"}), 400
    
    current_floor = session['floor']
    current_level = session['level']
    
    # Floor cannot decrease
    if floor < current_floor:
        _record_abuse('floor_regression', request.remote_addr, session_id, 
                     {'current': current_floor, 'attempted': floor})
        return jsonify({"error": "Floor regression detected", "detail": f"Current floor: {current_floor}, attempted: {floor}"}), 400
    
    # Level cannot decrease on same floor
    if floor == current_floor and level < current_level:
        _record_abuse('level_regression', request.remote_addr, session_id,
                     {'current': current_level, 'attempted': level})
        return jsonify({"error": "Level regression detected on same floor", "detail": f"Current level: {current_level}, attempted: {level}"}), 400
    
    # Prevent skipping floors
    if floor > current_floor and floor - current_floor > 1:
        _record_abuse('floor_skip', request.remote_addr, session_id,
                     {'current': current_floor, 'attempted': floor, 'skip_distance': floor - current_floor})
        return jsonify({"error": "Abnormal floor jump detected", "detail": f"Current floor: {current_floor}, attempted: {floor}"}), 400
    
    # Prevent abnormal level jumps (must increment by 1 or stay the same)
    if level > current_level and level - current_level > 1 and floor == current_floor:
        _record_abuse('level_jump', request.remote_addr, session_id,
                     {'current': current_level, 'attempted': level, 'jump_distance': level - current_level})
        return jsonify({"error": "Abnormal level jump detected", "detail": f"Current level: {current_level}, attempted: {level}"}), 400
    
    now = datetime.utcnow()
    last_level_update = session.get('last_level_update')
    last_floor_update = session.get('last_floor_update')

    # Enforce minimum 10 seconds between level increments
    if level > current_level:
        if last_level_update:
            last_level_update_dt = datetime.fromisoformat(last_level_update)
            if (now - last_level_update_dt).total_seconds() < 10:
                _record_abuse('level_speed_hack', request.remote_addr, session_id,
                             {'time_since_last': (now - last_level_update_dt).total_seconds()})
                return jsonify({"error": "Level increment too fast!"}), 400
        last_level_update = now.isoformat()
    else:
        last_level_update = session.get('last_level_update')

    # Enforce minimum 10 seconds between floor increments
    if floor > current_floor:
        if last_floor_update:
            last_floor_update_dt = datetime.fromisoformat(last_floor_update)
            if (now - last_floor_update_dt).total_seconds() < 10:
                _record_abuse('floor_speed_hack', request.remote_addr, session_id,
                             {'time_since_last': (now - last_floor_update_dt).total_seconds()})
                return jsonify({"error": "Floor increment too fast!"}), 400
        last_floor_update = now.isoformat()
    else:
        last_floor_update = session.get('last_floor_update')

    # Update session progress only if valid (targeted UPDATE, not full rewrite)
    new_expires = (datetime.utcnow() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)).isoformat()
    update_session(session_id, {
        'floor': floor,
        'level': level,
        'expires': new_expires,
        'last_level_update': last_level_update,
        'last_floor_update': last_floor_update
    })

    return jsonify({"status": "updated"}), 200

# Validate final submission before leaderboard post
@app.route('/api/vocaguard/validate', methods=['POST'])
def vocaguard_validate():
    # Validates final submission before leaderboard post
    data = request.get_json() or {}
    session_id = data.get('session_id')
    
    # VALIDATE TYPES EARLY (type safety fix)
    try:
        floor = int(data.get('floor', 0))
        level = int(data.get('level', 0))
    except (ValueError, TypeError):
        _record_abuse('invalid_progress_type', request.remote_addr, session_id,
                     {'floor_val': data.get('floor'), 'level_val': data.get('level')})
        return jsonify({"result": "fail", "reason": "Floor and level must be valid integers"}), 400
    
    # Fetch only this session (no full-table load)
    session = get_session_by_id(session_id)
    if not session:
        _record_abuse('invalid_session', request.remote_addr, session_id, 
                     {'attempted_session': session_id})
        return jsonify({"result": "fail", "reason": "Invalid session"}), 400
    
    if datetime.fromisoformat(session['expires']) < datetime.utcnow():
        _record_abuse('session_expired', request.remote_addr, session_id)
        delete_session(session_id)
        return jsonify({"result": "fail", "reason": "Session expired"}), 400
    
    if session['floor'] == floor and session['level'] == level:
        # Do NOT delete or expire sessions here!
        return jsonify({"result": "pass"}), 200
    else:
        # Log validation mismatch as abuse attempt
        _record_abuse('validate_mismatch', request.remote_addr, session_id,
                     {'session_floor': session['floor'], 'session_level': session['level'],
                      'submitted_floor': floor, 'submitted_level': level})
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
            log_error('leaderboard_get', e)
            return jsonify({"error": str(e)}), 500
    # POST: Update the leaderboard
    elif request.method == 'POST':
        try:
            new_entry = request.get_json() or {}
            if not new_entry or not isinstance(new_entry, dict):
                log_rejection("Invalid data format", new_entry)
                return jsonify({"error": "Invalid data format"}), 400
            # Core required fields (captcha token handled separately for backward compatibility)
            required_fields = ['name', 'floor', 'level', 'session_id']
            if not all(field in new_entry for field in required_fields):
                log_rejection("Missing required core fields", new_entry)
                return jsonify({"error": f"Missing required fields: {required_fields}"}), 400
            # Get captcha token from request (support both field names for compatibility)
            captcha_token = new_entry.get('captcha_token') or new_entry.get('hcaptcha_token')
            if not captcha_token:
                log_rejection("Captcha token missing", new_entry)
                _record_abuse('captcha_missing', request.remote_addr, new_entry.get('session_id'))
                return jsonify({"error": "Captcha token missing"}), 400
            if not verify_turnstile(captcha_token, remote_ip=request.remote_addr):
                log_rejection("Captcha verification failed", new_entry)
                _record_abuse('captcha_fail', request.remote_addr, new_entry.get('session_id'),
                             {'reason': 'captcha_verification_failed'})
                return jsonify({"error": "Captcha verification failed"}), 400
            raw_name = new_entry['name']
            filtered_name = re.sub(r'<.*?>', '', raw_name).strip()
            new_entry['name'] = clean_html(new_entry['name'])
            filtered_name = new_entry['name']
            if not filtered_name:
                log_rejection("Name is required and must be valid", new_entry)
                return jsonify({"error": "Name is required and must be valid"}), 400
            if re.search(r'[^A-Za-z0-9 ]', filtered_name):
                log_rejection("Name contains invalid characters", new_entry)
                return jsonify({"error": "Name contains invalid characters"}), 400
            if len(filtered_name) > MAX_LEADERBOARD_NAME_LENGTH:
                log_rejection(f"Name must be at most {MAX_LEADERBOARD_NAME_LENGTH} characters", new_entry)
                return jsonify({"error": f"Name must be at most {MAX_LEADERBOARD_NAME_LENGTH} characters"}), 400
            new_entry['name'] = filtered_name
            try:
                floor_val = int(new_entry['floor'])
                level_val = int(new_entry['level'])
            except (ValueError, TypeError):
                log_rejection("Floor and level must be valid numbers", new_entry)
                return jsonify({"error": "Floor and level must be valid numbers"}), 400
            new_entry['floor'] = floor_val
            new_entry['level'] = level_val
            
            # Fetch only this session (no full-table load)
            session = get_session_by_id(new_entry['session_id'])
            if not session:
                log_rejection("VocaGuard session missing or invalid", new_entry)
                _record_abuse('invalid_session', request.remote_addr, new_entry.get('session_id'))
                return jsonify({"error": "VocaGuard session missing or invalid"}), 400
            
            if datetime.fromisoformat(session['expires']) < datetime.utcnow():
                log_rejection("VocaGuard session expired", new_entry)
                _record_abuse('session_expired', request.remote_addr, new_entry.get('session_id'))
                delete_session(new_entry['session_id'])
                return jsonify({"error": "VocaGuard session expired"}), 400
            
            if session['floor'] != new_entry['floor'] or session['level'] != new_entry['level']:
                log_rejection("VocaGuard progress mismatch", new_entry)
                _record_abuse('validate_mismatch', request.remote_addr, new_entry.get('session_id'),
                             {'session_floor': session['floor'], 'session_level': session['level'],
                              'submitted_floor': new_entry['floor'], 'submitted_level': new_entry['level']})
                return jsonify({"error": "VocaGuard progress mismatch"}), 400
            
            # Expire session after successful leaderboard submission
            delete_session(new_entry['session_id'])
            # Insert into SQLite and return sorted list
            entry_to_store = {k: v for k, v in new_entry.items() if k not in ('session_id', 'captcha_token', 'hcaptcha_token')}
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
            log_error('leaderboard_post', e, {'request_data': str(new_entry)})
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
        _record_abuse('blocked_request', request.remote_addr, session_id)
        return jsonify({"error": "Temporarily blocked due to abuse", "until": info.get('until')}), 429
    
    # Fetch only this session (no full-table load)
    session = get_session_by_id(session_id)
    if not session:
        _record_abuse('invalid_session', request.remote_addr, session_id)
        return jsonify({"error": "Invalid session"}), 400
    
    if datetime.fromisoformat(session["expires"]) < datetime.utcnow():
        _record_abuse('session_expired', request.remote_addr, session_id)
        delete_session(session_id)
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
    
    # Fetch only this session (no full-table load)
    session = get_session_by_id(session_id)
    if not session:
        _record_abuse('invalid_session', request.remote_addr, session_id)
        return jsonify({"error": "Invalid session"}), 400
    
    if datetime.fromisoformat(session["expires"]) < datetime.utcnow():
        _record_abuse('session_expired', request.remote_addr, session_id)
        delete_session(session_id)
        return jsonify({"error": "Session expired"}), 400
    
    session = _ensure_inventory(session)
    cur = session['inv']['carrierPigeon']
    if cur >= MAX_PIGEONS_PER_SESSION:
        _record_abuse('pigeon_limit_reached', request.remote_addr, session_id)
        return jsonify({"error": "You've had enough pigeons for today!", "carrierPigeon": cur}), 400
    
    new_count = cur + 1
    new_expires = (datetime.utcnow() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)).isoformat()
    
    # Update inventory and expiry via targeted query
    # inv is passed as dict, update_session will json.dumps it
    update_session(session_id, {
        'expires': new_expires,
        'inv': {**session['inv'], 'carrierPigeon': new_count}
    })
    
    return jsonify({
        "purchased": True,
        "carrierPigeon": new_count,
        "remaining_capacity": MAX_PIGEONS_PER_SESSION - new_count
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

    # Fetch only this session (no full-table load)
    session = get_session_by_id(session_id)
    if not session:
        _record_abuse('invalid_session', request.remote_addr, session_id)
        return jsonify({"error": "Invalid session"}), 400
    
    if datetime.fromisoformat(session["expires"]) < datetime.utcnow():
        _record_abuse('session_expired', request.remote_addr, session_id)
        delete_session(session_id)
        return jsonify({"error": "Session expired"}), 400

    session = _ensure_inventory(session)
    if session['inv']['carrierPigeon'] <= 0:
        _record_abuse('no_inventory', request.remote_addr, session_id)
        return jsonify({"error": "No carrier pigeon in inventory"}), 400

    text = sanitize_pigeon_message(raw_text)
    if not text:
        _record_abuse('sanitize_reject', request.remote_addr, session_id)
        return jsonify({"error": "Message rejected (empty/invalid after sanitation)"}), 400

    # Check message count for this session (targeted query, LIMIT)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT COUNT(*) FROM pigeons WHERE from_session = ? AND delivered = 0', (session_id,))
    message_count = cur.fetchone()[0]
    conn.close()
    
    if message_count >= MAX_PIGEONS_PER_SESSION:
        _record_abuse('message_cap', request.remote_addr, session_id)
        return jsonify({"error": "Session pigeon message limit reached"}), 429

    # Check for duplicate (targeted query)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        'SELECT id FROM pigeons WHERE from_session = ? AND text = ? ORDER BY created DESC LIMIT 1',
        (session_id, text)
    )
    if cur.fetchone():
        conn.close()
        _record_abuse('duplicate', request.remote_addr, session_id)
        return jsonify({"error": "Duplicate message"}), 400
    conn.close()

    # Decrement pigeon inventory
    new_pigeon_count = session['inv']['carrierPigeon'] - 1
    update_session(session_id, {
        'inv': {**session['inv'], 'carrierPigeon': new_pigeon_count}
    })

    # Insert pigeon message (targeted INSERT, not full rewrite)
    pigeon_id = str(uuid.uuid4())
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        '''INSERT INTO pigeons (id, text, from_session, from_floor, from_level, from_verified, created, delivered, delivered_at, delivered_to)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (pigeon_id, text, session_id, int(session.get("floor", 0)), int(session.get("level", 0)), 
         bool(session.get("verified", False)), datetime.utcnow().isoformat(), 0, None, None)
    )
    conn.commit()
    conn.close()

    # Count pending pigeons (targeted COUNT query)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT COUNT(*) FROM pigeons WHERE delivered = 0')
    pending = cur.fetchone()[0]
    
    cur.execute('SELECT COUNT(*) FROM pigeons')
    total = cur.fetchone()[0]
    conn.close()

    _record_abuse('message_sent', request.remote_addr, session_id)

    return jsonify({
        "stored": True,
        "queue_length_pending": pending,
        "queue_length_total": total,
        "sanitized_text": text,
        "carrierPigeon_remaining": new_pigeon_count
    }), 200

# Deliver a pigeon message to session
@app.route('/api/pigeon/delivery', methods=['POST'])
@limiter.limit("5 per minute")
def pigeon_delivery():
    data = request.get_json() or {}
    session_id = data.get('session_id')
    if not session_id:
        return jsonify({"error": "session_id required"}), 400
    
    # Fetch only this session (no full-table load)
    session = get_session_by_id(session_id)
    if not session:
        _record_abuse('invalid_session', request.remote_addr, session_id)
        return jsonify({"error": "Invalid session"}), 400
    
    if datetime.fromisoformat(session["expires"]) < datetime.utcnow():
        _record_abuse('session_expired', request.remote_addr, session_id)
        delete_session(session_id)
        return jsonify({"error": "Session expired"}), 400

    # Use optimized delivery function with targeted query
    delivered_msg = get_pending_pigeon_for_delivery(
        session.get('floor', 0),
        session_id,
        session.get('last_from_session_delivered')
    )
    
    if delivered_msg:
        # Mark single pigeon delivered (targeted UPDATE, not full rewrite)
        mark_pigeon_delivered(delivered_msg['id'], session_id)
        
        # Update session metadata (targeted UPDATE, not full rewrite)
        update_session(session_id, {
            'last_message_received_at': datetime.utcnow().isoformat(),
            'last_from_session_delivered': delivered_msg.get('from_session')
        })
    
    # Count pending pigeons (targeted COUNT query)
    pending = get_pending_pigeon_count(session_id)
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT COUNT(*) FROM pigeons')
    total = cur.fetchone()[0]
    conn.close()

    return jsonify({
        "delivered": bool(delivered_msg),
        "pigeon_message": delivered_msg["text"] if delivered_msg else None,
        "pigeon_id": delivered_msg["id"] if delivered_msg else None,
        "remaining_queue_pending": pending,
        "remaining_queue_total": total
    }), 200

# Get abuse status (whitelisted IPs only)
@app.route('/api/abuse/status', methods=['GET'])
def abuse_status():
    # Whitelist-based access control
    if not _is_ip_whitelisted(request.remote_addr):
        log_error('abuse_status_unauthorized', Exception(f"Unauthorized IP access: {request.remote_addr}"))
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        # Load flagged IPs from flagged.json
        flagged = _load_flagged_ips()
        
        # Get aggregated counts from vocaguard.json
        recent_events = _load_vocaguard_events()
        agg = {}
        for e in recent_events:
            ip = e.get('ip')
            metric = e.get('metric')
            agg.setdefault(ip, {})[metric] = agg.setdefault(ip, {}).get(metric, 0) + 1
        
        return jsonify({
            'flagged': flagged,
            'counts': agg,
            'window_seconds': ABUSE_EVENT_WINDOW_SECONDS,
            'vocaguard_events': recent_events
        })
    except Exception as e:
        log_error('abuse_status', e)
        return jsonify({"error": str(e)}), 500

# Utility Functions

# Get Turnstile secret from environment
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "")

# Verify Cloudflare Turnstile token
def verify_turnstile(token: str, remote_ip: str = None) -> bool:
    if not token or not TURNSTILE_SECRET:
        return False
    url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    data = {"secret": TURNSTILE_SECRET, "response": token}
    if remote_ip:
        data["remoteip"] = remote_ip
    try:
        resp = requests.post(url, data=data, timeout=EXTERNAL_API_TIMEOUT_SECONDS)
        result = resp.json()
        return bool(result.get("success"))
    except Exception as e:
        print(f"Turnstile verification error: {e}")
        return False

# Clean HTML and scripts from string, enforce max length limit
def clean_html(val: str) -> str:
    """
    Clean HTML/script tags and dangerous content from string.
    
    Args:
        val: Input string to clean
        
    Returns:
        Cleaned string limited to MAX_LEADERBOARD_NAME_LENGTH, alphanumeric + spaces only
    """
    # Cleans HTML/script from string and enforces MAX_LEADERBOARD_NAME_LENGTH limit
    if isinstance(val, str):
        val = re.sub(r'<.*?>', '', val)
        val = re.sub(r'(script|meta|iframe|onerror|onload|javascript:|http-equiv|src|href|alert|document|window)', '', val, flags=re.IGNORECASE)
        val = val.strip()
        val = val[:MAX_LEADERBOARD_NAME_LENGTH]
        val = re.sub(r'[^A-Za-z0-9 ]', '', val)
        return val
    return val

# Recursively clean JSON data
def clean_json(obj: any) -> any:
    """
    Recursively clean JSON data structure by sanitizing 'name' fields.
    
    Args:
        obj: JSON object (dict, list, or scalar) to clean
        
    Returns:
        Cleaned JSON object with same structure
    """
    # Recursively clean leaderboard JSON
    if isinstance(obj, dict):
        return {k: clean_html(v) if k == 'name' else clean_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [clean_json(item) for item in obj]
    else:
        return obj

# Log rejection reason to vocaguard.json
def log_rejection(reason: str, data: Optional[Dict]) -> None:
    # Append rejection event to vocaguard.json
    try:
        now_ts = int(datetime.utcnow().timestamp())
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
        log_to_vocaguard_json(event)
    except Exception as e:
        # Fail open; rejection logging failure should not block main flow
        pass

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

# Purge old sessions
def purge_old_sessions():
    # Delete sessions older than SESSION_PURGE_AGE_DAYS with error handling
    try:
        cutoff = (datetime.utcnow() - timedelta(days=SESSION_PURGE_AGE_DAYS)).isoformat()
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM sessions WHERE created < ?", (cutoff,))
        deleted_count = cur.rowcount
        conn.commit()
        conn.close()
        if deleted_count > 0:
            print(f"Purged {deleted_count} old sessions")
    except Exception as e:
        log_error('purge_old_sessions', e)

def session_purge_worker():
    # Background thread to purge old sessions every BACKGROUND_WORKER_SLEEP_SECONDS
    while True:
        try:
            purge_old_sessions()
        except Exception as e:
            log_error('session_purge_worker', e)
        time.sleep(BACKGROUND_WORKER_SLEEP_SECONDS)

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