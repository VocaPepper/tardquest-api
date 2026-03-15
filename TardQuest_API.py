from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from typing import Any, Dict, List, Tuple, Optional, cast
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
import logging
from logging.handlers import RotatingFileHandler
from threading import Lock, RLock

# Import VocaGuard anti-cheat module
from vocaguard import validator as vocaguard_validator

load_dotenv()

app = Flask(__name__)
# Trust X-Forwarded-For from reverse proxy (1 proxy hop)
# This ensures request.remote_addr reflects the real client IP
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
# Enable CORS for specified origins to allow cross-origin requests
CORS(app, origins=["app://tard.quest", "https://vocapepper.com", "https://milklounge.wang", "https://uploads.ungrounded.net"])

# --- Directory Layout ---
# JSON state/config files live under json/
_json_dir = os.path.join(os.path.dirname(__file__), 'json')
os.makedirs(_json_dir, exist_ok=True)

# --- Unified Logging Setup ---
# All logs are written under the logs/ directory using RotatingFileHandler.
# Format: plain-text .log files for easy tailing, grepping, and rotation.
_log_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(_log_dir, exist_ok=True)

def _make_logger(name: str, filename: str, max_bytes: int = 10 * 1024 * 1024, backup_count: int = 5) -> logging.Logger:
    """Create a named rotating file logger under logs/."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = RotatingFileHandler(
        os.path.join(_log_dir, filename),
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)
    return logger

# Access log: logs/access.log  — every HTTP request
access_logger = _make_logger('access', 'access.log')
# VocaGuard / abuse log: logs/vocaguard.log  — abuse events, rejections
vocaguard_logger = _make_logger('vocaguard', 'vocaguard.log')
# Error log: logs/error.log  — server errors with tracebacks
error_logger = _make_logger('error', 'error.log')

@app.after_request
def log_request(response):
    """Log every request with the real client IP from X-Forwarded-For."""
    access_logger.info(
        '%s %s %s %s %s %d %s',
        datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        request.remote_addr,
        request.method,
        request.path,
        request.headers.get('User-Agent', '-'),
        response.status_code,
        request.headers.get('Referer', '-')
    )
    return response

# --- Thread Safety ---
# Locks for concurrent access to state files and session operations
flagged_ips_lock = Lock()
whitelist_lock = Lock()
launcher_manifest_lock = Lock()
# Per-session lock to prevent race conditions on concurrent updates
# RLock (reentrant) so pigeon_send can hold it while calling update_session
session_ops_lock = RLock()

# --- Application Configuration Constants ---
# Major.Minor.Patch
API_VERSION = "3.2.260315"
MIN_CLIENT_VERSION = "3.0.251113" # Minimum supported client version
# Server-Client check looks at Major.Minor only for compatibility, patch is numbered by date last edited in YYMMDD format.
# Legacy endpoints ignore this check, as they are deprecated and will be removed in future versions.

# Database connection timeout in seconds
DB_CONNECTION_TIMEOUT_SECONDS = 30
# API rate limiting: default maximum requests
API_DEFAULT_RATE_LIMIT = "100 per hour"
# External API timeout in seconds (for Turnstile, etc)
EXTERNAL_API_TIMEOUT_SECONDS = 5
# Session age before auto-purge in days
SESSION_PURGE_AGE_DAYS = 7
# Background worker sleep interval in seconds
BACKGROUND_WORKER_SLEEP_SECONDS = 24 * 60 * 60  # 24 hours
# Maximum leaderboard name length
MAX_LEADERBOARD_NAME_LENGTH = 5
# Developer API key for launcher manifest updates
MANIFESTO_API_KEY = os.getenv('MANIFESTO_API_KEY', '').strip()

# --- Anti-Cheat Configuration ---
# Enable/disable VocaGuard anti-cheat validation on progress updates
ENABLE_VOCAGUARD = os.getenv('ENABLE_VOCAGUARD', 'true').lower() in ('true', '1', 'yes')
# Allow legacy PoW proof format for older clients
ALLOW_LEGACY_POW = os.getenv('ALLOW_LEGACY_POW', 'true').lower() in ('true', '1', 'yes')
# Modern PoW leading-zero difficulty (clamped)
try:
    POW_DIFFICULTY_PREFIX_ZEROS = max(1, min(8, int(os.getenv('POW_DIFFICULTY_PREFIX_ZEROS', '4'))))
except (TypeError, ValueError):
    POW_DIFFICULTY_PREFIX_ZEROS = 4

# --- Session Configuration ---
SESSION_TIMEOUT_MINUTES = 120  # 2 hours (resets on vocaguard update)

# --- Pigeon Messaging Configuration ---
ALLOWED_CHARS_PATTERN = re.compile(r"[^A-Za-z0-9 .,!?;:'\-_/()\[\]@#%&*+=$\\\"]+")
MAX_PIGEON_MESSAGE_LEN = 420
MAX_PIGEONS_PER_SESSION = 20       # hard cap beyond rate limit
PIGEON_RATE_LIMIT = "20 per hour"  # purchase spam guard

# Delivery prioritization weights
FLOOR_PROXIMITY_RANGE = 2               # preferred ±2 floors
PRIORITY_HIGH_FLOOR_WEIGHT = 0.05       # +5% weight per sender floor
PRIORITY_VERIFIED_MULTIPLIER = 1.5      # 50% boost for verified senders
AGE_BOOST_FULL_SECONDS = 600            # full age boost after 10 min
AGE_BOOST_MAX = 0.5                     # up to +50% boost for older messages
RANDOM_JITTER_MIN = 0.85                # randomness factor range
RANDOM_JITTER_MAX = 1.15
REPEAT_SENDER_PENALTY = 0.5             # de-prioritize same sender consecutively

# --- Abuse Monitoring Thresholds ---
ABUSE_EVENT_WINDOW_SECONDS = 3600  # 1 hour rolling window
ABUSE_DUPLICATE_THRESHOLD = 2
ABUSE_SANITIZE_REJECT_THRESHOLD = 2
ABUSE_CAPTCHA_FAIL_THRESHOLD = 2
ABUSE_FLAG_DURATION_SECONDS = 3600  # 1 hour ban

# --- External Service Secrets ---
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "")

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
            verified INTEGER DEFAULT 0,
            created_via TEXT DEFAULT 'api_start'
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
        # Track pigeon murders reported by players
        """
        CREATE TABLE IF NOT EXISTS pigeon_murders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            pigeon_id TEXT,
            murdered_at TEXT NOT NULL,
            UNIQUE(session_id, pigeon_id)
        )
        """
    )
    
    # Migration: Add created_via column if it doesn't exist
    try:
        cur.execute("PRAGMA table_info(sessions)")
        columns = [col[1] for col in cur.fetchall()]
        if 'created_via' not in columns:
            cur.execute("ALTER TABLE sessions ADD COLUMN created_via TEXT DEFAULT 'api_start'")
            conn.commit()
            print("✓ Database Migration: Added created_via column to sessions table")
        if 'exp' not in columns:
            cur.execute("ALTER TABLE sessions ADD COLUMN exp INTEGER DEFAULT 0")
            conn.commit()
            print("✓ Database Migration: Added exp column to sessions table")
    except Exception as e:
        log_error('Database Migration', e, {'operation': 'add_columns'})
    
    conn.commit()
    conn.close()

# Initialize DB
init_db()

# --- Session Management ---

def save_session(session_id: str, session: Dict[str, Any]) -> None:
    """
    Save a single session to database using atomic INSERT OR REPLACE.
    
    Args:
        session_id: The session identifier
        session: Dictionary containing session data
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Try to insert with created_via column
        try:
            cur.execute(
                'INSERT OR REPLACE INTO sessions (session_id, floor, level, exp, expires, created, inv, last_level_update, last_floor_update, last_message_received_at, last_from_session_delivered, verified, created_via) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    session_id,
                    int(session.get('floor', 1)),
                    int(session.get('level', 1)),
                    int(session.get('exp', 0)),
                    session.get('expires', ''),
                    session.get('created', ''),
                    json.dumps(session.get('inv', {})),
                    session.get('last_level_update'),
                    session.get('last_floor_update'),
                    session.get('last_message_received_at'),
                    session.get('last_from_session_delivered'),
                    1 if session.get('verified') else 0,
                    session.get('created_via', 'api_start'),
                )
            )
        except Exception:
            # Fallback: column might not exist yet, insert without created_via
            cur.execute(
                'INSERT OR REPLACE INTO sessions (session_id, floor, level, exp, expires, created, inv, last_level_update, last_floor_update, last_message_received_at, last_from_session_delivered, verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    session_id,
                    int(session.get('floor', 1)),
                    int(session.get('level', 1)),
                    int(session.get('exp', 0)),
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

# --- Per-Session Database Functions ---

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
        # Try to fetch with exp + created_via columns first
        try:
            cur.execute('SELECT session_id, floor, level, exp, expires, created, inv, last_level_update, last_floor_update, last_message_received_at, last_from_session_delivered, verified, created_via FROM sessions WHERE session_id = ?', (session_id,))
            row = cur.fetchone()
        except Exception:
            try:
                # Fallback: exp present but created_via missing
                cur.execute('SELECT session_id, floor, level, exp, expires, created, inv, last_level_update, last_floor_update, last_message_received_at, last_from_session_delivered, verified FROM sessions WHERE session_id = ?', (session_id,))
                row = cur.fetchone()
                if row:
                    row = tuple(list(row) + ['api_start'])
            except Exception:
                # Fallback: legacy schema without exp or created_via
                cur.execute('SELECT session_id, floor, level, expires, created, inv, last_level_update, last_floor_update, last_message_received_at, last_from_session_delivered, verified FROM sessions WHERE session_id = ?', (session_id,))
                row = cur.fetchone()
                if row:
                    # Insert default exp=0 and created_via='api_start'
                    row = tuple(list(row[:3]) + [0] + list(row[3:]) + ['api_start'])
        
        conn.close()
        
        if not row:
            return None
        
        # Normalize row to expected shape: (sid, floor, level, exp, expires, created, inv, last_level_update, last_floor_update, last_message_received_at, last_from_session_delivered, verified, created_via)
        if len(row) == 13:
            sid, floor, level, exp_val, expires, created, inv_raw, last_level_update, last_floor_update, last_message_received_at, last_from_session_delivered, verified, created_via = row
        elif len(row) == 12:
            sid, floor, level, exp_val, expires, created, inv_raw, last_level_update, last_floor_update, last_message_received_at, last_from_session_delivered, verified = row
            created_via = 'api_start'
        elif len(row) == 11:
            sid, floor, level, expires, created, inv_raw, last_level_update, last_floor_update, last_message_received_at, last_from_session_delivered, verified = row
            exp_val = 0
            created_via = 'api_start'
        else:
            return None

        return {
            'session_id': sid,
            'floor': int(floor),
            'level': int(level),
            'exp': int(exp_val),
            'expires': expires,
            'created': created,
            'inv': json.loads(inv_raw) if inv_raw else {},
            'last_level_update': last_level_update,
            'last_floor_update': last_floor_update,
            'last_message_received_at': last_message_received_at,
            'last_from_session_delivered': last_from_session_delivered,
            'verified': bool(verified),
            'created_via': created_via
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
            if 'exp' in updates:
                set_clauses.append('exp = ?')
                params.append(int(updates['exp']))
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
        
        # Apply weighting logic (proximity, age, repeat-sender penalty, etc.)
        recipient_ctx = {'floor': recipient_floor, 'last_from_session_delivered': exclude_recent_sender}
        weights = [_message_weight(p, recipient_ctx) for p in candidates]
        
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
            'UPDATE pigeons SET delivered = 1, delivered_at = ?, delivered_to = ? WHERE id = ? AND delivered = 0',
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
    Get count of undelivered pigeons sent BY a specific session (outbox count).
    
    Args:
        session_id: The sender's session identifier
        
    Returns:
        Count of pending outbound pigeons
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

def get_deliverable_pigeon_count(session_id: str) -> int:
    """
    Get count of undelivered pigeons available FOR delivery to a session
    (i.e. not sent by this session).
    
    Args:
        session_id: The recipient's session identifier
        
    Returns:
        Count of pigeons available for delivery
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM pigeons WHERE delivered = 0 AND from_session != ?', (session_id,))
        count = cur.fetchone()[0]
        conn.close()
        return count
    except Exception as e:
        log_error('get_deliverable_pigeon_count', e, {'session_id': session_id})
        return 0

def record_pigeon_murder(session_id: str, pigeon_id: Optional[str] = None) -> str:
    """
    Record a pigeon murder event for a session.

    Args:
        session_id: The session that reported the murder
        pigeon_id: Optional pigeon ID for de-duplication

    Returns:
        'ok' on insert, 'duplicate' if already reported for this session+pigeon,
        or 'error' on unexpected failure.
    """
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO pigeon_murders (session_id, pigeon_id, murdered_at) VALUES (?, ?, ?)',
            (session_id, pigeon_id, datetime.utcnow().isoformat())
        )
        conn.commit()
        return 'ok'
    except sqlite3.IntegrityError:
        return 'duplicate'
    except Exception as e:
        log_error('record_pigeon_murder', e, {'session_id': session_id, 'pigeon_id': pigeon_id})
        return 'error'
    finally:
        if conn:
            conn.close()

def get_pigeon_murder_totals(session_id: Optional[str] = None) -> Dict[str, int]:
    """
    Get aggregate pigeon murder totals.

    Args:
        session_id: Optional session to include per-session count

    Returns:
        Dictionary with total_murdered, unique_players, session_murdered
    """
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute('SELECT COUNT(*) FROM pigeon_murders')
        total = int(cur.fetchone()[0])

        cur.execute('SELECT COUNT(DISTINCT session_id) FROM pigeon_murders')
        unique_players = int(cur.fetchone()[0])

        session_total = 0
        if session_id:
            cur.execute('SELECT COUNT(*) FROM pigeon_murders WHERE session_id = ?', (session_id,))
            session_total = int(cur.fetchone()[0])

        return {
            'total_murdered': total,
            'unique_players': unique_players,
            'session_murdered': session_total,
        }
    except Exception as e:
        log_error('get_pigeon_murder_totals', e, {'session_id': session_id})
        return {'total_murdered': 0, 'unique_players': 0, 'session_murdered': 0}
    finally:
        if conn:
            conn.close()

# --- Helper Functions for API Responses ---

def _is_session_expired(session: Dict) -> bool:
    """Check whether a session's 'expires' timestamp is in the past.

    Returns True (expired) when the value is missing, malformed, or past-due,
    so callers never need to catch ValueError themselves.
    """
    try:
        return datetime.fromisoformat(session['expires']) < datetime.utcnow()
    except (ValueError, KeyError, TypeError):
        return True

# VocaGuard / abuse event log — logs/vocaguard.log
# Line format: TIMESTAMP|IP|METRIC|sid=...|key=value ...
def log_vocaguard_event(event: Dict) -> None:
    """
    Append an abuse/VocaGuard event line to logs/vocaguard.log.
    Thread-safe via RotatingFileHandler internal locking.
    
    Args:
        event: Dictionary containing event data (ts, ip, metric, etc.)
    """
    try:
        def _sanitize_log_field(val: Any) -> str:
            """Strip pipe and newline characters to prevent log injection."""
            return str(val).replace('|', '_').replace('\n', ' ').replace('\r', ' ')

        ts = datetime.utcfromtimestamp(event.get('ts', int(datetime.utcnow().timestamp()))).strftime('%Y-%m-%d %H:%M:%S')
        ip = _sanitize_log_field(event.get('ip', 'unknown'))
        metric = _sanitize_log_field(event.get('metric', 'unknown'))
        parts = [ts, ip, metric]
        # Append optional structured fields
        if event.get('sid'):
            parts.append(f"sid={_sanitize_log_field(event['sid'])}")
        if event.get('reason'):
            parts.append(f"reason={_sanitize_log_field(event['reason'])}")
        if event.get('ua'):
            parts.append(f"ua={_sanitize_log_field(event['ua'])}")
        if event.get('extra'):
            for k, v in event['extra'].items():
                parts.append(f"{_sanitize_log_field(k)}={_sanitize_log_field(v)}")
        if event.get('data_excerpt'):
            for k, v in event['data_excerpt'].items():
                if v is not None:
                    parts.append(f"{_sanitize_log_field(k)}={_sanitize_log_field(v)}")
        vocaguard_logger.info('|'.join(str(p) for p in parts))
    except Exception as e:
        print(f"VOCAGUARD LOG ERROR: {e}")

# Error log — logs/error.log
def log_error(function_name: str, error: Exception, context: Optional[Dict] = None) -> None:
    """
    Log an error with stack trace and context to logs/error.log.
    
    Args:
        function_name: Name of the function where error occurred
        error: The exception object
        context: Optional dictionary with contextual data (counts, session info, etc.)
    """
    try:
        ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        tb = traceback.format_exc().replace('\n', '\\n')  # flatten for single-line log
        ctx = ''
        if context:
            ctx = ' ' + ' '.join(f'{k}={v}' for k, v in context.items())
        error_logger.info(
            '%s|%s|%s|%s|%s%s',
            ts, function_name, type(error).__name__, str(error), tb, ctx
        )
    except Exception as e:
        print(f"LOG ERROR FAILED: {e}")

def _load_vocaguard_events() -> List[Dict]:
    """
    Load recent vocaguard events within the time window from logs/vocaguard.log.
    Parses pipe-delimited log lines back into dicts for abuse threshold checks.
    
    Returns:
        List of event dictionaries from the past ABUSE_EVENT_WINDOW_SECONDS
    """
    vocaguard_log_file = os.path.join(_log_dir, 'vocaguard.log')
    events = []
    if not os.path.exists(vocaguard_log_file):
        return events
    try:
        now_ts = int(datetime.utcnow().timestamp())
        cutoff = now_ts - ABUSE_EVENT_WINDOW_SECONDS
        with open(vocaguard_log_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split('|')
                if len(parts) < 3:
                    continue
                try:
                    ts = int(datetime.strptime(parts[0], '%Y-%m-%d %H:%M:%S').timestamp())
                except (ValueError, IndexError):
                    continue
                if ts < cutoff:
                    continue
                event: Dict[str, Any] = {'ts': ts, 'ip': parts[1], 'metric': parts[2]}
                # Parse remaining key=value fields
                for part in parts[3:]:
                    if '=' in part:
                        k, _, v = part.partition('=')
                        event[k] = v
                events.append(event)
    except Exception as e:
        log_error('load_vocaguard_events', e)
    return events

def _load_flagged_ips() -> Dict[str, Dict]:
    """
    Load flagged (banned) IPs from json/flagged.json with thread-safe file locking.
    
    Returns:
        Dictionary mapping IP addresses to their flag information (expiry, counts)
    """
    flagged_file = os.path.join(_json_dir, 'flagged.json')
    flagged = {}
    try:
        with flagged_ips_lock:
            if os.path.exists(flagged_file):
                with open(flagged_file, 'r') as f:
                    flagged = json.load(f)
    except Exception as e:
        log_error('load_flagged_ips', e)
    return flagged

def _save_flagged_ips(flagged: Dict[str, Dict]) -> None:
    """
    Save flagged IPs dictionary to json/flagged.json with thread-safe file locking.
    
    Args:
        flagged: Dictionary mapping IPs to flag information
    """
    flagged_file = os.path.join(_json_dir, 'flagged.json')
    try:
        with flagged_ips_lock:
            with open(flagged_file, 'w') as f:
                json.dump(flagged, f, indent=2)
    except Exception as e:
        log_error('save_flagged_ips', e)

def _load_whitelist() -> List[str]:
    """
    Load admin whitelisted IPs from json/whitelist.json with thread-safe file locking.
    
    Returns:
        List of whitelisted IP address strings
    """
    whitelist_file = os.path.join(_json_dir, 'whitelist.json')
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

def _is_ip_whitelisted(ip: Optional[str]) -> bool:
    """
    Check if an IP address is in the whitelist.
    
    Args:
        ip: IP address string to check
        
    Returns:
        True if IP is whitelisted, False otherwise
    """
    if not ip:
        return False
    whitelist = _load_whitelist()
    return str(ip) in whitelist

def _record_abuse(metric: str, ip: Optional[str], session_id: Optional[str] = None, extra: Optional[Dict] = None) -> None:
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
        # Create event for vocaguard log
        safe_ip = ip or "unknown"
        event: Dict[str, Any] = {
            'ts': now_ts,
            'ip': safe_ip,
            'metric': metric
        }
        if session_id:
            event['sid'] = session_id
        if extra:
            # avoid storing sensitive raw data
            safe_extra = {k: (v if k != 'raw' else None) for k, v in extra.items()}
            event['extra'] = safe_extra
        # Log to logs/vocaguard.log
        log_vocaguard_event(event)
        
        # Count recent abuse events from vocaguard log to determine flagging
        recent_events = _load_vocaguard_events()
        ip_events = [e for e in recent_events if e.get('ip') == safe_ip]
        
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
            # Update flagged IPs in json/flagged.json
            flagged = _load_flagged_ips()
            flagged[safe_ip] = {
                'until': int(now_ts + ABUSE_FLAG_DURATION_SECONDS),
                'counts': counts
            }
            _save_flagged_ips(flagged)
    except Exception as e:
        # Fail open; do not break main flow
        log_error('record_abuse', e)

def _is_flagged(ip: Optional[str]) -> Tuple[bool, Optional[Dict]]:
    """
    Check if an IP is currently flagged for abuse, with auto-expiration of old flags.
    
    Args:
        ip: IP address to check
        
    Returns:
        Tuple of (is_flagged: bool, flag_info: dict or None)
    """
    if not ip:
        return False, None
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

def sanitize_pigeon_message(raw: str) -> str:
    """Sanitize pigeon message: normalize unicode, strip HTML, filter characters, enforce length."""
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


def parse_version(version_str: str) -> Optional[Tuple[int, int, int]]:
    """Parse a 'major.minor.patch' version string into a comparable tuple."""
    try:
        parts = version_str.split('.')
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except (IndexError, ValueError):
        return None


# --- Rate Limiting ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[API_DEFAULT_RATE_LIMIT],
)

# API Endpoints

# Start a new session
@app.route('/api/start', methods=['POST'])
def tardquest_start():
    # Starts a new session and returns session_id
    # First check: validate client API version before assigning session
    data = request.get_json() or {}
    client_version = data.get('version')
    
    if not client_version:
        return jsonify({
            "error": "Client API version required",
            "server_version": API_VERSION,
            "reason": "Missing 'version' field in request"
        }), 400
    
    client_version_tuple = parse_version(client_version)
    server_version_tuple = parse_version(API_VERSION)
    min_client_tuple = parse_version(MIN_CLIENT_VERSION)
    
    if not client_version_tuple or not server_version_tuple or not min_client_tuple:
        return jsonify({
            "error": "Invalid version format",
            "server_version": API_VERSION,
            "client_version": client_version,
            "reason": "Version must be in format: major.minor.patch"
        }), 400
    
    # Reject if below minimum supported client version (full comparison)
    if client_version_tuple < min_client_tuple:
        return jsonify({
            "error": "Client version too old",
            "server_version": API_VERSION,
            "client_version": client_version,
            "minimum_required": MIN_CLIENT_VERSION,
            "reason": f"Update client to at least {MIN_CLIENT_VERSION}"
        }), 400
    
    # Abuse flag check
    flagged, info = _is_flagged(request.remote_addr)
    if flagged:
        info = info or {}
        _record_abuse('blocked_request', request.remote_addr)
        return jsonify({"error": "Temporarily blocked due to abuse", "until": info.get('until')}), 429

    # Version check passed, proceed with session creation
    session_id = str(uuid.uuid4())
    expires = (datetime.utcnow() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)).isoformat()
    
    new_session = {
        "session_id": session_id,
        "floor": 1,
        "level": 1,
        "exp": 0,
        "expires": expires,
        "created": datetime.utcnow().isoformat(),
        "inv": {"carrierPigeon": 0},
        "last_floor_update": None,
        "last_message_received_at": None,
        "last_from_session_delivered": None,
        "verified": False,
        "created_via": "api_start"
    }
    save_session(session_id, new_session)

    response_data: Dict[str, Any] = {
        "session_id": session_id,
        "server_version": API_VERSION
    }

    # Generate proof-of-work challenge if VocaGuard is enabled
    if ENABLE_VOCAGUARD:
        challenge_id, challenge_salt = vocaguard_validator.generate_challenge(session_id)
        response_data["challenge_id"] = challenge_id
        response_data["challenge_salt"] = challenge_salt
        response_data["challenge_difficulty"] = POW_DIFFICULTY_PREFIX_ZEROS
        if ALLOW_LEGACY_POW:
            # Backwards compatibility for older clients that expect challenge_secret
            response_data["challenge_secret"] = challenge_salt

    return jsonify(response_data), 200

# Update session progress
@app.route('/api/update', methods=['POST'])
@limiter.limit("10 per minute")  # 10 updates per minute per IP
def vocaguard_update():
    # Updates session progress with optional anti-cheat validation
    data = request.get_json() or {}
    session_id = data.get('session_id')

    if not isinstance(session_id, str) or not session_id:
        return jsonify({"error": "session_id required"}), 400
    
    # Abuse flag check
    flagged, info = _is_flagged(request.remote_addr)
    if flagged:
        info = info or {}
        _record_abuse('blocked_request', request.remote_addr, session_id)
        return jsonify({"error": "Temporarily blocked due to abuse", "until": info.get('until')}), 429

    # VALIDATE TYPES EARLY to prevent TypeError (type safety fix)
    try:
        floor = int(data.get('floor', 0))
        level = int(data.get('level', 0))
        exp = int(data.get('exp', 0))
    except (ValueError, TypeError):
        _record_abuse('invalid_progress_type', request.remote_addr, session_id,
                     {'floor_val': data.get('floor'), 'level_val': data.get('level'), 'exp_val': data.get('exp')})
        return jsonify({"error": "Floor, level, and exp must be valid integers"}), 400
    
    # Fetch only this session (no full-table load)
    session = get_session_by_id(session_id)
    if not session:
        _record_abuse('invalid_session', request.remote_addr, session_id, 
                     {'attempted_session': session_id})
        return jsonify({"error": "Invalid session token"}), 400
    
    # Check expiration
    if _is_session_expired(session):
        _record_abuse('session_expired', request.remote_addr, session_id)
        delete_session(session_id)
        return jsonify({"error": "Session expired"}), 400
    
    current_floor = session['floor']
    current_level = session['level']
    current_exp = session.get('exp', 0)
    last_floor_update = session.get('last_floor_update')
    
    # Run anti-cheat validation if enabled
    if ENABLE_VOCAGUARD:
        is_valid, error_message, abuse_details = vocaguard_validator.validate_progress_update(
            current_floor=current_floor,
            current_level=current_level,
            current_exp=current_exp,
            new_floor=floor,
            new_level=level,
            new_exp=exp,
            session_id=session_id,
            last_floor_update=last_floor_update
        )
        
        if not is_valid:
            # Record abuse and return error
            abuse_details = abuse_details or {}
            _record_abuse(abuse_details.get('cheat_type', 'unknown_cheat'), 
                         request.remote_addr, session_id, abuse_details)
            safe_message = error_message or "Invalid progress update"
            return jsonify({
                "error": safe_message,
                "detail": f"Current floor: {current_floor}, attempted: {floor}" if "floor" in safe_message.lower() else f"Current level: {current_level}, attempted: {level}"
            }), 400
    
    # Update progress with new timestamps for floor increments
    now = datetime.utcnow().isoformat()
    new_last_floor_update = now if floor > current_floor else last_floor_update
    
    # Update session progress only if valid (targeted UPDATE, not full rewrite)
    new_expires = (datetime.utcnow() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)).isoformat()
    update_session(session_id, {
        'floor': floor,
        'level': level,
        'exp': exp,
        'expires': new_expires,
        'last_floor_update': new_last_floor_update
    })

    return jsonify({"status": "updated"}), 200

# Get API status
@app.route('/api/status', methods=['GET'])
def api_status():
    # Returns API status
    # Abuse flag check
    flagged, info = _is_flagged(request.remote_addr)
    if flagged:
        info = info or {}
        _record_abuse('blocked_request', request.remote_addr)
        return jsonify({"error": "Temporarily blocked due to abuse", "until": info.get('until')}), 429
    
    return jsonify({"status": "ok", "version": API_VERSION}), 200

@app.route('/api/launcher-win64', methods=['GET', 'POST'])
def launcher_win64():
    # Abuse flag check
    flagged, info = _is_flagged(request.remote_addr)
    if flagged:
        info = info or {}
        _record_abuse('blocked_request', request.remote_addr)
        return jsonify({"error": "Temporarily blocked due to abuse", "until": info.get('until')}), 429
    
    try:
        if request.method == 'GET':
            manifest = _load_launcher_manifest()
            if manifest is None:
                return jsonify({"error": "launcher-win64.json not found"}), 404
            return jsonify(manifest), 200

        provided_key = _extract_launcher_api_key(request)
        if not MANIFESTO_API_KEY:
            return jsonify({"error": "Launcher manifest update API key is not configured"}), 503
        if not provided_key or provided_key != MANIFESTO_API_KEY:
            _record_abuse('launcher_manifest_auth_fail', request.remote_addr)
            return jsonify({"error": "Unauthorized"}), 401

        payload = request.get_json(silent=True) or {}
        operation = str(payload.get('operation') or 'upsert_version').strip()

        if operation == 'replace_manifest':
            manifest = payload.get('manifest')
            valid, error_message = _validate_launcher_manifest(manifest)
            if not valid:
                return jsonify({"error": error_message}), 400
            if not isinstance(manifest, dict):
                return jsonify({"error": "manifest must be an object"}), 400
            _save_launcher_manifest(cast(Dict[str, Any], manifest))
            return jsonify({"status": "updated", "operation": "replace_manifest"}), 200

        if operation != 'upsert_version':
            return jsonify({"error": "Unsupported operation. Use 'upsert_version' or 'replace_manifest'"}), 400

        brand = payload.get('brand')
        version_entry = payload.get('version_entry')
        if not isinstance(brand, str) or not brand.strip():
            return jsonify({"error": "brand is required and must be a non-empty string"}), 400

        valid, error_message = _validate_launcher_version_entry(version_entry)
        if not valid:
            return jsonify({"error": error_message}), 400
        if not isinstance(version_entry, dict):
            return jsonify({"error": "version_entry must be an object"}), 400

        version_entry_dict = cast(Dict[str, Any], version_entry)
        updated_manifest, action = _upsert_launcher_win64_version(brand.strip(), version_entry_dict)
        return jsonify({
            "status": "updated",
            "operation": "upsert_version",
            "brand": brand.strip(),
            "version": version_entry_dict.get('version'),
            "action": action,
            "brands": len((updated_manifest or {}).get('brands', {}))
        }), 200
    except Exception as e:
        log_error('launcher_win64', e)
        return jsonify({"error": "Failed to load launcher-win64.json"}), 500
    
@app.route('/api/launcher-linux', methods=['GET'])
def launcher_linux():
    # Abuse flag check
    flagged, info = _is_flagged(request.remote_addr)
    if flagged:
        info = info or {}
        _record_abuse('blocked_request', request.remote_addr)
        return jsonify({"error": "Temporarily blocked due to abuse", "until": info.get('until')}), 429
    
    try:
        launcher_file = os.path.join(_json_dir, 'launcher-linux.json')
        if not os.path.exists(launcher_file):
            return jsonify({"error": "launcher-linux.json not found"}), 404

        with open(launcher_file, 'r', encoding='utf-8') as file:
            data = json.load(file)

        return jsonify(data), 200
    except Exception as e:
        log_error('launcher_linux', e)
        return jsonify({"error": "Failed to load launcher-linux.json"}), 500    

# Handle leaderboard GET and POST requests
@app.route('/api/leaderboard', methods=['GET', 'POST'])
def leaderboard():
    # Abuse flag check
    flagged, info = _is_flagged(request.remote_addr)
    if flagged:
        info = info or {}
        _record_abuse('blocked_request', request.remote_addr)
        return jsonify({"error": "Temporarily blocked due to abuse", "until": info.get('until')}), 429
    
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
            return jsonify({"error": "Internal server error"}), 500
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
            
            # VocaGuard validation (optional based on flag)
            if ENABLE_VOCAGUARD:
                # Fetch only this session (no full-table load)
                session = get_session_by_id(new_entry['session_id'])
                if not session:
                    log_rejection("VocaGuard session missing or invalid", new_entry)
                    _record_abuse('invalid_session', request.remote_addr, new_entry.get('session_id'))
                    return jsonify({"error": "VocaGuard session missing or invalid"}), 400
                
                if _is_session_expired(session):
                    log_rejection("VocaGuard session expired", new_entry)
                    _record_abuse('session_expired', request.remote_addr, new_entry.get('session_id'))
                    delete_session(new_entry['session_id'])
                    return jsonify({"error": "VocaGuard session expired"}), 400
                
                # Validate submission against session progress
                is_valid, error_message = vocaguard_validator.validate_submission(
                    session_floor=session['floor'],
                    session_level=session['level'],
                    submitted_floor=new_entry['floor'],
                    submitted_level=new_entry['level']
                )
                
                if not is_valid:
                    log_rejection("VocaGuard progress mismatch", new_entry)
                    _record_abuse('validate_mismatch', request.remote_addr, new_entry.get('session_id'),
                                 {'session_floor': session['floor'], 'session_level': session['level'],
                                  'submitted_floor': new_entry['floor'], 'submitted_level': new_entry['level']})
                    return jsonify({"error": error_message}), 400
                
                # Verify proof-of-work challenge only for sessions created via /api/start (not legacy)
                if session.get('created_via') == 'api_start':
                    challenge_id = new_entry.get('challenge_id')
                    challenge_proof = new_entry.get('challenge_proof')
                    
                    if not challenge_id or not challenge_proof:
                        log_rejection("Proof-of-work challenge or proof missing", new_entry)
                        _record_abuse('pow_missing', request.remote_addr, new_entry.get('session_id'),
                                     {'challenge_id': bool(challenge_id), 'challenge_proof': bool(challenge_proof)})
                        return jsonify({"error": "Proof-of-work challenge verification required"}), 400
                    
                    pow_valid, pow_error = vocaguard_validator.verify_challenge_proof(
                        session_id=new_entry['session_id'],
                        challenge_id=challenge_id,
                        client_proof=challenge_proof,
                        allow_legacy=ALLOW_LEGACY_POW,
                        difficulty=POW_DIFFICULTY_PREFIX_ZEROS
                    )
                    
                    if not pow_valid:
                        log_rejection("Proof-of-work verification failed", new_entry)
                        _record_abuse('pow_verification_failed', request.remote_addr, new_entry.get('session_id'),
                                     {'reason': pow_error})
                        return jsonify({"error": pow_error}), 400
                
                # Expire session after successful leaderboard submission
                delete_session(new_entry['session_id'])
            
            # Insert into SQLite and return sorted list
            entry_to_store = {k: v for k, v in new_entry.items() if k not in ('session_id', 'captcha_token', 'hcaptcha_token', 'challenge_id', 'challenge_proof')}
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
            return jsonify({"error": "Internal server error"}), 500

    return jsonify({"error": "Method not allowed"}), 405

# Get carrier pigeon inventory for session
@app.route('/api/pigeon/inventory', methods=['GET'])
def pigeon_inventory():
    session_id = request.args.get('session_id')
    if not session_id:
        return jsonify({"error": "session_id required"}), 400
    
    # Abuse flag check
    flagged, info = _is_flagged(request.remote_addr)
    if flagged:
        info = info or {}
        _record_abuse('blocked_request', request.remote_addr, session_id)
        return jsonify({"error": "Temporarily blocked due to abuse", "until": info.get('until')}), 429
    
    # Fetch only this session (no full-table load)
    session = get_session_by_id(session_id)
    if not session:
        _record_abuse('invalid_session', request.remote_addr, session_id)
        return jsonify({"error": "Invalid session"}), 400
    
    if _is_session_expired(session):
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
        info = info or {}
        _record_abuse('blocked_request', request.remote_addr, session_id)
        return jsonify({"error": "Temporarily blocked due to abuse", "until": info.get('until')}), 429
    
    # Fetch only this session (no full-table load)
    session = get_session_by_id(session_id)
    if not session:
        _record_abuse('invalid_session', request.remote_addr, session_id)
        return jsonify({"error": "Invalid session"}), 400
    
    if _is_session_expired(session):
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
        info = info or {}
        _record_abuse('blocked_request', request.remote_addr, session_id)
        return jsonify({"error": "Temporarily blocked due to abuse", "until": info.get('until')}), 429

    # CRITICAL SECTION: Hold lock for entire request to prevent race conditions
    # (inventory depletion, message limit bypass, duplicate bypass)
    with session_ops_lock:
        # Fetch only this session (no full-table load) - inside lock for freshness
        session = get_session_by_id(session_id)
        if not session:
            _record_abuse('invalid_session', request.remote_addr, session_id)
            return jsonify({"error": "Invalid session"}), 400
        
        if _is_session_expired(session):
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

        # All pigeon DB ops in one connection with try/finally to prevent leaks
        conn = get_db_connection()
        try:
            cur = conn.cursor()

            # Check message count for this session
            cur.execute('SELECT COUNT(*) FROM pigeons WHERE from_session = ? AND delivered = 0', (session_id,))
            message_count = cur.fetchone()[0]

            if message_count >= MAX_PIGEONS_PER_SESSION:
                _record_abuse('message_cap', request.remote_addr, session_id)
                return jsonify({"error": "Session pigeon message limit reached"}), 429

            # Check for duplicate (only among undelivered messages)
            cur.execute(
                'SELECT id FROM pigeons WHERE from_session = ? AND text = ? AND delivered = 0 ORDER BY created DESC LIMIT 1',
                (session_id, text)
            )
            if cur.fetchone():
                _record_abuse('duplicate', request.remote_addr, session_id)
                return jsonify({"error": "Duplicate message"}), 400

            # Decrement pigeon inventory
            new_pigeon_count = session['inv']['carrierPigeon'] - 1
            update_session(session_id, {
                'inv': {**session['inv'], 'carrierPigeon': new_pigeon_count}
            })

            # Insert pigeon message
            pigeon_id = str(uuid.uuid4())
            cur.execute(
                '''INSERT INTO pigeons (id, text, from_session, from_floor, from_level, from_verified, created, delivered, delivered_at, delivered_to)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (pigeon_id, text, session_id, int(session.get("floor", 0)), int(session.get("level", 0)),
                 1 if session.get("verified") else 0, datetime.utcnow().isoformat(), 0, None, None)
            )
            conn.commit()

            # Count pending pigeons
            cur.execute('SELECT COUNT(*) FROM pigeons WHERE delivered = 0')
            pending = cur.fetchone()[0]

            cur.execute('SELECT COUNT(*) FROM pigeons')
            total = cur.fetchone()[0]
        finally:
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
    
    # Abuse flag check
    flagged, info = _is_flagged(request.remote_addr)
    if flagged:
        info = info or {}
        _record_abuse('blocked_request', request.remote_addr, session_id)
        return jsonify({"error": "Temporarily blocked due to abuse", "until": info.get('until')}), 429
    
    # Fetch only this session (no full-table load)
    session = get_session_by_id(session_id)
    if not session:
        _record_abuse('invalid_session', request.remote_addr, session_id)
        return jsonify({"error": "Invalid session"}), 400
    
    if _is_session_expired(session):
        _record_abuse('session_expired', request.remote_addr, session_id)
        delete_session(session_id)
        return jsonify({"error": "Session expired"}), 400

    # Use optimized delivery function with targeted query
    # Retry loop: if another request claimed the pigeon between SELECT and UPDATE, try again
    delivered_msg = None
    for _attempt in range(3):
        candidate = get_pending_pigeon_for_delivery(
            session.get('floor', 0),
            session_id,
            session.get('last_from_session_delivered')
        )
        if not candidate:
            break
        # Atomically claim: returns False if another request already delivered it
        if mark_pigeon_delivered(candidate['id'], session_id):
            delivered_msg = candidate
            break
    
    if delivered_msg:
        # Update session metadata (targeted UPDATE, not full rewrite)
        update_session(session_id, {
            'last_message_received_at': datetime.utcnow().isoformat(),
            'last_from_session_delivered': delivered_msg.get('from_session')
        })
    
    # Count pigeons still available for this recipient
    pending = get_deliverable_pigeon_count(session_id)

    return jsonify({
        "delivered": bool(delivered_msg),
        "pigeon_message": delivered_msg["text"] if delivered_msg else None,
        "pigeon_id": delivered_msg["id"] if delivered_msg else None,
        "remaining_queue_pending": pending
    }), 200

# Pigeon Murder Reporting
@app.route('/api/pigeon/murder', methods=['GET', 'POST'])
@limiter.limit("30 per hour", exempt_when=lambda: request.method == 'GET')
def pigeon_murder():
    if request.method == 'GET':
        session_id = (request.args.get('session_id') or request.args.get('SID') or '').strip() or None
        totals = get_pigeon_murder_totals(session_id)

        payload: Dict[str, Any] = {
            "murder_total": totals['total_murdered'],
            "players_with_murders": totals['unique_players']
        }
        if session_id:
            payload["session_id"] = session_id
            payload["session_murder_total"] = totals['session_murdered']

        return jsonify(payload), 200

    data = request.get_json() or {}
    session_id = (data.get('session_id') or data.get('SID') or '').strip()
    pigeon_id = (data.get('pigeon_id') or '').strip() or None
    if not session_id:
        return jsonify({"error": "session_id required"}), 400

    # Abuse flag check
    flagged, info = _is_flagged(request.remote_addr)
    if flagged:
        info = info or {}
        _record_abuse('blocked_request', request.remote_addr, session_id)
        return jsonify({"error": "Temporarily blocked due to abuse", "until": info.get('until')}), 429

    # Fetch only this session (no full-table load)
    session = get_session_by_id(session_id)
    if not session:
        _record_abuse('invalid_session', request.remote_addr, session_id)
        return jsonify({"error": "Invalid session"}), 400

    if _is_session_expired(session):
        _record_abuse('session_expired', request.remote_addr, session_id)
        delete_session(session_id)
        return jsonify({"error": "Session expired"}), 400

    # Record murder event (optionally de-duplicated by pigeon_id)
    murder_result = record_pigeon_murder(session_id, pigeon_id)
    if murder_result == 'ok':
        _record_abuse('pigeon_murdered', request.remote_addr, session_id)
        totals = get_pigeon_murder_totals(session_id)
        return jsonify({
            "murdered": True,
            "session_id": session_id,
            "pigeon_id": pigeon_id,
            "murder_total": totals['total_murdered'],
            "session_murder_total": totals['session_murdered']
        }), 200
    if murder_result == 'duplicate':
        return jsonify({"murdered": False, "error": "Murder already reported for this pigeon", "pigeon_id": pigeon_id}), 409

    return jsonify({"murdered": False, "error": "Failed to record murder"}), 500

# Get abuse status (whitelisted IPs only)
@app.route('/api/abuse', methods=['GET']) # simplified abuse status endpoint
def abuse_status():
    # Whitelist-based access control
    if not _is_ip_whitelisted(request.remote_addr):
        log_error('abuse_status_unauthorized', Exception(f"Unauthorized IP access: {request.remote_addr}"))
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        # Load flagged IPs from json/flagged.json
        flagged = _load_flagged_ips()
        
        # Get aggregated counts from logs/vocaguard.log
        recent_events = _load_vocaguard_events()
        agg = {}
        for e in recent_events:
            ip = e.get('ip')
            metric = e.get('metric')
            agg.setdefault(ip, {})[metric] = agg.setdefault(ip, {}).get(metric, 0) + 1
        
        # Gather behavioral fingerprint scores for active sessions
        behavior_scores = {}
        query_session = request.args.get('session_id')
        if query_session:
            score, details = vocaguard_validator.get_behavior_score(query_session)
            behavior_scores[query_session] = {'score': score, **details}

        return jsonify({
            'flagged': flagged,
            'counts': agg,
            'window_seconds': ABUSE_EVENT_WINDOW_SECONDS,
            'vocaguard_events': recent_events,
            'behavior': behavior_scores
        })
    except Exception as e:
        log_error('abuse_status', e)
        return jsonify({"error": "Internal server error"}), 500

# --- Utility Functions ---

def verify_turnstile(token: str, remote_ip: Optional[str] = None) -> bool:
    """Verify a Cloudflare Turnstile captcha token via their API."""
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
        log_error('verify_turnstile', e)
        return False

def _extract_launcher_api_key(req) -> str:
    """
    Extract launcher manifest API key from headers.

    Supported headers:
    - X-API-Key: <key>
    - Authorization: Bearer <key>
    """
    key = (req.headers.get('X-API-Key') or '').strip()
    if key:
        return key
    auth = (req.headers.get('Authorization') or '').strip()
    if auth.lower().startswith('bearer '):
        return auth[7:].strip()
    return ""

def _launcher_manifest_path() -> str:
    return os.path.join(_json_dir, 'launcher-win64.json')

def _load_launcher_manifest() -> Optional[Dict[str, Any]]:
    """Load launcher-win64.json safely."""
    launcher_file = _launcher_manifest_path()
    if not os.path.exists(launcher_file):
        return None
    with launcher_manifest_lock:
        with open(launcher_file, 'r', encoding='utf-8') as file:
            return json.load(file)

def _save_launcher_manifest(manifest: Dict[str, Any]) -> None:
    """Save launcher-win64.json atomically to avoid partial writes."""
    launcher_file = _launcher_manifest_path()
    temp_file = f"{launcher_file}.tmp"
    with launcher_manifest_lock:
        with open(temp_file, 'w', encoding='utf-8') as file:
            json.dump(manifest, file, indent=2)
            file.write('\n')
        os.replace(temp_file, launcher_file)

def _validate_launcher_manifest(manifest: Any) -> Tuple[bool, Optional[str]]:
    """Validate minimal launcher manifest structure."""
    if not isinstance(manifest, dict):
        return False, "manifest must be an object"
    brands = manifest.get('brands')
    if not isinstance(brands, dict):
        return False, "manifest.brands must be an object"

    for brand_name, brand_data in brands.items():
        if not isinstance(brand_name, str) or not brand_name.strip():
            return False, "Each brand name must be a non-empty string"
        if not isinstance(brand_data, dict):
            return False, f"Brand '{brand_name}' must be an object"
        versions = brand_data.get('versions')
        if not isinstance(versions, list):
            return False, f"Brand '{brand_name}' must contain a versions array"
        for entry in versions:
            valid, err = _validate_launcher_version_entry(entry)
            if not valid:
                return False, f"Brand '{brand_name}' has invalid version entry: {err}"

    return True, None

def _validate_launcher_version_entry(entry: Any) -> Tuple[bool, Optional[str]]:
    """Validate a single launcher version entry payload."""
    if not isinstance(entry, dict):
        return False, "version_entry must be an object"

    required_fields = ['version', 'file_name', 'download_url', 'sha256', 'size', 'release_notes']
    for field in required_fields:
        if field not in entry:
            return False, f"version_entry is missing required field '{field}'"

    if not isinstance(entry['version'], str) or not entry['version'].strip():
        return False, "version_entry.version must be a non-empty string"
    if not isinstance(entry['file_name'], str) or not entry['file_name'].strip():
        return False, "version_entry.file_name must be a non-empty string"
    if not isinstance(entry['download_url'], str) or not re.match(r'^https?://', entry['download_url']):
        return False, "version_entry.download_url must be a valid http(s) URL"
    if not isinstance(entry['sha256'], str) or not re.fullmatch(r'[A-Fa-f0-9]{64}', entry['sha256']):
        return False, "version_entry.sha256 must be a 64-character hex string"
    if not isinstance(entry['size'], int) or entry['size'] < 0:
        return False, "version_entry.size must be a non-negative integer"
    if not isinstance(entry['release_notes'], str):
        return False, "version_entry.release_notes must be a string"

    return True, None

def _upsert_launcher_win64_version(brand: str, version_entry: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    """Insert or replace a version entry for a brand in launcher-win64 manifest."""
    launcher_file = _launcher_manifest_path()
    temp_file = f"{launcher_file}.tmp"

    with launcher_manifest_lock:
        if os.path.exists(launcher_file):
            with open(launcher_file, 'r', encoding='utf-8') as file:
                manifest = json.load(file)
        else:
            manifest = {'brands': {}}

        if 'brands' not in manifest or not isinstance(manifest['brands'], dict):
            manifest['brands'] = {}

        if brand not in manifest['brands'] or not isinstance(manifest['brands'].get(brand), dict):
            manifest['brands'][brand] = {'versions': []}

        versions = manifest['brands'][brand].get('versions')
        if not isinstance(versions, list):
            versions = []
            manifest['brands'][brand]['versions'] = versions

        action = 'created'
        target_version = version_entry.get('version')
        for idx, existing in enumerate(versions):
            if isinstance(existing, dict) and existing.get('version') == target_version:
                versions[idx] = version_entry
                action = 'updated'
                break
        else:
            versions.append(version_entry)

        with open(temp_file, 'w', encoding='utf-8') as file:
            json.dump(manifest, file, indent=2)
            file.write('\n')
        os.replace(temp_file, launcher_file)

    return manifest, action

def clean_html(val: str) -> str:
    """
    Clean HTML/script tags and dangerous content from string.
    
    Args:
        val: Input string to clean
        
    Returns:
        Cleaned string limited to MAX_LEADERBOARD_NAME_LENGTH, alphanumeric + spaces only
    """
    if isinstance(val, str):
        val = re.sub(r'<.*?>', '', val)
        val = re.sub(r'(script|meta|iframe|onerror|onload|javascript:|http-equiv|src|href|alert|document|window)', '', val, flags=re.IGNORECASE)
        val = val.strip()
        val = val[:MAX_LEADERBOARD_NAME_LENGTH]
        val = re.sub(r'[^A-Za-z0-9 ]', '', val)
        return val
    return val

def clean_json(obj: Any) -> Any:
    """
    Recursively clean JSON data structure by sanitizing 'name' fields.
    
    Args:
        obj: JSON object (dict, list, or scalar) to clean
        
    Returns:
        Cleaned JSON object with same structure
    """
    if isinstance(obj, dict):
        return {k: clean_html(v) if k == 'name' else clean_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [clean_json(item) for item in obj]
    else:
        return obj

def log_rejection(reason: str, data: Optional[Dict]) -> None:
    """Log a leaderboard submission rejection to vocaguard.log."""
    try:
        now_ts = int(datetime.utcnow().timestamp())
        event: Dict[str, Any] = {
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
        log_vocaguard_event(event)
    except Exception as e:
        # Fail open; rejection logging failure should not block main flow
        pass

def _ensure_inventory(session: dict) -> dict:
    """Ensure a session dict has the expected inventory structure."""
    if 'inv' not in session or not isinstance(session['inv'], dict):
        session['inv'] = {}
    if 'carrierPigeon' not in session['inv']:
        session['inv']['carrierPigeon'] = 0
    return session

def _sender_progress_for_msg(msg: dict) -> Tuple[int, int, bool]:
    """Return (floor, level, verified) from a pigeon message's captured fields."""
    from_floor = int(msg.get("from_floor") or 0)
    from_level = int(msg.get("from_level") or 0)
    from_verified = bool(msg.get("from_verified", False))
    return from_floor, from_level, from_verified

def _closeness_weight(sender_floor: int, recipient_floor: int) -> float:
    """Compute a 0–1 closeness factor based on floor proximity."""
    delta = abs(sender_floor - recipient_floor)
    if delta > FLOOR_PROXIMITY_RANGE:
        return 0.0
    return max(0.0, 1.0 - (delta / (FLOOR_PROXIMITY_RANGE + 1)))

def _age_boost(created_iso: str) -> float:
    """Compute an age-based delivery priority boost (0 to AGE_BOOST_MAX)."""
    try:
        created_dt = datetime.fromisoformat(created_iso)
    except Exception:
        return 0.0
    age = (datetime.utcnow() - created_dt).total_seconds()
    if age <= 0:
        return 0.0
    return min(AGE_BOOST_MAX, AGE_BOOST_MAX * (age / AGE_BOOST_FULL_SECONDS))

def _message_weight(msg: dict, recipient_session: dict) -> float:
    """Compute a delivery priority weight for a pigeon message."""
    sender_floor, sender_level, sender_verified = _sender_progress_for_msg(msg)
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

def purge_old_sessions():
    """Delete sessions older than SESSION_PURGE_AGE_DAYS from the database."""
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
    """Background thread that periodically purges old sessions and expired PoW challenges."""
    while True:
        try:
            purge_old_sessions()
            # Also clean up expired proof-of-work challenges
            if ENABLE_VOCAGUARD:
                expired_count = vocaguard_validator.cleanup_expired_challenges()
                if expired_count > 0:
                    error_logger.info(
                        '%s|session_purge_worker|INFO|pow_challenge_cleanup expired_count=%d',
                        datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                        expired_count
                    )
        except Exception as e:
            log_error('session_purge_worker', e)
        time.sleep(BACKGROUND_WORKER_SLEEP_SECONDS)

# Start the purge thread when the app starts
purge_thread = threading.Thread(target=session_purge_worker, daemon=True)
purge_thread.start()

# Main entry point
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=9601)