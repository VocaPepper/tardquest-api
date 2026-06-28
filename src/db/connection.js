const path = require('node:path');
const Database = require('better-sqlite3');
const config = require('../config');

const dbDir = path.dirname(config.sqliteDbPath);
const fs = require('node:fs');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

let db = null;

function getDbConnection() {
  if (db) return db;
  db = new Database(config.sqliteDbPath, {
    timeout: config.dbConnectionTimeoutSeconds * 1000,
  });
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('foreign_keys = ON');
  initDb(db);
  return db;
}

function initDb(database) {
  database.exec(`
    CREATE TABLE IF NOT EXISTS leaderboard (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      floor INTEGER NOT NULL,
      level INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      floor INTEGER NOT NULL DEFAULT 1,
      level INTEGER NOT NULL DEFAULT 1,
      exp INTEGER DEFAULT 0,
      expires TEXT NOT NULL,
      created TEXT NOT NULL,
      inv TEXT NOT NULL DEFAULT '{}',
      last_level_update TEXT,
      last_floor_update TEXT,
      last_message_received_at TEXT,
      last_from_session_delivered TEXT,
      verified INTEGER DEFAULT 0,
      created_via TEXT DEFAULT 'api_start',
      username TEXT DEFAULT NULL
    );

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
    );

    CREATE TABLE IF NOT EXISTS pigeon_murders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      pigeon_id TEXT,
      murdered_at TEXT NOT NULL,
      UNIQUE(session_id, pigeon_id)
    );

    CREATE TABLE IF NOT EXISTS online_sessions (
      token_hash TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      created TEXT NOT NULL,
      expires TEXT NOT NULL,
      last_verified TEXT,
      source_ip TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_online_sessions_username ON online_sessions (username);
    CREATE INDEX IF NOT EXISTS idx_online_sessions_expires ON online_sessions (expires);
    CREATE INDEX IF NOT EXISTS idx_pigeons_undelivered ON pigeons (delivered, from_session);
  `);
}

function closeDb() {
  if (db) {
    db.close();
    db = null;
  }
}

module.exports = { getDbConnection, closeDb, initDb };
