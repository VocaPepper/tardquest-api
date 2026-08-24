/**
 * Migration script: legacy Python SQLite → Node.js SQLite
 *
 * Usage:
 *   node migrate-legacy-db.js <legacy.db> <node.db>
 *
 * Example:
 *   node migrate-legacy-db.js ../legacy/tardquest.db ./data/tardquest.db
 *
 * What it handles:
 * - Legacy sessions table has a `bound_ip` column (Node ignores it)
 * - Legacy sessions table may be missing the `username` column (Node requires it)
 * - Column order differs between schemas
 * - Node schema adds DEFAULT values for several columns
 */
const path = require('node:path');
const Database = require('better-sqlite3');
const fs = require('node:fs');

const legacyPath = path.resolve(process.argv[2] || '../legacy/tardquest.db');
const nodePath = path.resolve(process.argv[3] || './data/tardquest.db');

if (!fs.existsSync(legacyPath)) {
  console.error(`Legacy DB not found: ${legacyPath}`);
  process.exit(1);
}

console.log('Legacy DB:', legacyPath);
console.log('Node DB:', nodePath);

const legacy = new Database(legacyPath, { readonly: true });
const node = new Database(nodePath, { timeout: 30000 });

node.pragma('journal_mode = WAL');
node.pragma('synchronous = NORMAL');
node.pragma('foreign_keys = ON');

// Keep the schema aligned with src/db/connection.js.
node.exec(`
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

const legacySessionCols = legacy.prepare('PRAGMA table_info(sessions)').all();
const legacyColNames = legacySessionCols.map(c => c.name);
console.log('Legacy sessions columns:', legacyColNames.join(', '));

const hasUsername = legacyColNames.includes('username');
const hasBoundIp = legacyColNames.includes('bound_ip');

// Missing legacy tables are skipped.
function getLegacyRows(table, sql) {
  try {
    return legacy.prepare(sql || `SELECT * FROM ${table}`).all();
  } catch (e) {
    console.log(`  Table "${table}" not found in legacy DB, skipping`);
    return null;
  }
}

const leaderboardRows = getLegacyRows('leaderboard', 'SELECT name, floor, level FROM leaderboard ORDER BY id');
if (leaderboardRows && leaderboardRows.length > 0) {
  const mergedLeaderboard = new Map();
  for (const row of leaderboardRows) {
    const nameKey = String(row.name).toUpperCase();
    const current = mergedLeaderboard.get(nameKey);
    if (!current || Number(row.floor) > Number(current.floor) ||
        (Number(row.floor) === Number(current.floor) && Number(row.level) > Number(current.level))) {
      mergedLeaderboard.set(nameKey, row);
    }
  }
  const mergedLeaderboardRows = [...mergedLeaderboard.values()];

  node.prepare('DELETE FROM leaderboard').run();
  const insertLB = node.prepare('INSERT INTO leaderboard (name, floor, level) VALUES (?, ?, ?)');
  const txLB = node.transaction(() => {
    for (const r of mergedLeaderboardRows) insertLB.run(r.name, r.floor, r.level);
  });
  txLB();
  console.log(`Migrated ${mergedLeaderboardRows.length} leaderboard entries` +
    (mergedLeaderboardRows.length < leaderboardRows.length
      ? ` (merged ${leaderboardRows.length - mergedLeaderboardRows.length} duplicates)`
      : ''));
} else {
  console.log('Leaderboard: empty');
}

const sessionRows = getLegacyRows('sessions', hasUsername
  ? `SELECT session_id, floor, level, COALESCE(exp, 0) AS exp,
            expires, created, inv,
            last_level_update, last_floor_update,
            last_message_received_at, last_from_session_delivered,
            COALESCE(verified, 0) AS verified,
            COALESCE(created_via, 'api_start') AS created_via,
            COALESCE(username, '') AS username
     FROM sessions`
  : `SELECT session_id, floor, level, COALESCE(exp, 0) AS exp,
            expires, created, inv,
            last_level_update, last_floor_update,
            last_message_received_at, last_from_session_delivered,
            COALESCE(verified, 0) AS verified,
            COALESCE(created_via, 'api_start') AS created_via,
            NULL AS username
     FROM sessions`
);

if (sessionRows && sessionRows.length > 0) {
  node.prepare('DELETE FROM sessions').run();
  const insertSess = node.prepare(`
    INSERT INTO sessions (session_id, floor, level, exp, expires, created, inv,
                          last_level_update, last_floor_update, last_message_received_at,
                          last_from_session_delivered, verified, created_via, username)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const txSess = node.transaction(() => {
    for (const r of sessionRows) {
      try {
        insertSess.run(
          r.session_id, r.floor, r.level, r.exp,
          r.expires, r.created,
          typeof r.inv === 'string' ? r.inv : JSON.stringify(r.inv || {}),
          r.last_level_update || null, r.last_floor_update || null,
          r.last_message_received_at || null, r.last_from_session_delivered || null,
          r.verified ? 1 : 0, r.created_via || 'api_start', r.username || null
        );
      } catch (e) {
        console.error(`  Skipping session ${r.session_id}: ${e.message}`);
      }
    }
  });
  txSess();
  console.log(`Migrated ${sessionRows.length} sessions`);
} else {
  console.log('Sessions: empty');
}

const pigeonRows = getLegacyRows('pigeons');
if (pigeonRows && pigeonRows.length > 0) {
  node.prepare('DELETE FROM pigeons').run();
  const insertPig = node.prepare(`
    INSERT INTO pigeons (id, text, from_session, from_floor, from_level, from_verified,
                         created, delivered, delivered_at, delivered_to)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const txPig = node.transaction(() => {
    for (const r of pigeonRows) {
      insertPig.run(r.id, r.text, r.from_session, r.from_floor, r.from_level,
                    r.from_verified ? 1 : 0, r.created,
                    r.delivered ? 1 : 0, r.delivered_at || null, r.delivered_to || null);
    }
  });
  txPig();
  console.log(`Migrated ${pigeonRows.length} pigeon messages`);
} else {
  console.log('Pigeons: empty');
}

const murderRows = getLegacyRows('pigeon_murders');
if (murderRows && murderRows.length > 0) {
  node.prepare('DELETE FROM pigeon_murders').run();
  const insertMur = node.prepare(`
    INSERT INTO pigeon_murders (session_id, pigeon_id, murdered_at)
    VALUES (?, ?, ?)
  `);
  const txMur = node.transaction(() => {
    for (const r of murderRows) {
      insertMur.run(r.session_id, r.pigeon_id || null, r.murdered_at);
    }
  });
  txMur();
  console.log(`Migrated ${murderRows.length} pigeon murders`);
} else {
  console.log('Pigeon murders: empty');
}

const onlineRows = getLegacyRows('online_sessions');
if (onlineRows && onlineRows.length > 0) {
  node.prepare('DELETE FROM online_sessions').run();
  const insertOn = node.prepare(`
    INSERT INTO online_sessions (token_hash, username, created, expires, last_verified, source_ip)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  const txOn = node.transaction(() => {
    for (const r of onlineRows) {
      insertOn.run(r.token_hash, r.username, r.created, r.expires,
                   r.last_verified || null, r.source_ip || null);
    }
  });
  txOn();
  console.log(`Migrated ${onlineRows.length} online sessions`);
} else {
  console.log('Online sessions: empty');
}

legacy.close();
node.close();
console.log('\nMigration complete.');
