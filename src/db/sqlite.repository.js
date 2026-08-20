const { getDbConnection } = require('./connection');
const config = require('../config');
const logger = require('../utils/logger');

function saveSession(sessionId, session) {
  try {
    const db = getDbConnection();
    const stmt = db.prepare(`
      INSERT OR REPLACE INTO sessions
        (session_id, floor, level, exp, expires, created, inv, last_level_update, last_floor_update, last_message_received_at, last_from_session_delivered, verified, created_via, username, client_version, died_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      sessionId,
      session.floor || 1,
      session.level || 1,
      session.exp || 0,
      session.expires || '',
      session.created || '',
      JSON.stringify(session.inv || {}),
      session.last_level_update || null,
      session.last_floor_update || null,
      session.last_message_received_at || null,
      session.last_from_session_delivered || null,
      session.verified ? 1 : 0,
      session.created_via || 'api_start',
      session.username || null,
      session.client_version || null,
      session.died_at || null,
    );
    return true;
  } catch (e) {
    logger.logError('saveSession', e, { sessionId });
    console.error('saveSession FAILED:', e.message);
    return false;
  }
}

function getSessionById(sessionId) {
  try {
    const db = getDbConnection();
    const row = db.prepare(`
      SELECT session_id, floor, level, exp, expires, created, inv,
             last_level_update, last_floor_update, last_message_received_at,
             last_from_session_delivered, verified, created_via, username, client_version, died_at
      FROM sessions WHERE session_id = ?
    `).get(sessionId);
    if (!row) return null;
    return {
      session_id: row.session_id,
      floor: row.floor,
      level: row.level,
      exp: row.exp,
      expires: row.expires,
      created: row.created,
      inv: safeJsonParse(row.inv, {}),
      last_level_update: row.last_level_update,
      last_floor_update: row.last_floor_update,
      last_message_received_at: row.last_message_received_at,
      last_from_session_delivered: row.last_from_session_delivered,
      verified: !!row.verified,
      created_via: row.created_via || 'api_start',
      username: row.username || null,
      client_version: row.client_version || null,
      died_at: row.died_at || null,
    };
  } catch (e) {
    logger.logError('getSessionById', e, { sessionId });
    return null;
  }
}

function updateSession(sessionId, updates) {
  try {
    const db = getDbConnection();
    const setClauses = [];
    const params = [];

    if (updates.floor !== undefined) { setClauses.push('floor = ?'); params.push(updates.floor); }
    if (updates.level !== undefined) { setClauses.push('level = ?'); params.push(updates.level); }
    if (updates.exp !== undefined) { setClauses.push('exp = ?'); params.push(updates.exp); }
    if (updates.expires !== undefined) { setClauses.push('expires = ?'); params.push(updates.expires); }
    if (updates.inv !== undefined) { setClauses.push('inv = ?'); params.push(JSON.stringify(updates.inv)); }
    if (updates.last_level_update !== undefined) { setClauses.push('last_level_update = ?'); params.push(updates.last_level_update); }
    if (updates.last_floor_update !== undefined) { setClauses.push('last_floor_update = ?'); params.push(updates.last_floor_update); }
    if (updates.last_message_received_at !== undefined) { setClauses.push('last_message_received_at = ?'); params.push(updates.last_message_received_at); }
    if (updates.last_from_session_delivered !== undefined) { setClauses.push('last_from_session_delivered = ?'); params.push(updates.last_from_session_delivered); }
    if (updates.verified !== undefined) { setClauses.push('verified = ?'); params.push(updates.verified ? 1 : 0); }
    if (updates.username !== undefined) { setClauses.push('username = ?'); params.push(updates.username); }
    if (updates.client_version !== undefined) { setClauses.push('client_version = ?'); params.push(updates.client_version); }
    if (updates.died_at !== undefined) { setClauses.push('died_at = ?'); params.push(updates.died_at); }

    if (setClauses.length === 0) return true;
    params.push(sessionId);
    const result = db.prepare(`UPDATE sessions SET ${setClauses.join(', ')} WHERE session_id = ?`).run(...params);
    return result.changes > 0;
  } catch (e) {
    logger.logError('updateSession', e, { sessionId, updates: Object.keys(updates) });
    return false;
  }
}

function deleteSession(sessionId) {
  try {
    const db = getDbConnection();
    db.prepare('DELETE FROM sessions WHERE session_id = ?').run(sessionId);
    return true;
  } catch (e) {
    logger.logError('deleteSession', e, { sessionId });
    return false;
  }
}

function deleteSessionsByUsername(username) {
  if (!username) return 0;
  try {
    const db = getDbConnection();
    const result = db.prepare("DELETE FROM sessions WHERE LOWER(COALESCE(username, '')) = LOWER(?)").run(username);
    return result.changes;
  } catch (e) {
    logger.logError('deleteSessionsByUsername', e, { username });
    return 0;
  }
}

function purgeOldSessions() {
  try {
    const cutoff = new Date(Date.now() - config.sessionPurgeAgeDays * 86400000).toISOString();
    const db = getDbConnection();
    const result = db.prepare('DELETE FROM sessions WHERE created < ?').run(cutoff);
    if (result.changes > 0) {
      console.log(`Purged ${result.changes} old sessions`);
    }
    return result.changes;
  } catch (e) {
    logger.logError('purgeOldSessions', e);
    return 0;
  }
}

function getLeaderboard() {
  try {
    const db = getDbConnection();
    return db.prepare('SELECT name, floor, level FROM leaderboard ORDER BY floor DESC, level DESC').all();
  } catch (e) {
    logger.logError('getLeaderboard', e);
    return [];
  }
}

function submitLeaderboardEntry(name, floor, level) {
  try {
    const db = getDbConnection();

    const safeName = (name || '').slice(0, 256);

    const existing = db.prepare(
      'SELECT id, floor, level FROM leaderboard WHERE UPPER(name) = UPPER(?) ORDER BY id ASC'
    ).all(safeName);

    if (existing.length > 0) {
      const keepId = existing[0].id;
      let bestFloor = floor;
      let bestLevel = level;
      for (const row of existing) {
        if (row.floor > bestFloor || (row.floor === bestFloor && row.level > bestLevel)) {
          bestFloor = row.floor;
          bestLevel = row.level;
        }
      }
      db.prepare('UPDATE leaderboard SET name = ?, floor = ?, level = ? WHERE id = ?').run(safeName, bestFloor, bestLevel, keepId);
      const idsToRemove = existing.slice(1).map(r => r.id);
      for (const id of idsToRemove) {
        db.prepare('DELETE FROM leaderboard WHERE id = ?').run(id);
      }
    } else {
      db.prepare('INSERT INTO leaderboard (name, floor, level) VALUES (?, ?, ?)').run(safeName, floor, level);
    }
    return getLeaderboard();
  } catch (e) {
    logger.logError('submitLeaderboardEntry', e, { name, floor, level });
    return null;
  }
}

function deleteLeaderboardEntryByName(name) {
  try {
    const db = getDbConnection();
    const result = db.prepare('DELETE FROM leaderboard WHERE UPPER(name) = UPPER(?)').run(name);
    return result.changes > 0;
  } catch (e) {
    logger.logError('deleteLeaderboardEntryByName', e, { name });
    return false;
  }
}

function getPendingPigeonForDelivery(recipientFloor, recipientSessionId, excludeRecentSender) {
  try {
    const db = getDbConnection();
    const rows = db.prepare(
      'SELECT id, text, from_session, from_floor, from_level, from_verified, created, delivered, delivered_at, delivered_to FROM pigeons WHERE delivered = 0 AND from_session != ? LIMIT 100'
    ).all(recipientSessionId);

    if (rows.length === 0) return null;

    const candidates = rows.map(r => ({
      id: r.id,
      text: r.text,
      from_session: r.from_session,
      from_floor: r.from_floor,
      from_level: r.from_level,
      from_verified: !!r.from_verified,
      created: r.created,
      delivered: !!r.delivered,
      delivered_at: r.delivered_at,
      delivered_to: r.delivered_to,
    }));

    const recipientCtx = { floor: recipientFloor, last_from_session_delivered: excludeRecentSender };
    const weights = candidates.map(p => messageWeight(p, recipientCtx));
    const totalWeight = weights.reduce((s, w) => s + w, 0);
    if (totalWeight <= 0) return candidates[0] || null;

    let r = Math.random() * totalWeight;
    for (let i = 0; i < candidates.length; i++) {
      r -= weights[i];
      if (r <= 0) return candidates[i];
    }
    return candidates[candidates.length - 1];
  } catch (e) {
    logger.logError('getPendingPigeonForDelivery', e);
    return null;
  }
}

function markPigeonDelivered(pigeonId, deliveredToSession) {
  try {
    const db = getDbConnection();
    const result = db.prepare(
      "UPDATE pigeons SET delivered = 1, delivered_at = ?, delivered_to = ? WHERE id = ? AND delivered = 0"
    ).run(new Date().toISOString(), deliveredToSession, pigeonId);
    return result.changes > 0;
  } catch (e) {
    logger.logError('markPigeonDelivered', e, { pigeonId });
    return false;
  }
}

function claimPigeonAtomically(recipientFloor, recipientSessionId, excludeRecentSender) {
  try {
    const db = getDbConnection();
    const claim = db.transaction(() => {
      const rows = db.prepare(
        'SELECT id, text, from_session, from_floor, from_level, from_verified, created FROM pigeons WHERE delivered = 0 AND from_session != ? LIMIT 100'
      ).all(recipientSessionId);

      if (rows.length === 0) return null;

      const candidates = rows.map(r => ({
        id: r.id,
        text: r.text,
        from_session: r.from_session,
        from_floor: r.from_floor,
        from_level: r.from_level,
        from_verified: !!r.from_verified,
        created: r.created,
      }));

      const recipientCtx = { floor: recipientFloor, last_from_session_delivered: excludeRecentSender };
      const weights = candidates.map(p => messageWeight(p, recipientCtx));
      const totalWeight = weights.reduce((s, w) => s + w, 0);

      let chosen;
      if (totalWeight <= 0) {
        chosen = candidates[0];
      } else {
        let r = Math.random() * totalWeight;
        for (let i = 0; i < candidates.length; i++) {
          r -= weights[i];
          if (r <= 0) { chosen = candidates[i]; break; }
        }
        if (!chosen) chosen = candidates[candidates.length - 1];
      }

      const result = db.prepare(
        "UPDATE pigeons SET delivered = 1, delivered_at = ?, delivered_to = ? WHERE id = ? AND delivered = 0"
      ).run(new Date().toISOString(), recipientSessionId, chosen.id);

      if (result.changes === 0) return null;
      return chosen;
    });

    return claim();
  } catch (e) {
    logger.logError('claimPigeonAtomically', e);
    return null;
  }
}

function getPendingPigeonCount(sessionId) {
  try {
    const db = getDbConnection();
    const row = db.prepare('SELECT COUNT(*) AS cnt FROM pigeons WHERE from_session = ? AND delivered = 0').get(sessionId);
    return row.cnt;
  } catch (e) {
    logger.logError('getPendingPigeonCount', e, { sessionId });
    return 0;
  }
}

function getDeliverablePigeonCount(sessionId) {
  try {
    const db = getDbConnection();
    const row = db.prepare('SELECT COUNT(*) AS cnt FROM pigeons WHERE delivered = 0 AND from_session != ?').get(sessionId);
    return row.cnt;
  } catch (e) {
    logger.logError('getDeliverablePigeonCount', e, { sessionId });
    return 0;
  }
}

function insertPigeon(pigeon) {
  try {
    const db = getDbConnection();
    db.prepare(`
      INSERT INTO pigeons (id, text, from_session, from_floor, from_level, from_verified, created, delivered, delivered_at, delivered_to)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      pigeon.id, pigeon.text, pigeon.from_session, pigeon.from_floor, pigeon.from_level,
      pigeon.from_verified ? 1 : 0, pigeon.created, 0, null, null
    );
  } catch (e) {
    logger.logError('insertPigeon', e, { pigeonId: pigeon.id });
  }
}

function storePigeon(pigeon) {
  try {
    const db = getDbConnection();
    return db.transaction(() => {
      const session = db.prepare('SELECT inv FROM sessions WHERE session_id = ?').get(pigeon.from_session);
      if (!session) return { error: 'Invalid session' };

      const inventory = safeJsonParse(session.inv, {});
      const carrierPigeons = Number(inventory.carrierPigeon);
      if (!Number.isFinite(carrierPigeons) || carrierPigeons <= 0) {
        return { error: 'No carrier pigeon in inventory' };
      }

      const pending = db.prepare(
        'SELECT COUNT(*) AS cnt FROM pigeons WHERE from_session = ? AND delivered = 0'
      ).get(pigeon.from_session).cnt;
      if (pending >= config.maxPigeonsPerSession) {
        return { error: 'Session pigeon message limit reached' };
      }

      const duplicate = db.prepare(
        'SELECT id FROM pigeons WHERE from_session = ? AND text = ? AND delivered = 0 LIMIT 1'
      ).get(pigeon.from_session, pigeon.text);
      if (duplicate) return { error: 'Duplicate message' };

      const newCount = carrierPigeons - 1;
      const updated = db.prepare('UPDATE sessions SET inv = ? WHERE session_id = ?').run(
        JSON.stringify({ ...inventory, carrierPigeon: newCount }),
        pigeon.from_session,
      );
      if (updated.changes === 0) return { error: 'Internal server error', internal: true };

      db.prepare(`
        INSERT INTO pigeons (id, text, from_session, from_floor, from_level, from_verified, created, delivered, delivered_at, delivered_to)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        pigeon.id, pigeon.text, pigeon.from_session, pigeon.from_floor, pigeon.from_level,
        pigeon.from_verified ? 1 : 0, pigeon.created, 0, null, null,
      );

      const queueLengthPending = db.prepare(
        'SELECT COUNT(*) AS cnt FROM pigeons WHERE from_session = ? AND delivered = 0'
      ).get(pigeon.from_session).cnt;
      const queueLengthTotal = db.prepare('SELECT COUNT(*) AS cnt FROM pigeons').get().cnt;

      return {
        stored: true,
        queue_length_pending: queueLengthPending,
        queue_length_total: queueLengthTotal,
        sanitized_text: pigeon.text,
        carrierPigeon_remaining: newCount,
      };
    })();
  } catch (e) {
    logger.logError('storePigeon', e, { pigeonId: pigeon.id });
    return { error: 'Internal server error', internal: true };
  }
}

function checkDuplicatePigeonMessage(sessionId, text) {
  try {
    const db = getDbConnection();
    const row = db.prepare(
      "SELECT id FROM pigeons WHERE from_session = ? AND text = ? AND delivered = 0 ORDER BY created DESC LIMIT 1"
    ).get(sessionId, text);
    return !!row;
  } catch (e) {
    logger.logError('checkDuplicatePigeonMessage', e);
    return false;
  }
}

function countTotalPigeons() {
  try {
    const db = getDbConnection();
    return db.prepare('SELECT COUNT(*) AS cnt FROM pigeons').get().cnt;
  } catch (e) {
    logger.logError('countTotalPigeons', e);
    return 0;
  }
}

function recordPigeonMurder(sessionId, pigeonId) {
  try {
    const db = getDbConnection();
    const result = db.prepare(
      'INSERT OR IGNORE INTO pigeon_murders (session_id, pigeon_id, murdered_at) VALUES (?, ?, ?)'
    ).run(
      sessionId, pigeonId || null, new Date().toISOString()
    );
    if (result.changes === 0) return 'duplicate';
    return 'ok';
  } catch (e) {
    logger.logError('recordPigeonMurder', e, { sessionId, pigeonId });
    return 'error';
  }
}

function getPigeonMurderTotals(sessionId) {
  try {
    const db = getDbConnection();
    const total = db.prepare('SELECT COUNT(*) AS cnt FROM pigeon_murders').get().cnt;
    const uniquePlayers = db.prepare('SELECT COUNT(DISTINCT session_id) AS cnt FROM pigeon_murders').get().cnt;
    let sessionTotal = 0;
    if (sessionId) {
      sessionTotal = db.prepare('SELECT COUNT(*) AS cnt FROM pigeon_murders WHERE session_id = ?').get(sessionId).cnt;
    }
    return { total_murdered: total, unique_players: uniquePlayers, session_murdered: sessionTotal };
  } catch (e) {
    logger.logError('getPigeonMurderTotals', e, { sessionId });
    return { total_murdered: 0, unique_players: 0, session_murdered: 0 };
  }
}

function createOnlineAuthSession(username, sourceIp, token, expiresIso, nowIso) {
  try {
    const db = getDbConnection();
    db.prepare('DELETE FROM online_sessions WHERE expires < ?').run(nowIso);
    const tokenHash = hashOnlineToken(token);
    db.prepare(`
      INSERT INTO online_sessions (token_hash, username, created, expires, last_verified, source_ip)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(tokenHash, username, nowIso, expiresIso, nowIso, sourceIp || null);
    return { token, username, expiresAt: expiresIso };
  } catch (e) {
    logger.logError('createOnlineAuthSession', e, { username });
    return null;
  }
}

function verifyOnlineAuthToken(token) {
  if (!token) return { valid: false, error: 'Missing authorization token' };
  try {
    const db = getDbConnection();
    const tokenHash = hashOnlineToken(token);
    const nowIso = new Date().toISOString();
    const row = db.prepare('SELECT username, expires FROM online_sessions WHERE token_hash = ? LIMIT 1').get(tokenHash);
    if (!row) return { valid: false, error: 'Invalid or expired token' };
    if (new Date(row.expires) < new Date()) {
      db.prepare('DELETE FROM online_sessions WHERE token_hash = ?').run(tokenHash);
      return { valid: false, error: 'Invalid or expired token' };
    }
    db.prepare('UPDATE online_sessions SET last_verified = ? WHERE token_hash = ?').run(nowIso, tokenHash);
    return { valid: true, error: null, username: row.username, expiresAt: row.expires };
  } catch (e) {
    logger.logError('verifyOnlineAuthToken', e);
    return { valid: false, error: 'Online auth service unavailable' };
  }
}

function safeJsonParse(str, fallback) {
  try { return JSON.parse(str); } catch (e) { return fallback; }
}

function hashOnlineToken(token) {
  const crypto = require('node:crypto');
  return crypto.createHash('sha256').update(token).digest('hex');
}

function messageWeight(msg, recipientSession) {
  const delta = Math.abs(msg.from_floor - (recipientSession.floor || 0));
  let weight = 1.0;
  if (delta <= config.floorProximityRange) {
    weight *= (1.0 + 0.5 * Math.max(0, 1.0 - (delta / (config.floorProximityRange + 1))));
  }
  weight *= (1.0 + config.priorityHighFloorWeight * Math.max(0, msg.from_floor));
  if (msg.from_verified) weight *= config.priorityVerifiedMultiplier;
  weight *= (1.0 + ageBoost(msg.created));
  if (recipientSession.last_from_session_delivered && recipientSession.last_from_session_delivered === msg.from_session) {
    weight *= config.repeatSenderPenalty;
  }
  weight *= (config.randomJitterMin + Math.random() * (config.randomJitterMax - config.randomJitterMin));
  return Math.max(weight, 0);
}

function ageBoost(createdIso) {
  try {
    const age = (Date.now() - new Date(createdIso).getTime()) / 1000;
    if (age <= 0) return 0;
    return Math.min(config.ageBoostMax, config.ageBoostMax * (age / config.ageBoostFullSeconds));
  } catch (e) {
    return 0;
  }
}

module.exports = {
  saveSession,
  getSessionById,
  updateSession,
  deleteSession,
  deleteSessionsByUsername,
  purgeOldSessions,
  getLeaderboard,
  submitLeaderboardEntry,
  deleteLeaderboardEntryByName,
  getPendingPigeonForDelivery,
  markPigeonDelivered,
  claimPigeonAtomically,
  getPendingPigeonCount,
  getDeliverablePigeonCount,
  insertPigeon,
  storePigeon,
  checkDuplicatePigeonMessage,
  countTotalPigeons,
  recordPigeonMurder,
  getPigeonMurderTotals,
  createOnlineAuthSession,
  verifyOnlineAuthToken,
};
