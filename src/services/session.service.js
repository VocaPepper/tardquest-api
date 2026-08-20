const crypto = require('node:crypto');
const repo = require('../db/sqlite.repository');
const config = require('../config');
const logger = require('../utils/logger');

function createApiSession(username, clientVersion) {
  const sessionId = crypto.randomUUID();
  const expires = new Date(Date.now() + config.sessionTimeoutMinutes * 60000).toISOString();
  const session = {
    session_id: sessionId,
    floor: 1,
    level: 1,
    exp: 0,
    expires,
    created: new Date().toISOString(),
    inv: { carrierPigeon: 0 },
    last_floor_update: null,
    last_message_received_at: null,
    last_from_session_delivered: null,
    verified: false,
    created_via: username ? 'auth_login' : 'api_start',
    username: username || null,
    // Authenticated sessions default to the current API version so they remain leaderboard-eligible.
    client_version: clientVersion || config.apiVersion,
  };
  const saved = repo.saveSession(sessionId, session);
  if (!saved) {
    throw new Error('Failed to persist session to database');
  }
  return session;
}

function linkAuthSession(authSessionId) {
  if (!authSessionId) return null;
  const authSession = repo.getSessionById(authSessionId);
  if (!authSession) return null;
  try {
    if (new Date(authSession.expires) < new Date()) return null;
  } catch (e) { return null; }
  return authSession.username || null;
}

module.exports = { createApiSession, linkAuthSession };
