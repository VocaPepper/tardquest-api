const repo = require('../db/sqlite.repository');
const logger = require('../utils/logger');

function isSessionExpired(session) {
  try {
    return new Date(session.expires) < new Date();
  } catch (e) {
    return true;
  }
}

function sessionAuth(options = {}) {
  const { requireAuth = false } = options;

  return (req, res, next) => {
    let sessionId = (req.headers['x-session-id'] || '').trim();
    if (!sessionId && req.body && req.body.session_id) {
      sessionId = (req.body.session_id || '').trim();
    }

    if (!sessionId) {
      return res.status(400).json({ error: 'session_id required' });
    }

    const session = repo.getSessionById(sessionId);
    if (!session) {
      logger.logError('sessionAuth', new Error('Invalid session'), { sessionId });
      return res.status(400).json({ error: 'Invalid session' });
    }

    if (isSessionExpired(session)) {
      repo.deleteSession(sessionId);
      return res.status(400).json({ error: 'Session expired' });
    }

    req.session = session;
    req.sessionId = sessionId;
    next();
  };
}

module.exports = { sessionAuth, isSessionExpired };
