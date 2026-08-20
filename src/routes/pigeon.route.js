const repo = require('../db/sqlite.repository');
const abuse = require('../services/abuse.service');
const pigeonService = require('../services/pigeon.service');
const config = require('../config');
const { limiter } = require('../middleware/rateLimiter');
const logger = require('../utils/logger');

function register(app) {
  app.get('/pigeon/inventory', (req, res) => {
    const sessionId = (req.headers['x-session-id'] || '').trim();
    if (!sessionId) return res.status(400).json({ error: 'session_id required' });

    const { flagged, info } = abuse.isFlagged(req.ip);
    if (flagged) {
      return res.status(429).json({ error: 'Temporarily blocked due to abuse', until: (info || {}).until });
    }

    const session = repo.getSessionById(sessionId);
    if (!session) {
      abuse.recordAbuse('invalid_session', req.ip, sessionId);
      return res.status(400).json({ error: 'Invalid session' });
    }
    try {
      if (new Date(session.expires) < new Date()) {
        abuse.recordAbuse('session_expired', req.ip, sessionId);
        repo.deleteSession(sessionId);
        return res.status(400).json({ error: 'Session expired' });
      }
    } catch (e) {
      return res.status(400).json({ error: 'Session expired' });
    }

    pigeonService.ensureInventory(session);
    res.json({ carrierPigeon: session.inv.carrierPigeon });
  });

  app.post('/pigeon/purchase', limiter({ windowMs: 3600000, max: 20 }), (req, res) => {
    const sessionId = ((req.body || {}).session_id || '').trim();
    if (!sessionId) return res.status(400).json({ error: 'session_id required' });

    const { flagged, info } = abuse.isFlagged(req.ip);
    if (flagged) {
      return res.status(429).json({ error: 'Temporarily blocked due to abuse', until: (info || {}).until });
    }

    const session = repo.getSessionById(sessionId);
    if (!session) {
      abuse.recordAbuse('invalid_session', req.ip, sessionId);
      return res.status(400).json({ error: 'Invalid session' });
    }
    try {
      if (new Date(session.expires) < new Date()) {
        abuse.recordAbuse('session_expired', req.ip, sessionId);
        repo.deleteSession(sessionId);
        return res.status(400).json({ error: 'Session expired' });
      }
    } catch (e) {
      return res.status(400).json({ error: 'Session expired' });
    }

    pigeonService.ensureInventory(session);
    const cur = session.inv.carrierPigeon;
    const maxPigeons = config.maxPigeonsPerSession;
    if (cur >= maxPigeons) {
      abuse.recordAbuse('pigeon_limit_reached', req.ip, sessionId);
      return res.status(400).json({ error: "You've had enough pigeons for today!", carrierPigeon: cur });
    }

    const newCount = cur + 1;
    const saved = repo.updateSession(sessionId, {
      expires: new Date(Date.now() + config.sessionTimeoutMinutes * 60000).toISOString(),
      inv: { ...session.inv, carrierPigeon: newCount },
    });
    if (!saved) return res.status(500).json({ error: 'Failed to update session' });

    res.json({
      purchased: true,
      carrierPigeon: newCount,
      remaining_capacity: maxPigeons - newCount,
    });
  });

  app.post('/pigeon/send', limiter({ windowMs: 60000, max: 5 }), (req, res) => {
    const data = req.body || {};
    const sessionId = (data.session_id || '').trim();
    const rawText = (data.message || '').trim();

    if (!sessionId || !rawText) {
      return res.status(400).json({ error: 'session_id and message required' });
    }

    const { flagged, info } = abuse.isFlagged(req.ip);
    if (flagged) {
      return res.status(429).json({ error: 'Temporarily blocked due to abuse', until: (info || {}).until });
    }

    const result = pigeonService.sendPigeon(sessionId, rawText);
    if (result.error) {
      if (result.internal) {
        return res.status(500).json({ error: 'Internal server error' });
      }
      const metric =
        result.error === 'Invalid session' ? 'invalid_session' :
        result.error === 'Session expired' ? 'session_expired' :
        result.error === 'No carrier pigeon in inventory' ? 'no_inventory' :
        result.error === 'Duplicate message' ? 'duplicate' :
        result.error === 'Session pigeon message limit reached' ? 'message_cap' :
          'sanitize_reject';
      abuse.recordAbuse(metric, req.ip, sessionId, { pigeon_error: result.error });
      return res.status(400).json({ error: result.error });
    }

    abuse.recordAbuse('message_sent', req.ip, sessionId);
    res.json(result);
  });

  app.post('/pigeon/delivery', limiter({ windowMs: 60000, max: 5 }), (req, res) => {
    const sessionId = ((req.body || {}).session_id || '').trim();
    if (!sessionId) return res.status(400).json({ error: 'session_id required' });

    const { flagged, info } = abuse.isFlagged(req.ip);
    if (flagged) {
      return res.status(429).json({ error: 'Temporarily blocked due to abuse', until: (info || {}).until });
    }

    const result = pigeonService.deliverPigeon(sessionId);
    if (result.error) {
      if (result.error === 'Invalid session') {
        abuse.recordAbuse('invalid_session', req.ip, sessionId);
      } else if (result.error === 'Session expired') {
        abuse.recordAbuse('session_expired', req.ip, sessionId);
      }
      return res.status(400).json({ error: result.error });
    }
    res.json(result);
  });

  app.get('/pigeon/murder', (req, res) => {
    const sessionId = (req.headers['x-session-id'] || '').trim() || null;
    const totals = repo.getPigeonMurderTotals(sessionId);
    const payload = {
      murder_total: totals.total_murdered,
      players_with_murders: totals.unique_players,
    };
    if (sessionId) {
      payload.session_id = sessionId;
      payload.session_murder_total = totals.session_murdered;
    }
    res.json(payload);
  });

  app.post('/pigeon/murder', limiter({ windowMs: 3600000, max: 30 }), (req, res) => {
    const data = req.body || {};
    const sessionId = (data.session_id || data.SID || '').trim();
    const pigeonId = (data.pigeon_id || '').trim() || null;

    if (!sessionId) return res.status(400).json({ error: 'session_id required' });

    const { flagged, info } = abuse.isFlagged(req.ip);
    if (flagged) {
      return res.status(429).json({ error: 'Temporarily blocked due to abuse', until: (info || {}).until });
    }

    const session = repo.getSessionById(sessionId);
    if (!session) {
      abuse.recordAbuse('invalid_session', req.ip, sessionId);
      return res.status(400).json({ error: 'Invalid session' });
    }
    try {
      if (new Date(session.expires) < new Date()) {
        abuse.recordAbuse('session_expired', req.ip, sessionId);
        repo.deleteSession(sessionId);
        return res.status(400).json({ error: 'Session expired' });
      }
    } catch (e) {
      return res.status(400).json({ error: 'Session expired' });
    }

    const murderResult = repo.recordPigeonMurder(sessionId, pigeonId);
    if (murderResult === 'ok') {
      abuse.recordAbuse('pigeon_murdered', req.ip, sessionId);
      const totals = repo.getPigeonMurderTotals(sessionId);
      return res.json({
        murdered: true,
        session_id: sessionId,
        pigeon_id: pigeonId,
        murder_total: totals.total_murdered,
        session_murder_total: totals.session_murdered,
      });
    }
    if (murderResult === 'duplicate') {
      return res.status(409).json({ murdered: false, error: 'Murder already reported for this pigeon', pigeon_id: pigeonId });
    }
    res.status(500).json({ murdered: false, error: 'Failed to record murder' });
  });
}

module.exports = { register };
