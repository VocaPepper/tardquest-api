const crypto = require('node:crypto');
const config = require('../config');
const repo = require('../db/sqlite.repository');
const abuse = require('../services/abuse.service');
const sessionService = require('../services/session.service');
const leaderboardService = require('../services/leaderboard.service');
const { validateClientVersion, isLeaderboardEligible } = require('../utils/validation');
const { validator } = require('../services/vocaguard.service');
const { limiter } = require('../middleware/rateLimiter');
const logger = require('../utils/logger');

function register(app) {
  app.post('/start', (req, res) => {
    const data = req.body || {};
    const clientVersion = data.version;

    if (!clientVersion) {
      return res.status(400).json({
        error: 'Client API version required',
        server_version: config.apiVersion,
        reason: "Missing 'version' field in request",
      });
    }

    const versionCheck = validateClientVersion(clientVersion);
    if (!versionCheck.valid) {
      return res.status(400).json({
        error: versionCheck.error,
        server_version: config.apiVersion,
        client_version: clientVersion,
        minimum_required: config.minSupportedClientVersion,
        reason: versionCheck.reason,
      });
    }

    const { flagged, info } = abuse.isFlagged(req.ip);
    if (flagged) {
      return res.status(429).json({ error: 'Temporarily blocked due to abuse', until: (info || {}).until });
    }

    const linkedUsername = sessionService.linkAuthSession(data.auth_session_id);
    let session;
    try {
      session = sessionService.createApiSession(linkedUsername, clientVersion);
    } catch (e) {
      logger.logError('start_createSession', e);
      return res.status(500).json({ error: 'Failed to create session', server_version: config.apiVersion });
    }

    const responseData = {
      session_id: session.session_id,
      server_version: config.apiVersion,
    };
    if (linkedUsername) {
      responseData.username = linkedUsername;
    }

    if (config.enableVocaguard) {
      const { challengeId, challengeSalt } = validator.generateChallenge(session.session_id);
      responseData.challenge_id = challengeId;
      responseData.challenge_salt = challengeSalt;
      responseData.challenge_difficulty = config.powDifficultyPrefixZeros;
    }

    res.json(responseData);
  });

  app.post('/update', limiter({ windowMs: 60000, max: 10 }), async (req, res) => {
    const data = req.body || {};
    const sessionId = data.session_id;

    if (!sessionId || typeof sessionId !== 'string') {
      return res.status(400).json({ error: 'session_id required' });
    }

    const { flagged, info } = abuse.isFlagged(req.ip);
    if (flagged) {
      return res.status(429).json({ error: 'Temporarily blocked due to abuse', until: (info || {}).until });
    }

    let floor, level, exp;
    try {
      floor = parseInt(data.floor, 10);
      level = parseInt(data.level, 10);
      exp = parseInt(data.exp, 10);
      if (isNaN(floor) || isNaN(level) || isNaN(exp)) throw new Error('NaN');
    } catch (e) {
      abuse.recordAbuse('invalid_progress_type', req.ip, sessionId, {
        floor_val: data.floor, level_val: data.level, exp_val: data.exp,
      });
      return res.status(400).json({ error: 'Floor, level, and exp must be valid integers' });
    }

    const died = data.died === true || data.died === 'true' || data.died === 1;
    const challengeId = data.challenge_id;
    const challengeProof = data.challenge_proof;

    const session = repo.getSessionById(sessionId);
    if (!session) {
      abuse.recordAbuse('invalid_session', req.ip, sessionId, { attempted_session: sessionId });
      return res.status(400).json({ error: 'Invalid session token' });
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

    if (session.died_at) {
      abuse.recordAbuse('session_already_dead', req.ip, sessionId, { died_at: session.died_at });
      return res.status(400).json({ error: 'Session has already ended' });
    }

    const currentFloor = session.floor;
    const currentLevel = session.level;
    const currentExp = session.exp || 0;
    const lastFloorUpdate = session.last_floor_update || null;

    if (config.enableVocaguard) {
      const result = validator.validateProgressUpdate(
        currentFloor, currentLevel, currentExp,
        floor, level, exp,
        sessionId, lastFloorUpdate,
      );

      if (!result.valid) {
        abuse.recordAbuse(result.abuse ? (result.abuse.cheat_type || 'unknown_cheat') : 'unknown_cheat', req.ip, sessionId, result.abuse || {});
        return res.status(400).json({
          error: result.error,
          detail: result.error && result.error.toLowerCase().includes('floor')
            ? `Current floor: ${currentFloor}, attempted: ${floor}`
            : `Current level: ${currentLevel}, attempted: ${level}`,
        });
      }
    }

    const nowIso = new Date().toISOString();

    if (died) {
      if (config.enableVocaguard) {
        if (!challengeId || !challengeProof) {
          abuse.recordAbuse('death_pow_missing', req.ip, sessionId, {
            challenge_id: !!challengeId, challenge_proof: !!challengeProof,
          });
          repo.updateSession(sessionId, { died_at: nowIso });
          return res.status(400).json({ error: 'Proof-of-work challenge verification required for death submission' });
        }

        const powResult = validator.verifyChallengeProof(
          sessionId, challengeId, challengeProof, config.powDifficultyPrefixZeros,
        );

        if (!powResult.valid) {
          abuse.recordAbuse('death_pow_verification_failed', req.ip, sessionId, { reason: powResult.error });

          if (session.username) {
            try {
              leaderboardService.removeAccountEntry(session.username);
            } catch (e) {
              logger.logError('death_rollback_failed', e, { sessionId, username: session.username });
            }
          }

          repo.updateSession(sessionId, { died_at: nowIso });
          return res.status(400).json({ error: `Death verification failed: ${powResult.error}` });
        }
      }

      // Successful PoW freezes the session and permits authenticated auto-submit.
      const newLastFloorUpdate = floor > currentFloor ? nowIso : lastFloorUpdate;

      if (session.username && isLeaderboardEligible(session.client_version) && (floor > currentFloor || level > currentLevel)) {
        try {
          await leaderboardService.submitScore(session, null, floor, level);
        } catch (e) {
          logger.logError('death_autosubmit_failed', e, { sessionId, username: session.username });
        }
      }

      repo.updateSession(sessionId, {
        floor,
        level,
        exp,
        last_floor_update: newLastFloorUpdate,
        died_at: nowIso,
      });

      return res.json({ status: 'updated', died: true });
    }

    if (config.enableVocaguard) {
      try {
        validator.refreshChallengeForSession(sessionId);
      } catch (e) {
        logger.logError('update_refresh_challenge', e, { sessionId });
      }
    }

    const newLastFloorUpdate = floor > currentFloor ? nowIso : lastFloorUpdate;
    const newExpires = new Date(Date.now() + config.sessionTimeoutMinutes * 60000).toISOString();

    // Auto-submit changes only for authenticated, leaderboard-eligible sessions.
    if (session.username && isLeaderboardEligible(session.client_version) && (floor > currentFloor || level > currentLevel)) {
      try {
        await leaderboardService.submitScore(session, null, floor, level);
      } catch (e) {
        logger.logError('update_autosubmit_failed', e, { sessionId, username: session.username });
      }
    }

    repo.updateSession(sessionId, {
      floor,
      level,
      exp,
      expires: newExpires,
      last_floor_update: newLastFloorUpdate,
    });

    res.json({ status: 'updated' });
  });
}

module.exports = { register };
