const repo = require('../db/sqlite.repository');
const abuse = require('../services/abuse.service');
const leaderboardService = require('../services/leaderboard.service');
const { validator } = require('../services/vocaguard.service');
const { isLeaderboardEligible } = require('../utils/validation');
const config = require('../config');
const logger = require('../utils/logger');

function register(app) {
  app.get('/leaderboard', (req, res) => {
    const { flagged, info } = abuse.isFlagged(req.ip);
    if (flagged) {
      return res.status(429).json({ error: 'Temporarily blocked due to abuse', until: (info || {}).until });
    }
    try {
      const data = leaderboardService.getLeaderboard();
      res.json(data);
    } catch (e) {
      logger.logError('leaderboard_get', e);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/leaderboard', async (req, res) => {
    const { flagged, info } = abuse.isFlagged(req.ip);
    if (flagged) {
      return res.status(429).json({ error: 'Temporarily blocked due to abuse', until: (info || {}).until });
    }

    try {
      const data = req.body || {};
      if (!data.session_id) {
        return res.status(400).json({ error: 'Missing required field: session_id' });
      }
      if (data.floor === undefined || data.level === undefined) {
        return res.status(400).json({ error: 'Missing required fields: floor, level' });
      }

      const session = repo.getSessionById(data.session_id);
      if (!session) {
        abuse.recordAbuse('invalid_session', req.ip, data.session_id);
        return res.status(400).json({ error: 'VocaGuard session missing or invalid' });
      }

      try {
        if (new Date(session.expires) < new Date()) {
          abuse.recordAbuse('session_expired', req.ip, data.session_id);
          repo.deleteSession(data.session_id);
          return res.status(400).json({ error: 'VocaGuard session expired' });
        }
      } catch (e) {
        return res.status(400).json({ error: 'Session expired' });
      }

      // Pre-4.0 clients may play but cannot submit to the
      // leaderboard. Tell them to update their client instead of accepting
      // the score or rejecting it as an anti-cheat failure.
      if (!isLeaderboardEligible(session.client_version)) {
        return res.status(400).json({
          error: 'Leaderboard submissions require client version 4.0 or newer. Please update your client.',
          client_version: session.client_version,
          minimum_required: config.minClientVersion,
          update_required: true,
        });
      }

      if (config.enableVocaguard) {
        const vResult = validator.validateSubmission(
          session.floor, session.level,
          parseInt(data.floor, 10), parseInt(data.level, 10),
        );
        if (!vResult.valid) {
          abuse.recordAbuse('validate_mismatch', req.ip, data.session_id, {
            session_floor: session.floor, session_level: session.level,
            submitted_floor: data.floor, submitted_level: data.level,
          });
          return res.status(400).json({ error: vResult.error });
        }

        if (session.created_via === 'api_start') {
          const challengeId = data.challenge_id;
          const challengeProof = data.challenge_proof;
          if (!challengeId || !challengeProof) {
            abuse.recordAbuse('pow_missing', req.ip, data.session_id, {
              challenge_id: !!challengeId, challenge_proof: !!challengeProof,
            });
            return res.status(400).json({ error: 'Proof-of-work challenge verification required' });
          }
          const powResult = validator.verifyChallengeProof(
            data.session_id, challengeId, challengeProof, config.powDifficultyPrefixZeros,
          );
          if (!powResult.valid) {
            abuse.recordAbuse('pow_verification_failed', req.ip, data.session_id, { reason: powResult.error });
            return res.status(400).json({ error: powResult.error });
          }
        }

        if (session.username) {
          repo.updateSession(data.session_id, {
            expires: new Date(Date.now() + config.sessionTimeoutMinutes * 60000).toISOString(),
          });
        } else {
          repo.deleteSession(data.session_id);
        }
      }

      const result = await leaderboardService.submitScore(
        session, data.name, parseInt(data.floor, 10), parseInt(data.level, 10),
      );
      if (result.error) {
        return res.status(400).json({ error: result.error });
      }
      res.json({ message: 'Leaderboard updated successfully', data: result.data });
    } catch (e) {
      logger.logError('leaderboard_post', e, { request_data: JSON.stringify(req.body || {}) });
      res.status(500).json({ error: 'Internal server error' });
    }
  });
}

module.exports = { register };
