const repo = require('../db/sqlite.repository');
const abuse = require('../services/abuse.service');
const leaderboardService = require('../services/leaderboard.service');
const { validator } = require('../services/vocaguard.service');
const { isLeaderboardEligible, parseInteger } = require('../utils/validation');
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
      const submittedFloor = parseInteger(data.floor);
      const submittedLevel = parseInteger(data.level);
      if (submittedFloor === null || submittedLevel === null) {
        return res.status(400).json({ error: 'Floor and level must be valid integers' });
      }

      const session = repo.getSessionById(data.session_id);
      if (!session) {
        abuse.recordAbuse('invalid_session', req.ip, data.session_id);
        return res.status(400).json({ error: 'VocaGuard session missing or invalid' });
      }

      // Fail closed on a malformed expiry (see /update): Invalid Date never
      // throws, so the previous try/catch let corrupted sessions pass as valid.
      const expiresAt = new Date(session.expires);
      if (Number.isNaN(expiresAt.getTime())) {
        logger.logError('leaderboard_invalid_expiry', new Error('Unparseable session expiry'), { sessionId: data.session_id });
        return res.status(400).json({ error: 'Session expired' });
      }
      if (expiresAt < new Date()) {
        abuse.recordAbuse('session_expired', req.ip, data.session_id);
        repo.deleteSession(data.session_id);
        return res.status(400).json({ error: 'VocaGuard session expired' });
      }

      // Legacy clients may play, but must update before leaderboard submission.
      if (!isLeaderboardEligible(session.client_version)) {
        return res.status(400).json({
          error: 'Leaderboard submissions require client version 4.0 or newer. Please update your client.',
          client_version: session.client_version,
          minimum_required: config.minClientVersion,
          update_required: true,
        });
      }

      // Guest name checks run before the PoW challenge is verified so a
      // rejected name never consumes the solved challenge: the session,
      // floor/level, and challenge all stay intact for an immediate retry
      // with a new name.
      if (!session.username) {
        const nameCheck = await leaderboardService.validateGuestName(data.name);
        if (nameCheck.error) {
          return res.status(400).json(nameCheck);
        }
      }

      if (config.enableVocaguard) {
        const vResult = validator.validateSubmission(
          session.floor, session.level,
          submittedFloor, submittedLevel,
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
        }
      }

      const result = await leaderboardService.submitScore(
        session, data.name, submittedFloor, submittedLevel,
      );
      if (result.error) {
        // Carry the structured fields (error_code, retry_allowed, max_length)
        // through to the client so a rejected name can be retried on the same
        // session instead of being treated as a lost score.
        const errorPayload = { error: result.error };
        if (result.error_code !== undefined) errorPayload.error_code = result.error_code;
        if (result.retry_allowed !== undefined) errorPayload.retry_allowed = result.retry_allowed;
        if (result.max_length !== undefined) errorPayload.max_length = result.max_length;
        if (!session.username && config.enableVocaguard) {
          const challenge = validator.generateChallenge(data.session_id);
          return res.status(400).json({
            ...errorPayload,
            challenge_id: challenge.challengeId,
            challenge_salt: challenge.challengeSalt,
            challenge_difficulty: config.powDifficultyPrefixZeros,
          });
        }
        return res.status(400).json(errorPayload);
      }
      if (!session.username) repo.deleteSession(data.session_id);
      res.json({ message: 'Leaderboard updated successfully', data: result.data });
    } catch (e) {
      logger.logError('leaderboard_post', e, { request_data: JSON.stringify(req.body || {}) });
      res.status(500).json({ error: 'Internal server error' });
    }
  });
}

module.exports = { register };
