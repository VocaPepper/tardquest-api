const config = require('../config');
const abuse = require('../services/abuse.service');
const { whitelistMiddleware } = require('../middleware/ipWhitelist');
const { validator } = require('../services/vocaguard.service');
const logger = require('../utils/logger');

function register(app) {
  app.get('/abuse', whitelistMiddleware, (req, res) => {
    try {
      const flagged = abuse.loadFlaggedIps();
      const vocaguardEvents = require('../utils/logger').loadVocaguardEvents(config.abuseEventWindowSeconds);
      const agg = {};
      for (const e of vocaguardEvents) {
        const ip = e.ip;
        const metric = e.metric;
        if (!agg[ip]) agg[ip] = {};
        agg[ip][metric] = (agg[ip][metric] || 0) + 1;
      }

      const behaviorScores = {};
      const querySession = req.headers['x-session-id'] || '';
      if (querySession) {
        const { score, details } = validator.getBehaviorScore(querySession);
        behaviorScores[querySession] = { score, ...details };
      }

      res.json({
        flagged,
        counts: agg,
        window_seconds: config.abuseEventWindowSeconds,
        vocaguard_events: vocaguardEvents,
        behavior: behaviorScores,
      });
    } catch (e) {
      logger.logError('abuse_status', e);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
}

module.exports = { register };
