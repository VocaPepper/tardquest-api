const config = require('../config');
const abuse = require('../services/abuse.service');

function register(app) {
  app.get('/status', (req, res) => {
    const { flagged, info } = abuse.isFlagged(req.ip);
    if (flagged) {
      return res.status(429).json({ error: 'Temporarily blocked due to abuse', until: (info || {}).until });
    }
    res.json({ status: 'ok', version: config.apiVersion });
  });
}

module.exports = { register };
