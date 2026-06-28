const logger = require('../utils/logger');

function errorHandler(err, req, res, _next) {
  logger.logError('unhandledError', err, {
    method: req.method,
    path: req.path,
    ip: req.ip,
  });
  res.status(500).json({ error: 'Internal server error' });
}

module.exports = { errorHandler };
