const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const config = require('./config');

function buildApp(routeModules) {
  const app = express();

  app.set('trust proxy', 1);

  app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));

  app.use(cors({
    origin: config.corsOrigins,
  }));

  app.use(express.json({ limit: config.bodyLimit }));
  app.use(express.urlencoded({ limit: config.bodyLimit, extended: false }));

  const logger = require('./utils/logger');
  app.use((req, res, next) => {
    res.on('finish', () => {
      logger.logAccess(
        req.method, req.path, res.statusCode,
        req.ip, req.headers['user-agent'] || '-',
        req.headers['referer'] || '-',
      );
    });
    next();
  });

  // Pre 4.0-compatible API prefix. Register every route module on a sub-app
  // mounted at /api as well, so both /status and /api/status (etc.) work.
  // This keeps the Node port drop-in compatible with the production client.
  const apiApp = express();
  apiApp.set('trust proxy', 1);
  for (const routeModule of routeModules) {
    routeModule.register(apiApp);
  }
  app.use('/api', apiApp);

  for (const routeModule of routeModules) {
    routeModule.register(app);
  }

  const { errorHandler } = require('./middleware/errorHandler');
  app.use(errorHandler);

  return app;
}

module.exports = { buildApp };
