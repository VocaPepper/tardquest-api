const config = require('./config');
const { validator } = require('./services/vocaguard.service');
const repo = require('./db/sqlite.repository');
const postgres = require('./db/postgres');
const logger = require('./utils/logger');

async function listen(app) {
  console.log(`Starting TardQuest API server`);

  if (config.profile === 'private' && !config.recoveryCodePepper) {
    console.warn('SECURITY: RECOVERY_CODE_PEPPER is not set. Recovery codes are weaker without a pepper. Set the RECOVERY_CODE_PEPPER environment variable.');
  }

  postgres.ensureRecoverySchema().catch(e => {
    logger.logError('startup_ensureRecoverySchema', e);
  });

  const bgWorker = setInterval(() => {
    try {
      repo.purgeOldSessions();
      if (config.enableVocaguard) {
        const expiredCount = validator.cleanupExpired();
        if (expiredCount > 0) {
          console.log(`Cleaned up ${expiredCount} expired VocaGuard challenges/profiles`);
        }
      }
    } catch (e) {
      logger.logError('backgroundWorker', e);
    }
  }, config.backgroundWorkerSleepSeconds * 1000);

  bgWorker.unref();

  const signals = ['SIGINT', 'SIGTERM'];
  signals.forEach(signal => {
    process.on(signal, async () => {
      console.log(`\nReceived ${signal}, shutting down gracefully...`);
      clearInterval(bgWorker);
      await postgres.close();
      process.exit(0);
    });
  });

  app.listen(config.port, config.host, () => {
    console.log(`TardQuest API listening on http://${config.host}:${config.port}`);
  });
}

module.exports = { listen };
