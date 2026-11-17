// Mocha setup, loaded via .mocharc.json before any test file.
// Gives every test run an isolated, throwaway environment so the suite:
//   - never touches the real ./data database,
//   - never writes into the repo's ./logs or ./json state directories, and
//   - does not trip per-IP rate limits (express-rate-limit) under load.
// Sensitive values are intentionally left unset; the public gameplay profile
// runs entirely against local SQLite.
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');

// Rate limits are about production traffic shaping, not correctness; disable
// them so repeated supertest calls against a shared test IP don't get throttled.
process.env.DEPLOY_MODE = 'dev';

// Exercise the public gameplay surface regardless of the host environment.
process.env.API_PROFILE = 'public';

// Isolated, per-process SQLite file under the OS temp dir. connection.js creates
// the parent directory, and it is removed on exit below.
const testDbPath = path.join(
  os.tmpdir(),
  `tardquest-api-test-${process.pid}-${Date.now()}.db`,
);
process.env.SQLITE_DB_PATH = testDbPath;

// config.logDir/stateDir have no env override, and logger.js captures logDir at
// require time. Repoint them on the config singleton here — before any test
// requires the logger/abuse/connection modules — so logs and abuse state
// (flagged.json, vocaguard.log, …) land in a temp dir instead of the checkout.
const config = require('../src/config');
const testLogDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tq-test-logs-'));
const testStateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tq-test-state-'));
config.logDir = testLogDir;
config.stateDir = testStateDir;

// Best-effort cleanup of the throwaway database and temp log/state dirs.
function cleanupTestEnv() {
  for (const suffix of ['', '-wal', '-shm']) {
    try {
      fs.rmSync(testDbPath + suffix, { force: true });
    } catch (e) {
      // Ignore: nothing to clean up if the DB was never opened.
    }
  }
  for (const dir of [testLogDir, testStateDir]) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      // Ignore: already gone.
    }
  }
}
process.on('exit', cleanupTestEnv);

module.exports = { testDbPath, testLogDir, testStateDir };
