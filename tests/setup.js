// Mocha setup, loaded via .mocharc.json before any test file.
// Gives every test run an isolated, throwaway environment so the suite:
//   - never touches the real ./data database, and
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

// Best-effort cleanup of the throwaway database and its WAL sidecar files.
function cleanupTestDb() {
  for (const suffix of ['', '-wal', '-shm']) {
    try {
      fs.rmSync(testDbPath + suffix, { force: true });
    } catch (e) {
      // Ignore: nothing to clean up if the DB was never opened.
    }
  }
}
process.on('exit', cleanupTestDb);

module.exports = { testDbPath };
