const { expect } = require('chai');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const config = require('../../src/config');
const abuse = require('../../src/services/abuse.service');

// A2 — abuse flagging.
// Two behaviors: the flag-window check (isFlagged) and the event-threshold that
// sets a flag (recordAbuse). config.stateDir is read dynamically by the service,
// so each test gets a fresh state dir; the vocaguard event log lives in the
// (isolated) config.logDir that logger.js captured, which is where recordAbuse
// reads counts back from.
const TEST_IP = '10.0.0.42';
const originalStateDir = config.stateDir;
const eventLogFile = path.join(config.logDir, 'vocaguard.log');

function eventLine(metric, ip) {
  // Matches logger's ts format ("YYYY-MM-DD HH:MM:SS") so loadVocaguardEvents parses it.
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 19);
  return `${ts}|${ip}|${metric}`;
}

function seedEvents(metric, ip, count) {
  fs.writeFileSync(eventLogFile, Array.from({ length: count }, () => eventLine(metric, ip)).join('\n') + '\n', 'utf-8');
}

describe('abuse.service', () => {
  let stateDir;

  beforeEach(() => {
    stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tq-abuse-state-'));
    config.stateDir = stateDir;
  });

  afterEach(() => {
    try { fs.rmSync(stateDir, { recursive: true, force: true }); } catch (e) { /* gone */ }
  });

  after(() => {
    config.stateDir = originalStateDir;
  });

  describe('isFlagged window', () => {
    it('flags an IP whose entry has not yet expired, returning its info', () => {
      const until = Math.floor(Date.now() / 1000) + 600;
      abuse.saveFlaggedIps({ [TEST_IP]: { until, counts: { duplicate: 2 } } });
      const res = abuse.isFlagged(TEST_IP);
      expect(res.flagged).to.equal(true);
      expect(res.info.until).to.equal(until);
    });

    it('treats an expired entry as unflagged and prunes it on read', () => {
      const until = Math.floor(Date.now() / 1000) - 10; // already elapsed
      abuse.saveFlaggedIps({ [TEST_IP]: { until, counts: { duplicate: 2 } } });
      const res = abuse.isFlagged(TEST_IP);
      expect(res.flagged).to.equal(false);
      expect(abuse.loadFlaggedIps()[TEST_IP]).to.equal(undefined);
    });

    it('does not flag an IP with no entry', () => {
      expect(abuse.isFlagged('10.0.0.99').flagged).to.equal(false);
    });
  });

  describe('recordAbuse threshold', () => {
    it('flags an IP once duplicate events reach the threshold', () => {
      seedEvents('duplicate', TEST_IP, config.abuseDuplicateThreshold - 1);
      expect(abuse.isFlagged(TEST_IP).flagged).to.equal(false);

      // One more tips the running count over the threshold.
      abuse.recordAbuse('duplicate', TEST_IP, 'sid-1');
      expect(abuse.isFlagged(TEST_IP).flagged).to.equal(true);
    });

    it('does not flag while below the threshold', () => {
      seedEvents('duplicate', TEST_IP, Math.max(0, config.abuseDuplicateThreshold - 2));
      abuse.recordAbuse('duplicate', TEST_IP, 'sid-1'); // total = threshold - 1
      expect(abuse.isFlagged(TEST_IP).flagged).to.equal(false);
    });

    it('counts only events for the same IP', () => {
      seedEvents('duplicate', '10.0.0.98', config.abuseDuplicateThreshold - 1);
      abuse.recordAbuse('duplicate', TEST_IP, 'sid-1'); // TEST_IP count = 1
      expect(abuse.isFlagged(TEST_IP).flagged).to.equal(false);
    });
  });
});
