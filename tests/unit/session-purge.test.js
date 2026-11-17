const { expect } = require('chai');
const repo = require('../../src/db/sqlite.repository');
const config = require('../../src/config');

// A5 — session lifetime reconciliation. The purge worker deletes rows keyed on
// created_at; the session TTL (expires) is a 30-day idle window refreshed on
// activity. The purge age must never be *shorter* than the TTL window, or rows
// are removed long before their expiry could ever take effect (the original bug:
// 7-day purge vs 30-day TTL). These tests pin that invariant and the delete
// behavior itself.
const DAY_MS = 86400000;

function uniqueId(tag) {
  return `purge-${tag}-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function seedWithCreated(id, createdMs) {
  repo.saveSession(id, {
    floor: 1,
    level: 1,
    exp: 0,
    expires: new Date(createdMs + config.sessionTimeoutMinutes * 60000).toISOString(),
    created: new Date(createdMs).toISOString(),
    created_via: 'api_start',
    client_version: config.minClientVersion,
  });
}

describe('Session purge (unit)', () => {
  describe('config invariant', () => {
    it('purge age is never shorter than the session TTL window', () => {
      const ttlDays = config.sessionTimeoutMinutes / (60 * 24);
      expect(config.sessionPurgeAgeDays).to.be.at.least(ttlDays);
    });
  });

  describe('purgeOldSessions deletes by created_at', () => {
    let savedPurgeAge;
    const oldId = uniqueId('old');
    const recentId = uniqueId('recent');
    const boundaryId = uniqueId('boundary');

    before(() => {
      savedPurgeAge = config.sessionPurgeAgeDays;
      // Temporarily shrink the window so the test runs against a 1-day horizon.
      config.sessionPurgeAgeDays = 1;

      seedWithCreated(oldId, Date.now() - 2 * DAY_MS);        // older than window -> purged
      seedWithCreated(recentId, Date.now() - 60000);          // ~1 min old -> kept
      seedWithCreated(boundaryId, Date.now() - 12 * 3600000); // 12h old -> kept (inside 1-day window)
    });

    after(() => {
      config.sessionPurgeAgeDays = savedPurgeAge;
      repo.deleteSession(oldId);
      repo.deleteSession(recentId);
      repo.deleteSession(boundaryId);
    });

    it('removes sessions created before the cutoff and keeps newer ones', () => {
      const purged = repo.purgeOldSessions();
      expect(purged).to.be.at.least(1);

      expect(repo.getSessionById(oldId)).to.equal(null);
      expect(repo.getSessionById(recentId)).to.not.equal(null);
      expect(repo.getSessionById(boundaryId)).to.not.equal(null);
    });

    it('is idempotent — a second run removes nothing further', () => {
      repo.purgeOldSessions();
      const again = repo.purgeOldSessions();
      expect(again).to.equal(0);
      expect(repo.getSessionById(oldId)).to.equal(null);
    });
  });
});
