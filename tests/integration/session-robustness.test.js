const { expect } = require('chai');
const supertest = require('supertest');
const { buildApp } = require('../../src/buildApp');
const repo = require('../../src/db/sqlite.repository');
const config = require('../../src/config');

// A4 — robustness against corrupted date fields on stored sessions.
// new Date("<garbage>") yields Invalid Date instead of throwing, and every
// comparison against Invalid Date is false, so the previous expiry guards let a
// malformed session pass as "not expired". These tests pin the fail-closed
// behavior for both /update and /leaderboard, and confirm a bad last_floor_update
// never crashes a request.
const routes = [
  require('../../src/routes/status.route'),
  require('../../src/routes/session.route'),
  require('../../src/routes/leaderboard.route'),
];

describe('Session date robustness (integration)', () => {
  let app;

  before(() => {
    app = buildApp(routes);
  });

  function seedSession(sessionId, fields) {
    repo.saveSession(sessionId, {
      created: new Date().toISOString(),
      floor: 1,
      level: 1,
      exp: 0,
      created_via: 'api_start',
      client_version: config.minClientVersion,
      inv: { carrierPigeon: 0 },
      ...fields,
    });
  }

  describe('malformed session expiry', () => {
    const id = `corrupt-expiry-${process.pid}-${Date.now()}`;

    before(() => {
      seedSession(id, { expires: 'not-a-real-timestamp' });
    });

    it('POST /update is rejected (not a crash) when expiry is unparseable', async () => {
      const res = await supertest(app)
        .post('/update')
        .send({ session_id: id, floor: 2, level: 1, exp: 50 });
      expect(res.status).to.equal(400);
      expect(res.body.error).to.equal('Session expired');
    });

    it('POST /leaderboard is rejected (not a crash) when expiry is unparseable', async () => {
      const res = await supertest(app)
        .post('/leaderboard')
        .send({ session_id: id, name: 'ABC', floor: 1, level: 1 });
      expect(res.status).to.equal(400);
      expect(res.body.error).to.equal('Session expired');
    });
  });

  describe('a genuinely expired (but valid) session', () => {
    const id = `past-expiry-${process.pid}-${Date.now()}`;

    before(() => {
      seedSession(id, { expires: new Date(Date.now() - 60000).toISOString() });
    });

    it('is still rejected at POST /update', async () => {
      const res = await supertest(app)
        .post('/update')
        .send({ session_id: id, floor: 2, level: 1, exp: 50 });
      expect(res.status).to.equal(400);
      expect(res.body.error).to.equal('Session expired');
    });
  });

  describe('valid sessions still work', () => {
    let sessionId;

    before(async () => {
      const res = await supertest(app).post('/start').send({ version: config.minClientVersion });
      sessionId = res.body.session_id;
    });

    it('POST /update succeeds on a normal progress increment', async () => {
      const res = await supertest(app)
        .post('/update')
        .send({ session_id: sessionId, floor: 2, level: 1, exp: 50 });
      expect(res.status).to.equal(200);
      expect(res.body.status).to.equal('updated');
    });
  });

  describe('malformed last_floor_update', () => {
    const id = `corrupt-lfu-${process.pid}-${Date.now()}`;

    before(() => {
      seedSession(id, {
        expires: new Date(Date.now() + 600000).toISOString(),
        last_floor_update: 'garbage-date-value',
      });
    });

    it('never returns a 500 on a floor increment', async () => {
      const res = await supertest(app)
        .post('/update')
        .send({ session_id: id, floor: 2, level: 1, exp: 50 });
      expect(res.status).to.not.equal(500);
    });
  });
});
