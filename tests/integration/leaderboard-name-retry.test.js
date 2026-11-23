const { expect } = require('chai');
const supertest = require('supertest');
const { buildApp } = require('../../src/buildApp');
const config = require('../../src/config');
const postgres = require('../../src/db/postgres');
const repo = require('../../src/db/sqlite.repository');

// Guest leaderboard name-retry flow (4.1 "name retry" work).
// Locks the contract from steps 1-4 of the plan:
//   * name rejections carry machine-readable error_code / retry_allowed
//   * rejections run BEFORE proof-of-work verification, so the solved
//     challenge survives and a retry with a new name on the same session
//     (same challenge_id/challenge_proof) succeeds and keeps the score
//   * account-owned leaderboard rows block guest squatters locally, even
//     when the account service lookup is not consulted
//   * repeated name rejections never feed abuse flagging (no 429)
const routes = [
  require('../../src/routes/session.route'),
  require('../../src/routes/leaderboard.route'),
];

const RESERVED = 'TAKEN'; // treated as an existing account by the stub below
const OWNED = 'OWNED';    // account-owned leaderboard row, inserted directly

// Stub the account-service lookup the same way postgres.js wraps the private
// repository; leaderboard.service calls postgres.usernameExists at call time,
// so replacing the property is enough.
const originalUsernameExists = postgres.usernameExists;

function solvePow(sessionId, challengeId, salt) {
  const prefix = '0'.repeat(config.powDifficultyPrefixZeros);
  for (let nonce = 0; ; nonce++) {
    const hash = require('node:crypto')
      .createHash('sha256')
      .update(`${sessionId}:${challengeId}:${salt}:${nonce}`)
      .digest('hex');
    if (hash.startsWith(prefix)) return `${nonce}:${hash}`;
  }
}

async function startGuestSession(app) {
  const res = await supertest(app).post('/start').send({ version: config.apiVersion });
  expect(res.status).to.equal(200);
  const body = res.body;
  if (!config.enableVocaguard || !body.challenge_id) {
    return { session_id: body.session_id };
  }
  return {
    session_id: body.session_id,
    challenge_id: body.challenge_id,
    challenge_proof: solvePow(body.session_id, body.challenge_id, body.challenge_salt),
  };
}

let app;

describe('Leaderboard guest name retry (integration)', () => {
  before(() => {
    app = buildApp(routes);
    postgres.usernameExists = async (name) => ({ exists: name.toUpperCase() === RESERVED });
    // Account-owned row stamped directly through the repository; the public
    // profile has no auth routes to produce one over HTTP.
    repo.submitLeaderboardEntry(OWNED, 7, 7, OWNED);
  });

  after(() => {
    postgres.usernameExists = originalUsernameExists;
  });

  describe('structured retryable errors', () => {
    it('rejects names reserved by a registered account with name_reserved', async () => {
      const pow = await startGuestSession(app);
      const res = await supertest(app)
        .post('/leaderboard')
        .send({ ...pow, name: RESERVED, floor: 1, level: 1 });
      expect(res.status).to.equal(400);
      expect(res.body.error_code).to.equal('name_reserved');
      expect(res.body.retry_allowed).to.equal(true);
      // The solved challenge is not consumed and no replacement is issued.
      expect(res.body).to.not.have.property('challenge_id');
    });

    it('rejects too-long names with name_too_long and max_length', async () => {
      const pow = await startGuestSession(app);
      const res = await supertest(app)
        .post('/leaderboard')
        .send({ ...pow, name: 'WAYTOOLONG', floor: 1, level: 1 });
      expect(res.status).to.equal(400);
      expect(res.body.error_code).to.equal('name_too_long');
      expect(res.body.max_length).to.equal(config.maxLeaderboardNameLength);
      expect(res.body.retry_allowed).to.equal(true);
    });

    it('rejects missing names with name_required', async () => {
      const pow = await startGuestSession(app);
      const res = await supertest(app)
        .post('/leaderboard')
        .send({ ...pow, name: '', floor: 1, level: 1 });
      expect(res.status).to.equal(400);
      expect(res.body.error_code).to.equal('name_required');
      expect(res.body.retry_allowed).to.equal(true);
    });

    it('rejects invalid characters with name_invalid', async () => {
      const pow = await startGuestSession(app);
      // cleanHtml keeps underscores, so the pattern check still trips.
      const res = await supertest(app)
        .post('/leaderboard')
        .send({ ...pow, name: 'AB_CD', floor: 1, level: 1 });
      expect(res.status).to.equal(400);
      expect(res.body.error_code).to.equal('name_invalid');
      expect(res.body.retry_allowed).to.equal(true);
    });
  });

  describe('retry with a new name', () => {
    it('succeeds on the same session reusing the same solved challenge and keeps the score', async () => {
      const pow = await startGuestSession(app);

      const rejected = await supertest(app)
        .post('/leaderboard')
        .send({ ...pow, name: RESERVED, floor: 1, level: 1 });
      expect(rejected.status).to.equal(400);
      expect(rejected.body.error_code).to.equal('name_reserved');

      const retry = await supertest(app)
        .post('/leaderboard')
        .send({ ...pow, name: 'RETRY', floor: 1, level: 1 });
      expect(retry.status).to.equal(200);
      expect(retry.body.message).to.equal('Leaderboard updated successfully');

      const board = await supertest(app).get('/leaderboard');
      const entry = (board.body || []).find(e => e.name === 'RETRY');
      expect(entry, 'retry score persisted').to.deep.include({ name: 'RETRY', floor: 1, level: 1 });
    });
  });

  describe('account-owned leaderboard rows (local backstop)', () => {
    it('rejects guest submissions colliding with an account-owned row, case-insensitively', async () => {
      const pow = await startGuestSession(app);
      const res = await supertest(app)
        .post('/leaderboard')
        .send({ ...pow, name: OWNED.toLowerCase(), floor: 9, level: 9 });
      expect(res.status).to.equal(400);
      expect(res.body.error_code).to.equal('name_reserved');
      expect(res.body.retry_allowed).to.equal(true);
      expect(res.body).to.not.have.property('challenge_id');
    });

    it('lets the guest immediately retry with a free name on the same session/challenge', async () => {
      const pow = await startGuestSession(app);
      const rejected = await supertest(app)
        .post('/leaderboard')
        .send({ ...pow, name: OWNED, floor: 1, level: 1 });
      expect(rejected.status).to.equal(400);

      const retry = await supertest(app)
        .post('/leaderboard')
        .send({ ...pow, name: 'FREEB', floor: 1, level: 1 });
      expect(retry.status).to.equal(200);
    });

    it('does not merge the guest submission into the account-owned row', async () => {
      const board = await supertest(app).get('/leaderboard');
      const entry = (board.body || []).find(e => e.name === OWNED);
      expect(entry, 'account row score untouched by guest attempt').to.deep.include({ name: OWNED, floor: 7, level: 7 });
    });
  });

  describe('no abuse flagging from name retries', () => {
    it('survives repeated rejections with the same IP: no 429, still retryable', async () => {
      const pow = await startGuestSession(app);
      for (let i = 0; i < 4; i++) {
        const res = await supertest(app)
          .post('/leaderboard')
          .send({ ...pow, name: RESERVED, floor: 1, level: 1 });
        expect(res.status).to.equal(400);
        expect(res.status).to.not.equal(429);
      }
      const board = await supertest(app).get('/leaderboard');
      expect(board.status, 'IP not blocked by repeated name rejections').to.equal(200);

      const retry = await supertest(app)
        .post('/leaderboard')
        .send({ ...pow, name: 'FREEC', floor: 1, level: 1 });
      expect(retry.status).to.equal(200);
    });
  });
});
