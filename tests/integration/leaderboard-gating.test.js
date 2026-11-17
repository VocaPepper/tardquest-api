const { expect } = require('chai');
const supertest = require('supertest');
const { buildApp } = require('../../src/buildApp');
const config = require('../../src/config');

// A1 — leaderboard client-version gating.
// Three bands, derived from config so they survive version bumps:
//   * below minSupportedClientVersion  -> rejected at POST /start
//   * >= minSupported but < minClient  -> may play, but score submission is
//                                         refused with `update_required`
//   * >= minClient (major.minor)       -> passes the eligibility gate
const routes = [
  require('../../src/routes/status.route'),
  require('../../src/routes/session.route'),
  require('../../src/routes/leaderboard.route'),
];

function parse(v) {
  const [major, minor, patch] = v.split('.').map(Number);
  return { major, minor, patch };
}

const minSupported = parse(config.minSupportedClientVersion); // lowest allowed to connect
const minClient = parse(config.minClientVersion);             // lowest allowed to submit

// Guaranteed below minSupported: same shape, one major lower.
const belowMin = `${minSupported.major - 1}.0.0`;
// Allowed to connect but not submit: same major as minSupported, lower major than minClient.
const legacySupported = `${minSupported.major}.999.0`;
// Eligible: exactly the submission threshold.
const eligible = `${minClient.major}.${minClient.minor}.${minClient.patch}`;
// Eligible via a higher patch on the same major.minor (patch must NOT gate — cf. 2cdfd4e).
const eligiblePatchBump = `${minClient.major}.${minClient.minor}.${minClient.patch + 9999}`;

let app;

async function startSession(clientVersion) {
  const res = await supertest(app).post('/start').send({ version: clientVersion });
  return res;
}

describe('Leaderboard version gating (integration)', () => {
  before(() => {
    app = buildApp(routes);
  });

  describe('GET /leaderboard', () => {
    it('returns an array of entries', async () => {
      const res = await supertest(app).get('/leaderboard');
      expect(res.status).to.equal(200);
      expect(res.body).to.be.an('array');
    });
  });

  describe('clients below minSupportedClientVersion', () => {
    it('are rejected outright at POST /start', async () => {
      const res = await startSession(belowMin);
      expect(res.status).to.equal(400);
      expect(res.body.error).to.equal('Client version too old');
      expect(res.body.minimum_required).to.equal(config.minSupportedClientVersion);
      expect(res.body.session_id).to.equal(undefined);
    });
  });

  describe('legacy clients (>= minSupported, < minClient)', () => {
    let sessionId;

    it('may start a session', async () => {
      const res = await startSession(legacySupported);
      expect(res.status).to.equal(200);
      sessionId = res.body.session_id;
      expect(sessionId).to.be.a('string');
    });

    it('are refused leaderboard submission with update_required', async () => {
      const res = await supertest(app)
        .post('/leaderboard')
        .send({ session_id: sessionId, name: 'ABC', floor: 1, level: 1 });
      expect(res.status).to.equal(400);
      expect(res.body.update_required).to.equal(true);
      expect(res.body.minimum_required).to.equal(config.minClientVersion);
      expect(res.body.client_version).to.equal(legacySupported);
      expect(res.body.error).to.match(/update your client/i);
    });
  });

  describe('current clients (>= minClient major.minor)', () => {
    it('pass the eligibility gate and reach proof-of-work validation', async () => {
      const res = await startSession(eligible);
      expect(res.status).to.equal(200);
      const post = await supertest(app)
        .post('/leaderboard')
        .send({ session_id: res.body.session_id, name: 'ABC', floor: 1, level: 1 });
      // No PoW supplied: gated at the PoW stage rather than the version stage.
      expect(post.status).to.equal(400);
      expect(post.body.update_required).to.equal(undefined);
      expect(post.body.error).to.match(/proof-of-work/i);
    });

    it('are eligible on a higher patch of the same major.minor (patch does not gate)', async () => {
      const res = await startSession(eligiblePatchBump);
      expect(res.status).to.equal(200);
      const post = await supertest(app)
        .post('/leaderboard')
        .send({ session_id: res.body.session_id, name: 'ABC', floor: 1, level: 1 });
      expect(post.body.update_required).to.equal(undefined);
      expect(post.body.error).to.match(/proof-of-work/i);
    });
  });
});
