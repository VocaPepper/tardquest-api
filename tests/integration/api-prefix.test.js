const { expect } = require('chai');
const supertest = require('supertest');
const { buildApp } = require('../../src/buildApp');
const config = require('../../src/config');

// A3 — the /api compatibility prefix. buildApp mounts every route at both the
// bare path and under /api; assert the two resolve identically (same status and
// body shape) for representative public endpoints, and that unknown paths 404
// under both prefixes rather than silently differing.
const routes = [
  require('../../src/routes/status.route'),
  require('../../src/routes/session.route'),
  require('../../src/routes/leaderboard.route'),
  require('../../src/routes/pigeon.route'),
  require('../../src/routes/abuse.route'),
];

describe('/api prefix parity (integration)', () => {
  let app;

  before(() => {
    app = buildApp(routes);
  });

  it('GET /status resolves identically at both prefixes', async () => {
    const bare = await supertest(app).get('/status');
    const prefixed = await supertest(app).get('/api/status');
    expect(bare.status).to.equal(200);
    expect(prefixed.status).to.equal(200);
    expect(prefixed.body).to.deep.equal(bare.body);
    expect(prefixed.body.status).to.equal('ok');
  });

  it('GET /leaderboard resolves identically at both prefixes', async () => {
    const bare = await supertest(app).get('/leaderboard');
    const prefixed = await supertest(app).get('/api/leaderboard');
    expect(bare.status).to.equal(200);
    expect(prefixed.status).to.equal(200);
    expect(prefixed.body).to.deep.equal(bare.body);
    expect(prefixed.body).to.be.an('array');
  });

  it('POST /start resolves identically at both prefixes', async () => {
    const version = config.minClientVersion;
    const bare = await supertest(app).post('/start').send({ version });
    const prefixed = await supertest(app).post('/api/start').send({ version });
    expect(bare.status).to.equal(200);
    expect(prefixed.status).to.equal(200);
    expect(prefixed.body.session_id).to.be.a('string');
    expect(prefixed.body.server_version).to.equal(bare.body.server_version);
  });

  it('POST /leaderboard is routed under /api (not a 404)', async () => {
    const res = await supertest(app).post('/api/leaderboard').send({});
    expect(res.status).to.not.equal(404); // reaches validation, not a missing route
    expect(res.status).to.equal(400);
  });

  it('unknown paths 404 under both prefixes', async () => {
    expect((await supertest(app).get('/definitely-not-a-route')).status).to.equal(404);
    expect((await supertest(app).get('/api/definitely-not-a-route')).status).to.equal(404);
  });
});
