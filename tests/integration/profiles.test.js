const { expect } = require('chai');
const supertest = require('supertest');
const { buildApp } = require('../../src/buildApp');

describe('Public API Integration', () => {
  let app;
  const publicRoutes = [
    require('../../src/routes/status.route'),
    require('../../src/routes/session.route'),
    require('../../src/routes/leaderboard.route'),
    require('../../src/routes/pigeon.route'),
    require('../../src/routes/abuse.route'),
  ];

  before(() => {
    app = buildApp(publicRoutes);
  });

  describe('GET /status', () => {
    it('returns ok status', async () => {
      const res = await supertest(app).get('/status');
      expect(res.status).to.equal(200);
      expect(res.body.status).to.equal('ok');
      expect(res.body.version).to.be.a('string');
    });
  });

  describe('POST /start', () => {
    it('creates a new session', async () => {
      const res = await supertest(app)
        .post('/start')
        .send({ version: '4.0.2606' });
      expect(res.status).to.equal(200);
      expect(res.body.session_id).to.be.a('string');
      expect(res.body.server_version).to.be.a('string');
    });

    it('rejects missing version', async () => {
      const res = await supertest(app).post('/start').send({});
      expect(res.status).to.equal(400);
      expect(res.body.error).to.include('version');
    });
  });

  describe('auth routes are NOT present', () => {
    it('returns 404 for /auth/login', async () => {
      const res = await supertest(app).post('/auth/login').send({});
      expect(res.status).to.equal(404);
    });

    it('returns 404 for /auth/register', async () => {
      const res = await supertest(app).post('/auth/register').send({});
      expect(res.status).to.equal(404);
    });

    it('returns 404 for /launcher-win64', async () => {
      const res = await supertest(app).get('/launcher-win64');
      expect(res.status).to.equal(404);
    });
  });
});

describe('Private API Integration', () => {
  let app;
  const privateRoutes = [
    require('../../src/routes/status.route'),
    require('../../src/routes/session.route'),
    require('../../src/routes/leaderboard.route'),
    require('../../src/routes/pigeon.route'),
    require('../../src/routes/abuse.route'),
    require('../../src/private/routes/auth.route'),
    require('../../src/private/routes/launcher.route'),
  ];

  before(() => {
    app = buildApp(privateRoutes);
  });

  describe('auth routes ARE present', () => {
    it('rejects malformed field types without crashing', async () => {
      const res = await supertest(app)
        .post('/auth/login')
        .send({ username: {}, password: 'password' });
      expect(res.status).to.equal(400);
    });

    it('returns 400 (not 404) for /auth/login with missing fields', async () => {
      const res = await supertest(app).post('/auth/login').send({});
      expect(res.status).to.not.equal(404);
    });

    it('returns 400 (not 404) for /auth/register with missing fields', async () => {
      const res = await supertest(app).post('/auth/register').send({});
      expect(res.status).to.not.equal(404);
    });
  });

  describe('launcher routes ARE present (deprecated)', () => {
    it('GET /launcher-win64 returns JSON manifest or JSON error with a Deprecation header (never HTML 404)', async () => {
      const res = await supertest(app).get('/launcher-win64');
      expect(res.status).to.be.oneOf([200, 404]);
      expect(res.body).to.be.an('object');
      expect(res.headers.deprecation).to.equal('true');
      if (res.status === 200) {
        expect(res.body.launcher).to.be.an('object');
        expect(res.body.launcher.download_url).to.equal('https://milklounge.wang/tardquest');
        expect(res.body.launcher.releases_url)
          .to.equal('https://github.com/VocaPepper/tardquest-launcher/releases/latest');
      }
    });

    it('POST /launcher-win64 is deprecated and returns 410 Gone', async () => {
      const res = await supertest(app)
        .post('/launcher-win64')
        .send({ operation: 'upsert_version', brand: 'test', version_entry: { version: '1.0.0' } });
      expect(res.status).to.equal(410);
      expect(res.body.error).to.include('deprecated');
      expect(res.body.download_url).to.equal('https://milklounge.wang/tardquest');
      expect(res.body.releases_url)
        .to.equal('https://github.com/VocaPepper/tardquest-launcher/releases/latest');
    });
  });

  describe('public routes still work', () => {
    it('GET /status works in private build too', async () => {
      const res = await supertest(app).get('/status');
      expect(res.status).to.equal(200);
    });
  });
});
