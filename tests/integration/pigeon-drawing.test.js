const { expect } = require('chai');
const supertest = require('supertest');
const { buildApp } = require('../../src/buildApp');
const repo = require('../../src/db/sqlite.repository');
const config = require('../../src/config');

// Handdrawn picture messages end-to-end through the public profile. The gate is
// enforced in the service from the *stored* session.client_version, so sessions
// are seeded directly (no client-version validation at the DB layer) to pin both
// the send gate and the delivery strip without depending on /start semantics.
const routes = [require('../../src/routes/pigeon.route')];

const DRAWING = { strokes: [{ c: 1, p: [0, 0, 10, 10, 20, 5] }] };

function seedSession(sessionId, clientVersion, carrierPigeon) {
  repo.saveSession(sessionId, {
    created: new Date().toISOString(),
    expires: new Date(Date.now() + 3600000).toISOString(),
    floor: 1,
    level: 1,
    exp: 0,
    created_via: 'api_start',
    client_version: clientVersion,
    inv: { carrierPigeon },
  });
}

function uid(tag) {
  return `drawing-${tag}-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

describe('pigeon drawing messages (integration)', () => {
  let app;
  let originalMin;

  before(() => {
    originalMin = config.pigeonDrawingMinClientVersion;
    config.pigeonDrawingMinClientVersion = '4.2.0';
    app = buildApp(routes);
  });
  after(() => {
    config.pigeonDrawingMinClientVersion = originalMin;
  });

  it('sends a captioned drawing and hands the drawing to a capable recipient', async () => {
    const sender = uid('sender');
    const recipient = uid('recipient');
    seedSession(sender, '4.2.0', 1);
    seedSession(recipient, '4.2.0', 0);

    const send = await supertest(app)
      .post('/pigeon/send')
      .send({ session_id: sender, message: 'hello there', drawing: DRAWING });
    expect(send.status).to.equal(200);
    expect(send.body.stored).to.equal(true);

    const del = await supertest(app)
      .post('/pigeon/delivery')
      .send({ session_id: recipient });
    expect(del.status).to.equal(200);
    expect(del.body.delivered).to.equal(true);
    expect(del.body.pigeon_message).to.equal('hello there');
    expect(del.body.pigeon_drawing).to.deep.equal({ v: 1, strokes: [{ c: 1, p: [0, 0, 10, 10, 20, 5] }] });
  });

  it('accepts a drawing-only send (empty caption) from a capable client', async () => {
    const sender = uid('cap-sender');
    const recipient = uid('cap-recipient');
    seedSession(sender, '4.2.0', 1);
    seedSession(recipient, '4.2.0', 0);

    const send = await supertest(app)
      .post('/pigeon/send')
      .send({ session_id: sender, drawing: DRAWING });
    expect(send.status).to.equal(200);
    expect(send.body.stored).to.equal(true);

    const del = await supertest(app)
      .post('/pigeon/delivery')
      .send({ session_id: recipient });
    expect(del.body.delivered).to.equal(true);
    expect(del.body.pigeon_message).to.equal('');
    expect(del.body.pigeon_drawing).to.not.equal(null);
  });

  it('rejects a drawing send from a client below the drawing minimum', async () => {
    const sender = uid('old-sender');
    seedSession(sender, '3.0.251113', 1);

    const send = await supertest(app)
      .post('/pigeon/send')
      .send({ session_id: sender, message: 'still allowed', drawing: DRAWING });
    expect(send.status).to.equal(400);
    expect(send.body.error).to.equal('Client too old for picture messages');
  });

  it('strips the drawing for a recipient below the drawing minimum', async () => {
    const sender = uid('strip-sender');
    const oldRecipient = uid('strip-recipient');
    seedSession(sender, '4.2.0', 1);
    seedSession(oldRecipient, '3.0.251113', 0);

    const send = await supertest(app)
      .post('/pigeon/send')
      .send({ session_id: sender, message: 'look at this', drawing: DRAWING });
    expect(send.status).to.equal(200);

    const del = await supertest(app)
      .post('/pigeon/delivery')
      .send({ session_id: oldRecipient });
    expect(del.body.delivered).to.equal(true);
    expect(del.body.pigeon_message).to.equal('look at this');
    expect(del.body.pigeon_drawing).to.equal(null);
  });

  it('rejects a send with neither message nor drawing', async () => {
    const sender = uid('empty-sender');
    seedSession(sender, '4.2.0', 1);

    const send = await supertest(app)
      .post('/pigeon/send')
      .send({ session_id: sender });
    expect(send.status).to.equal(400);
    expect(send.body.error).to.match(/message or drawing/);
  });
});
