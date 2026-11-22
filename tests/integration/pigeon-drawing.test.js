const { expect } = require('chai');
const supertest = require('supertest');
const { buildApp } = require('../../src/buildApp');
const repo = require('../../src/db/sqlite.repository');
const config = require('../../src/config');

// Handdrawn picture messages end-to-end through the public profile. The gate is
// enforced in the service from the *stored* session.client_version, so sessions
// are seeded directly (no client-version validation at the DB layer) to pin both
// the send gate and the delivery *pool separation* without depending on /start
// semantics: a pigeon that carries a picture is held out of the pool for a
// recipient below the drawing floor, so an old client is never handed a blank
// message or a picture it cannot render.
//
// Determinism: this file runs while the only pending pigeons in the DB are the
// ones it creates (no other integration file seeds pigeons, and it runs before
// profiles/session-robustness). Each test therefore drains every pigeon it
// creates — picture messages an old recipient can't consume are claimed by a
// trailing capable recipient inside the same test — so no residue leaks between
// tests and each first-delivery assertion sees only its own pigeons.
const routes = [require('../../src/routes/pigeon.route')];

const DRAWING = { strokes: [{ c: 1, w: 1.5, p: [0, 0, 10, 10, 20, 5] }] };
const RENDERABLE = '4.1.0';   // at the drawing floor: can render pictures
const LEGACY = '4.0.2608';    // prior 4.0 line: below the floor, can't render

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

async function send(app, body) {
  return supertest(app).post('/pigeon/send').send(body);
}
async function deliver(app, sessionId) {
  return supertest(app).post('/pigeon/delivery').send({ session_id: sessionId });
}

describe('pigeon drawing messages (integration)', () => {
  let app;
  let originalMin;

  before(() => {
    originalMin = config.pigeonDrawingMinClientVersion;
    config.pigeonDrawingMinClientVersion = '4.1.0';
    app = buildApp(routes);
  });
  after(() => {
    config.pigeonDrawingMinClientVersion = originalMin;
  });

  it('sends a captioned drawing and hands the drawing to a capable recipient', async () => {
    const sender = uid('sender');
    const recipient = uid('recipient');
    seedSession(sender, RENDERABLE, 1);
    seedSession(recipient, RENDERABLE, 0);

    const sent = await send(app, { session_id: sender, message: 'hello there', drawing: DRAWING });
    expect(sent.status).to.equal(200);
    expect(sent.body.stored).to.equal(true);

    const del = await deliver(app, recipient);
    expect(del.status).to.equal(200);
    expect(del.body.delivered).to.equal(true);
    expect(del.body.pigeon_message).to.equal('hello there');
    expect(del.body.pigeon_drawing).to.deep.equal({ v: 2, strokes: [{ c: 1, p: [0, 0, 10, 10, 20, 5], w: 1.5 }] });
  });

  it('accepts a drawing-only send (empty caption) from a capable client', async () => {
    const sender = uid('cap-sender');
    const recipient = uid('cap-recipient');
    seedSession(sender, RENDERABLE, 1);
    seedSession(recipient, RENDERABLE, 0);

    const sent = await send(app, { session_id: sender, drawing: DRAWING });
    expect(sent.status).to.equal(200);
    expect(sent.body.stored).to.equal(true);

    const del = await deliver(app, recipient);
    expect(del.body.delivered).to.equal(true);
    expect(del.body.pigeon_message).to.equal('');
    expect(del.body.pigeon_drawing).to.not.equal(null);
  });

  it('rejects a drawing send from a client below the drawing minimum', async () => {
    const sender = uid('old-sender');
    seedSession(sender, LEGACY, 1);

    const sent = await send(app, { session_id: sender, message: 'still allowed', drawing: DRAWING });
    expect(sent.status).to.equal(400);
    expect(sent.body.error).to.equal('Client too old for picture messages');
  });

  it('keeps a picture message out of an old recipient pool and delivers it to a capable one', async () => {
    const sender = uid('pool-sender');
    const oldRecipient = uid('pool-old');
    const newRecipient = uid('pool-new');
    seedSession(sender, RENDERABLE, 1);
    seedSession(oldRecipient, LEGACY, 0);
    seedSession(newRecipient, RENDERABLE, 0);

    const sent = await send(app, { session_id: sender, message: 'look at this', drawing: DRAWING });
    expect(sent.status).to.equal(200);

    // The picture is not consumed by the old client and is not even counted as
    // deliverable to it, so it never sees a blank/stripped message.
    const old = await deliver(app, oldRecipient);
    expect(old.status).to.equal(200);
    expect(old.body.delivered).to.equal(false);
    expect(old.body.pigeon_message).to.equal(null);
    expect(old.body.pigeon_drawing).to.equal(null);
    expect(old.body.remaining_queue_pending).to.equal(0);

    // Still queued for a client that can render it (drains the pigeon).
    const fresh = await deliver(app, newRecipient);
    expect(fresh.body.delivered).to.equal(true);
    expect(fresh.body.pigeon_message).to.equal('look at this');
    expect(fresh.body.pigeon_drawing).to.deep.equal({ v: 2, strokes: [{ c: 1, p: [0, 0, 10, 10, 20, 5], w: 1.5 }] });
  });

  it('holds a picture-only pigeon for a capable recipient, not an old one', async () => {
    const sender = uid('only-sender');
    const oldRecipient = uid('only-old');
    const newRecipient = uid('only-new');
    seedSession(sender, RENDERABLE, 1);
    seedSession(oldRecipient, LEGACY, 0);
    seedSession(newRecipient, RENDERABLE, 0);

    const sent = await send(app, { session_id: sender, drawing: DRAWING });
    expect(sent.status).to.equal(200);

    const old = await deliver(app, oldRecipient);
    expect(old.body.delivered).to.equal(false);
    expect(old.body.pigeon_drawing).to.equal(null);
    expect(old.body.remaining_queue_pending).to.equal(0);

    const fresh = await deliver(app, newRecipient);
    expect(fresh.body.delivered).to.equal(true);
    expect(fresh.body.pigeon_drawing).to.not.equal(null);
  });

  it('serves an old client the text-only pigeon while a picture stays out of its pool', async () => {
    const textSender = uid('txt-sender');
    const picSender = uid('pic-sender');
    const oldRecipient = uid('mix-old');
    const newRecipient = uid('mix-new');
    seedSession(textSender, RENDERABLE, 1);
    seedSession(picSender, RENDERABLE, 1);
    seedSession(oldRecipient, LEGACY, 0);
    seedSession(newRecipient, RENDERABLE, 0);

    const sentText = await send(app, { session_id: textSender, message: 'plain note' });
    expect(sentText.status).to.equal(200);
    const sentPic = await send(app, { session_id: picSender, drawing: DRAWING });
    expect(sentPic.status).to.equal(200);

    // The old client is served the text-only pigeon (the picture is excluded).
    const first = await deliver(app, oldRecipient);
    expect(first.body.delivered).to.equal(true);
    expect(first.body.pigeon_message).to.equal('plain note');
    expect(first.body.pigeon_drawing).to.equal(null);

    // Nothing else in the old client's pool — the picture is held, not stripped.
    const second = await deliver(app, oldRecipient);
    expect(second.body.delivered).to.equal(false);
    expect(second.body.remaining_queue_pending).to.equal(0);

    // The picture is still there for a capable recipient (drains it).
    const fresh = await deliver(app, newRecipient);
    expect(fresh.body.delivered).to.equal(true);
    expect(fresh.body.pigeon_drawing).to.not.equal(null);
  });

  it('rejects a send with neither message nor drawing', async () => {
    const sender = uid('empty-sender');
    seedSession(sender, RENDERABLE, 1);

    const sent = await send(app, { session_id: sender });
    expect(sent.status).to.equal(400);
    expect(sent.body.error).to.match(/message or drawing/);
  });
});
