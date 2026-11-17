const crypto = require('node:crypto');
const config = require('../config');
const repo = require('../db/sqlite.repository');
const logger = require('../utils/logger');
const { supportsPigeonDrawing } = require('../utils/validation');

// Enforce the whitelist as a global pass: the configured pattern is not
// global-flagged, so a single .replace would leave later runs of disallowed
// characters intact when an allowed character separates them (e.g. "a😀b😀c").
const DISALLOWED_RE = new RegExp(
  config.allowedCharsPattern.source,
  config.allowedCharsPattern.flags.includes('g') ? config.allowedCharsPattern.flags : `${config.allowedCharsPattern.flags}g`
);

function sanitizeMessage(raw) {
  if (typeof raw !== 'string') return '';
  let txt = raw.normalize('NFC');
  txt = txt.replace(/&#x?[0-9a-fA-F]+;?/g, '');
  txt = txt.replace(/&(?:[a-zA-Z]+|#x?[0-9a-fA-F]+);?/g, '');
  txt = txt.replace(/<[^>]*>/g, '');
  txt = txt.replace(/javascript\s*:/gi, '');
  txt = txt.replace(/data\s*:\s*text\s*\/\s*html/gi, '');
  txt = txt.replace(/vbscript\s*:/gi, '');
  txt = [...txt].filter(ch => {
    const cp = ch.codePointAt(0);
    if (cp === 0x200B || cp === 0x200C || cp === 0x200D || cp === 0xFEFF ||
        cp === 0x200E || cp === 0x200F || cp === 0x2028 || cp === 0x2029) return false;
    return ch === '\n' || (cp >= 32 && cp !== 127);
  }).join('');
  txt = txt.replace(/[ \t]+/g, ' ');
  txt = txt.replace(/\n{3,}/g, '\n\n');
  txt = txt.replace(DISALLOWED_RE, '');
  if (txt.length > config.maxPigeonMessageLen) {
    txt = txt.slice(0, config.maxPigeonMessageLen);
  }
  txt = txt.trim();
  txt = txt.replace(/([!?*.])\1{2,}/g, '$1$1');
  if (txt.length < 3 || /^[.!?* ]+$/.test(txt)) return '';
  return txt;
}

// Validate/normalize a handdrawn picture payload (not text — the text
// whitelist in sanitizeMessage must never see this). Fail-closed: any
// structural or bound violation returns an error, never throws.
function validateDrawing(raw) {
  if (raw === undefined || raw === null) return { drawing: null };
  if (typeof raw !== 'object' || Array.isArray(raw)) return { error: 'Invalid drawing payload' };
  const strokes = raw.strokes;
  if (!Array.isArray(strokes) || strokes.length === 0) return { error: 'Drawing requires at least one stroke' };
  if (strokes.length > config.drawingMaxStrokes) return { error: 'Drawing has too many strokes' };

  const canvas = config.drawingCanvasSize;
  const cleanStrokes = [];
  for (const s of strokes) {
    if (!s || typeof s !== 'object' || Array.isArray(s)) return { error: 'Invalid drawing stroke' };
    if (!Number.isInteger(s.c) || s.c < 0 || s.c >= config.drawingMaxColors) return { error: 'Invalid drawing color index' };
    const pts = s.p;
    if (!Array.isArray(pts) || pts.length < 2 || pts.length % 2 !== 0) return { error: 'Invalid drawing points' };
    if (pts.length / 2 > config.drawingMaxPointsPerStroke) return { error: 'Drawing stroke has too many points' };
    const cleanPts = [];
    for (const n of pts) {
      if (!Number.isInteger(n) || n < 0 || n > canvas) return { error: 'Drawing point out of canvas bounds' };
      cleanPts.push(n);
    }
    cleanStrokes.push({ c: s.c, p: cleanPts });
  }

  const drawing = { v: 1, strokes: cleanStrokes };
  if (JSON.stringify(drawing).length > config.drawingMaxPayloadBytes) return { error: 'Drawing payload too large' };
  return { drawing };
}

function ensureInventory(session) {
  if (!session.inv || typeof session.inv !== 'object') session.inv = {};
  if (session.inv.carrierPigeon === undefined) session.inv.carrierPigeon = 0;
  return session;
}

function sendPigeon(sessionId, rawText, rawDrawing) {
  const session = repo.getSessionById(sessionId);
  if (!session) return { error: 'Invalid session' };
  try {
    if (new Date(session.expires) < new Date()) {
      repo.deleteSession(sessionId);
      return { error: 'Session expired' };
    }
  } catch (e) {
    return { error: 'Session expired' };
  }

  ensureInventory(session);
  if (session.inv.carrierPigeon <= 0) {
    return { error: 'No carrier pigeon in inventory' };
  }

  const hasRawDrawing = rawDrawing !== undefined && rawDrawing !== null;
  const mayDraw = supportsPigeonDrawing(session.client_version);
  if (hasRawDrawing && !mayDraw) {
    return { error: 'Client too old for picture messages' };
  }
  const dvalid = validateDrawing(mayDraw ? rawDrawing : null);
  if (dvalid.error) {
    return { error: dvalid.error };
  }
  const drawing = dvalid.drawing;

  const text = sanitizeMessage(rawText);
  if (!text && !drawing) {
    return { error: 'Message rejected (empty/invalid after sanitation)' };
  }

  const pigeon = {
    id: crypto.randomUUID(),
    text,
    drawing,
    from_session: sessionId,
    from_floor: session.floor || 0,
    from_level: session.level || 0,
    from_verified: !!session.verified,
    created: new Date().toISOString(),
  };
  return repo.storePigeon(pigeon);
}

function deliverPigeon(sessionId) {
  const session = repo.getSessionById(sessionId);
  if (!session) return { error: 'Invalid session' };
  try {
    if (new Date(session.expires) < new Date()) {
      repo.deleteSession(sessionId);
      return { error: 'Session expired' };
    }
  } catch (e) {
    return { error: 'Session expired' };
  }

  let deliveredMsg = repo.claimPigeonAtomically(
    session.floor || 0,
    sessionId,
    session.last_from_session_delivered || null,
  );

  if (deliveredMsg) {
    repo.updateSession(sessionId, {
      last_message_received_at: new Date().toISOString(),
      last_from_session_delivered: deliveredMsg.from_session,
    });
  }

  const remaining = repo.getDeliverablePigeonCount(sessionId);
  // Only hand back a drawing to recipients whose client can render one.
  const mayDraw = supportsPigeonDrawing(session.client_version);
  return {
    delivered: !!deliveredMsg,
    pigeon_message: deliveredMsg ? deliveredMsg.text : null,
    pigeon_id: deliveredMsg ? deliveredMsg.id : null,
    pigeon_drawing: (deliveredMsg && mayDraw && deliveredMsg.drawing) ? deliveredMsg.drawing : null,
    remaining_queue_pending: remaining,
  };
}

module.exports = { sanitizeMessage, validateDrawing, ensureInventory, sendPigeon, deliverPigeon };
