const crypto = require('node:crypto');
const config = require('../config');
const repo = require('../db/sqlite.repository');
const logger = require('../utils/logger');

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
  txt = txt.replace(config.allowedCharsPattern, '');
  if (txt.length > config.maxPigeonMessageLen) {
    txt = txt.slice(0, config.maxPigeonMessageLen);
  }
  txt = txt.trim();
  txt = txt.replace(/([!?*.])\1{2,}/g, '$1$1');
  if (txt.length < 3 || /^[.!?* ]+$/.test(txt)) return '';
  return txt;
}

function ensureInventory(session) {
  if (!session.inv || typeof session.inv !== 'object') session.inv = {};
  if (session.inv.carrierPigeon === undefined) session.inv.carrierPigeon = 0;
  return session;
}

function sendPigeon(sessionId, rawText) {
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

  const text = sanitizeMessage(rawText);
  if (!text) {
    return { error: 'Message rejected (empty/invalid after sanitation)' };
  }

  const pigeon = {
    id: crypto.randomUUID(),
    text,
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
  return {
    delivered: !!deliveredMsg,
    pigeon_message: deliveredMsg ? deliveredMsg.text : null,
    pigeon_id: deliveredMsg ? deliveredMsg.id : null,
    remaining_queue_pending: remaining,
  };
}

module.exports = { sanitizeMessage, ensureInventory, sendPigeon, deliverPigeon };
