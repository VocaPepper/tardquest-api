const repo = require('../db/sqlite.repository');
const postgres = require('../db/postgres');
const config = require('../config');
const logger = require('../utils/logger');

function cleanHtml(val) {
  if (typeof val !== 'string') return val;
  let result = val.normalize('NFC');
  result = result.replace(/&#x?[0-9a-fA-F]+;?/g, '');
  result = result.replace(/&(?:[a-zA-Z]+|#x?[0-9a-fA-F]+);?/g, '');
  result = [...result].filter(ch => {
    const cp = ch.codePointAt(0);
    if (cp === 0x200B || cp === 0x200C || cp === 0x200D || cp === 0xFEFF ||
        cp === 0x200E || cp === 0x200F || cp === 0x2028 || cp === 0x2029) return false;
    return true;
  }).join('');
  result = result.replace(/<.*?>/g, '');
  result = result.replace(/(script|meta|iframe|onerror|onload|javascript:|vbscript:|data\s*:|http-equiv|src|href|alert|document|window)/gi, '');
  result = result.trim();
  result = result.replace(/[^A-Za-z0-9_ ]/g, '');
  return result;
}

function cleanJson(obj) {
  if (Array.isArray(obj)) return obj.map(cleanJson);
  if (obj && typeof obj === 'object') {
    const result = {};
    for (const [k, v] of Object.entries(obj)) {
      result[k] = k === 'name' ? cleanHtml(v) : cleanJson(v);
    }
    return result;
  }
  return obj;
}

function getLeaderboard() {
  const data = repo.getLeaderboard();
  const cleaned = cleanJson(data);
  if (Array.isArray(cleaned)) {
    for (const entry of cleaned) {
      if (entry && entry.name) {
        entry.name = entry.name.toUpperCase();
      }
    }
  }
  return cleaned;
}

async function submitScore(session, name, floor, level) {
  const accountUsername = session.username || null;

  let filteredName;
  if (accountUsername) {
    filteredName = accountUsername.replace(/[^A-Za-z0-9_ ]/g, '').slice(0, config.maxAccountLeaderboardNameLength);
  } else {
    filteredName = name ? cleanHtml(name).trim() : '';
    if (!filteredName) return { error: 'Name is required and must be valid' };
    if (/[^A-Za-z0-9 ]/.test(filteredName)) return { error: 'Name contains invalid characters' };
    if (filteredName.length > config.maxLeaderboardNameLength) {
      return { error: `Name must be at most ${config.maxLeaderboardNameLength} characters` };
    }
    const { exists } = await postgres.usernameExists(filteredName);
    if (exists) return { error: 'This name is reserved by a registered account' };
  }

  const result = repo.submitLeaderboardEntry(filteredName, floor, level);
  if (!result) return { error: 'Internal server error' };
  return { data: result };
}

function removeAccountEntry(username) {
  if (!username) return { error: 'Username required' };
  const cleaned = username.replace(/[^A-Za-z0-9_ ]/g, '').toUpperCase();
  if (!cleaned) return { error: 'Invalid username' };
  const removed = repo.deleteLeaderboardEntryByName(cleaned);
  return removed ? { removed: true } : { removed: false };
}

module.exports = { getLeaderboard, submitScore, removeAccountEntry, cleanHtml, cleanJson };
