const fs = require('node:fs');
const path = require('node:path');
const config = require('../config');

const logDir = config.logDir;
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

function sanitize(val) {
  return String(val).replace(/\|/g, '_').replace(/\n/g, ' ').replace(/\r/g, ' ');
}

function isoNow() {
  return new Date().toISOString().replace('T', ' ').slice(0, 19);
}

function appendLog(filename, line) {
  try {
    const filepath = path.join(logDir, filename);
    fs.appendFileSync(filepath, line + '\n', 'utf-8');
  } catch (e) {
    console.error(`LOG ERROR [${filename}]:`, e.message);
  }
}

function logAccess(method, path, status, ip, ua, referer) {
  appendLog('access.log',
    `${isoNow()} ${sanitize(ip)} ${method} ${path} ${sanitize(ua)} ${status} ${sanitize(referer)}`
  );
}

function logVocaguardEvent(event) {
  try {
    const ts = isoNow();
    const ip = sanitize(event.ip || 'unknown');
    const metric = sanitize(event.metric || 'unknown');
    const parts = [ts, ip, metric];
    if (event.sid) parts.push(`sid=${sanitize(event.sid)}`);
    if (event.reason) parts.push(`reason=${sanitize(event.reason)}`);
    if (event.ua) parts.push(`ua=${sanitize(event.ua)}`);
    if (event.extra) {
      for (const [k, v] of Object.entries(event.extra)) {
        if (v !== null && v !== undefined) parts.push(`${sanitize(k)}=${sanitize(v)}`);
      }
    }
    if (event.data_excerpt) {
      for (const [k, v] of Object.entries(event.data_excerpt)) {
        if (v !== null && v !== undefined) parts.push(`${sanitize(k)}=${sanitize(v)}`);
      }
    }
    appendLog('vocaguard.log', parts.join('|'));
  } catch (e) {
    console.error('VOCAGUARD LOG ERROR:', e.message);
  }
}

const SENSITIVE_KEYS = /\b(password|token|secret|pepper|hash|authorization|apikey|api_key|key|session_id|code)\b/i;

function redactContextValue(key, value) {
  if (SENSITIVE_KEYS.test(key)) return '***REDACTED***';
  return String(value);
}

function logError(functionName, error, context) {
  try {
    const ts = isoNow();
    const errName = error.name || 'Error';
    const errMsg = error.message || String(error);
    const stack = (error.stack || '').replace(/\n/g, '\\n');
    let ctx = '';
    if (context) {
      ctx = ' ' + Object.entries(context).map(([k, v]) => `${k}=${redactContextValue(k, v)}`).join(' ');
    }
    appendLog('error.log', `${ts}|${functionName}|${errName}|${errMsg}|${stack}${ctx}`);
  } catch (e) {
    console.error('LOG ERROR FAILED:', e.message);
  }
}

function loadVocaguardEvents(windowSeconds) {
  const filepath = path.join(logDir, 'vocaguard.log');
  if (!fs.existsSync(filepath)) return [];
  const events = [];
  try {
    const now = Date.now() / 1000;
    const cutoff = now - windowSeconds;
    const lines = fs.readFileSync(filepath, 'utf-8').split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const parts = trimmed.split('|');
      if (parts.length < 3) continue;
      const ts = new Date(parts[0]).getTime() / 1000;
      if (isNaN(ts) || ts < cutoff) continue;
      const event = { ts, ip: parts[1], metric: parts[2] };
      for (let i = 3; i < parts.length; i++) {
        const eqIdx = parts[i].indexOf('=');
        if (eqIdx > 0) {
          event[parts[i].slice(0, eqIdx)] = parts[i].slice(eqIdx + 1);
        }
      }
      events.push(event);
    }
  } catch (e) {
    logError('loadVocaguardEvents', e);
  }
  return events;
}

module.exports = {
  logAccess,
  logVocaguardEvent,
  logError,
  loadVocaguardEvents,
};
