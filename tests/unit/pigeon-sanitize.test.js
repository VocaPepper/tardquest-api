const { expect } = require('chai');
const { sanitizeMessage } = require('../../src/services/pigeon.service');
const config = require('../../src/config');

// B3 — pigeon message sanitation edge cases. sanitizeMessage is the gate that
// keeps player-authored text safe to relay; these pin its guarantees: HTML/entity/
// script-scheme stripping, invisible/control-character removal, the allowed-char
// whitelist, length truncation, repeated-punctuation collapse, and rejecting
// empty/short/punctuation-only output.
describe('Pigeon message sanitation (unit)', () => {
  it('strips HTML tags', () => {
    expect(sanitizeMessage('<script>alert(1)</script>hello')).to.equal('alert(1)hello');
  });

  it('strips numeric character entities', () => {
    expect(sanitizeMessage('hello&#x27;s')).to.equal('hellos');
  });

  it('strips named character entities and collapses the resulting gap', () => {
    expect(sanitizeMessage('rock &amp; roll')).to.equal('rock roll');
  });

  it('removes the javascript: scheme', () => {
    const out = sanitizeMessage('go javascript:nowhere');
    expect(out.toLowerCase()).to.not.include('javascript');
    expect(out).to.equal('go nowhere');
  });

  it('removes zero-width / BOM characters', () => {
    expect(sanitizeMessage('he\u200Bl\u200Flo')).to.equal('hello');
  });

  it('drops control characters', () => {
    expect(sanitizeMessage('abc\u0000def')).to.equal('abcdef');
  });

  it('removes disallowed characters', () => {
    const out = sanitizeMessage('hello😀world');
    expect(out).to.equal('helloworld');
    expect(out).to.not.include('😀');
  });

  it('removes disallowed characters in multiple separate runs', () => {
    // Regression: the whitelist pass must be global, not just the first run.
    const out = sanitizeMessage('a😀b😀😀c');
    expect(out).to.equal('abc');
    expect(out).to.not.include('😀');
  });

  it('removes the data:text/html scheme and nested tags', () => {
    const out = sanitizeMessage('see data:text/html,<b>x</b>');
    expect(out.toLowerCase()).to.not.include('data:text/html');
    expect(out).to.not.include('<');
    expect(out).to.equal('see ,x');
  });

  it('removes the vbscript: scheme', () => {
    const out = sanitizeMessage('go vbscript:x');
    expect(out.toLowerCase()).to.not.include('vbscript');
    expect(out).to.equal('go x');
  });

  it('leaves no live markup after double-encoded entities', () => {
    const out = sanitizeMessage('&amp;lt;img src&amp;gt;hi');
    expect(out).to.not.include('<');
    expect(out).to.not.include('>');
    expect(out).to.include('hi');
  });

  it('truncates to maxPigeonMessageLen', () => {
    const out = sanitizeMessage('a'.repeat(config.maxPigeonMessageLen + 80));
    expect(out.length).to.equal(config.maxPigeonMessageLen);
  });

  it('collapses runs of repeated punctuation', () => {
    expect(sanitizeMessage('hey....')).to.equal('hey..');
  });

  it('preserves ordinary text with allowed punctuation', () => {
    expect(sanitizeMessage('Status: ok (100%) #3')).to.equal('Status: ok (100%) #3');
  });

  it('rejects non-string input', () => {
    expect(sanitizeMessage(null)).to.equal('');
    expect(sanitizeMessage(42)).to.equal('');
    expect(sanitizeMessage(undefined)).to.equal('');
  });

  it('rejects output that is too short after sanitation', () => {
    expect(sanitizeMessage('hi')).to.equal('');
    expect(sanitizeMessage('ab😀')).to.equal('');
  });

  it('rejects punctuation-only messages', () => {
    expect(sanitizeMessage('!!!')).to.equal('');
    expect(sanitizeMessage('....')).to.equal('');
    expect(sanitizeMessage('?.?!')).to.equal('');
  });
});
