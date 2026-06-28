const { expect } = require('chai');
const { sanitizeMessage, ensureInventory } = require('../../src/services/pigeon.service');

describe('pigeon.service', () => {
  describe('sanitizeMessage', () => {
    it('strips HTML tags', () => {
      expect(sanitizeMessage('<script>alert("xss")</script>hello')).to.equal('alert("xss")hello');
    });

    it('enforces max length', () => {
      const long = 'a'.repeat(500);
      const result = sanitizeMessage(long);
      expect(result.length).to.be.at.most(420);
    });

    it('removes disallowed characters', () => {
      const result = sanitizeMessage('hello 🔥 world');
      expect(result).to.not.include('🔥');
    });

    it('returns empty for very short messages', () => {
      expect(sanitizeMessage('ab')).to.equal('');
    });

    it('collapses repeated punctuation', () => {
      const result = sanitizeMessage('hello!!!!!');
      expect(result).to.equal('hello!!');
    });
  });

  describe('ensureInventory', () => {
    it('adds default inventory when missing', () => {
      const session = {};
      ensureInventory(session);
      expect(session.inv).to.deep.equal({ carrierPigeon: 0 });
    });

    it('preserves existing inventory', () => {
      const session = { inv: { carrierPigeon: 5, other: true } };
      ensureInventory(session);
      expect(session.inv.carrierPigeon).to.equal(5);
    });
  });
});
