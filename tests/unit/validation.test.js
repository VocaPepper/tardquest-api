const { expect } = require('chai');
const { parseVersion, parseInteger, versionGte, validateClientVersion } = require('../../src/utils/validation');

describe('validation utils', () => {
  describe('parseVersion', () => {
    it('parses valid version strings', () => {
      expect(parseVersion('1.2.3')).to.deep.equal({ major: 1, minor: 2, patch: 3 });
    });

    it('returns null for invalid versions', () => {
      expect(parseVersion('abc')).to.be.null;
      expect(parseVersion('1.2')).to.be.null;
      expect(parseVersion('1.2.3suffix')).to.be.null;
    });
  });

  describe('parseInteger', () => {
    it('accepts integers and rejects malformed values', () => {
      expect(parseInteger(12)).to.equal(12);
      expect(parseInteger('12')).to.equal(12);
      expect(parseInteger('12suffix')).to.be.null;
      expect(parseInteger(1.5)).to.be.null;
    });
  });

  describe('versionGte', () => {
    it('compares versions correctly', () => {
      const v1 = { major: 1, minor: 0, patch: 0 };
      const v2 = { major: 2, minor: 0, patch: 0 };
      expect(versionGte(v2, v1)).to.be.true;
      expect(versionGte(v1, v2)).to.be.false;
      expect(versionGte(v1, v1)).to.be.true;
    });
  });

  describe('validateClientVersion', () => {
    it('rejects too-old clients', () => {
      const result = validateClientVersion('1.0.0');
      expect(result.valid).to.be.false;
      expect(result.error).to.equal('Client version too old');
    });
  });
});
