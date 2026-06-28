const { expect } = require('chai');
const { VocaGuardValidator, BehavioralFingerprinter } = require('../../src/services/vocaguard.service');

describe('BehavioralFingerprinter', () => {
  it('returns insufficient_data for empty profiles', () => {
    const fp = new BehavioralFingerprinter();
    const { score, details } = fp.analyze('nonexistent');
    expect(score).to.equal(0);
    expect(details.reason).to.equal('insufficient_data');
  });

  it('detects mechanical intervals', () => {
    const fp = new BehavioralFingerprinter();
    const sid = 'test-session';
    for (let i = 0; i < 10; i++) {
      fp.recordUpdate(sid, i, 1, i + 1, 1);
    }
    const { score } = fp.analyze(sid);
    expect(score).to.be.greaterThan(0);
  });
});

describe('VocaGuardValidator', () => {
  let validator;

  beforeEach(() => {
    validator = new VocaGuardValidator();
  });

  describe('validateProgressUpdate', () => {
    it('rejects floor regression', () => {
      const result = validator.validateProgressUpdate(5, 1, 0, 3, 1, 0, 's1', null);
      expect(result.valid).to.be.false;
      expect(result.error).to.include('regression');
    });

    it('rejects level regression on same floor', () => {
      const result = validator.validateProgressUpdate(5, 5, 100, 5, 3, 100, 's1', null);
      expect(result.valid).to.be.false;
      expect(result.error).to.include('regression');
    });

    it('rejects EXP regression', () => {
      const result = validator.validateProgressUpdate(1, 1, 100, 1, 1, 50, 's1', null);
      expect(result.valid).to.be.false;
      expect(result.error).to.include('regression');
    });

    it('rejects floor skips > 1', () => {
      const result = validator.validateProgressUpdate(1, 1, 0, 3, 1, 0, 's1', null);
      expect(result.valid).to.be.false;
      expect(result.error).to.include('jump');
    });

    it('rejects level jumps > 1 on same floor', () => {
      const result = validator.validateProgressUpdate(1, 1, 0, 1, 3, 0, 's1', null);
      expect(result.valid).to.be.false;
      expect(result.error).to.include('jump');
    });

    it('rejects insufficient EXP for level', () => {
      const result = validator.validateProgressUpdate(1, 1, 0, 1, 2, 5, 's1', null);
      expect(result.valid).to.be.false;
      expect(result.error).to.include('EXP');
    });

    it('accepts valid progress', () => {
      const result = validator.validateProgressUpdate(1, 1, 0, 1, 2, 30, 's1', null);
      expect(result.valid).to.be.true;
    });
  });

  describe('validateSubmission', () => {
    it('passes when values match', () => {
      const result = validator.validateSubmission(5, 10, 5, 10);
      expect(result.valid).to.be.true;
    });

    it('fails when values mismatch', () => {
      const result = validator.validateSubmission(5, 10, 6, 11);
      expect(result.valid).to.be.false;
    });
  });

  describe('Proof of Work', () => {
    it('generates and verifies a challenge', () => {
      const { challengeId, challengeSalt } = validator.generateChallenge('session-1');
      expect(challengeId).to.be.a('string').with.lengthOf(32);
      expect(challengeSalt).to.be.a('string').with.lengthOf(64);

      const proof = require('node:crypto').createHash('sha256')
        .update(`session-1:${challengeId}:${challengeSalt}:testnonce`)
        .digest('hex');
      const clientProof = `testnonce:${proof}`;

      const result = validator.verifyChallengeProof('session-1', challengeId, clientProof, 0);
      expect(result.valid).to.be.false;
      expect(result.error).to.include('difficulty');
    });

    it('rejects expired challenges', () => {
      const { challengeId } = validator.generateChallenge('session-1');
      validator._activeChallenges.get(challengeId).createdAt = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString();
      const result = validator.verifyChallengeProof('session-1', challengeId, 'nonce:hash', 0);
      expect(result.valid).to.be.false;
      expect(result.error).to.include('expired');
    });
  });

  describe('cleanupExpired', () => {
    it('cleans up expired challenges and stale profiles', () => {
      const { challengeId } = validator.generateChallenge('session-stale');
      validator._activeChallenges.get(challengeId).createdAt = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString();
      const count = validator.cleanupExpired();
      expect(count).to.be.greaterThan(0);
    });
  });
});
