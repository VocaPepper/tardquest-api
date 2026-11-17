const { expect } = require('chai');
const crypto = require('node:crypto');
const { VocaGuardValidator } = require('../../src/services/vocaguard.service');

// B1 — proof-of-work binding & single-use (regression for the closed issue #10
// intent). A challenge minted at /start must be (a) bound to the session that
// requested it, (b) consumed on first successful verification so a captured
// solved proof cannot be replayed, and (c) gated by the required difficulty.
function solve(sid, cid, salt, prefixZeros) {
  const prefix = '0'.repeat(prefixZeros);
  for (let nonce = 0; nonce < 2_000_000; nonce++) {
    const hash = crypto.createHash('sha256')
      .update(`${sid}:${cid}:${salt}:${nonce}`)
      .digest('hex');
    if (hash.startsWith(prefix)) return `${nonce}:${hash}`;
  }
  throw new Error('no nonce found for difficulty');
}

describe('VocaGuard proof-of-work (unit)', () => {
  let v;
  beforeEach(() => { v = new VocaGuardValidator(); });

  it('accepts a correctly solved challenge', () => {
    const sid = 'session-a';
    const { challengeId, challengeSalt } = v.generateChallenge(sid);
    const proof = solve(sid, challengeId, challengeSalt, 1);
    const res = v.verifyChallengeProof(sid, challengeId, proof, 1);
    expect(res.valid).to.equal(true);
    expect(res.error).to.equal(null);
  });

  it('binds a challenge to its session (rejects another session using it)', () => {
    const owner = 'session-owner';
    const attacker = 'session-attacker';
    const { challengeId, challengeSalt } = v.generateChallenge(owner);
    // Attacker solves using their OWN session id, which would not match the
    // server-computed hash; even supplying the owner's challengeId is refused.
    const proof = solve(owner, challengeId, challengeSalt, 1);
    const res = v.verifyChallengeProof(attacker, challengeId, proof, 1);
    expect(res.valid).to.equal(false);
    expect(res.error).to.equal('Challenge does not match session');
  });

  it('is single-use: a solved challenge cannot be verified twice', () => {
    const sid = 'session-once';
    const { challengeId, challengeSalt } = v.generateChallenge(sid);
    const proof = solve(sid, challengeId, challengeSalt, 1);

    const first = v.verifyChallengeProof(sid, challengeId, proof, 1);
    expect(first.valid).to.equal(true);

    const replay = v.verifyChallengeProof(sid, challengeId, proof, 1);
    expect(replay.valid).to.equal(false);
    expect(replay.error).to.equal('Invalid or expired challenge ID');
  });

  it('rejects a proof that meets the hash but not the required difficulty', () => {
    const sid = 'session-diff';
    const { challengeId, challengeSalt } = v.generateChallenge(sid);
    // Solve at difficulty 1, then demand 8 leading zeros.
    const proof = solve(sid, challengeId, challengeSalt, 1);
    const res = v.verifyChallengeProof(sid, challengeId, proof, 8);
    expect(res.valid).to.equal(false);
    expect(res.error).to.equal('Proof-of-work difficulty not met');
  });

  it('rejects a well-formed proof carrying a bogus hash', () => {
    const sid = 'session-bogus';
    const { challengeId, challengeSalt } = v.generateChallenge(sid);
    // Solve to obtain a valid nonce, then swap in a wrong hash.
    const proof = solve(sid, challengeId, challengeSalt, 1);
    const nonce = proof.split(':')[0];
    const res = v.verifyChallengeProof(sid, challengeId, `${nonce}:${'f'.repeat(64)}`, 1);
    expect(res.valid).to.equal(false);
    expect(res.error).to.equal('Proof-of-work verification failed');
  });

  it('rejects a missing proof value', () => {
    const sid = 'session-empty';
    const { challengeId } = v.generateChallenge(sid);
    const res = v.verifyChallengeProof(sid, challengeId, '', 1);
    expect(res.valid).to.equal(false);
    expect(res.error).to.equal('Proof-of-work value missing');
  });

  it('rejects an unknown challenge id', () => {
    const res = v.verifyChallengeProof('session-x', 'no-such-challenge', '1:' + '0'.repeat(64), 1);
    expect(res.valid).to.equal(false);
    expect(res.error).to.equal('Invalid or expired challenge ID');
  });
});
