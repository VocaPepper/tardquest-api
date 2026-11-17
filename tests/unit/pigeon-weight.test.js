const { expect } = require('chai');
const repo = require('../../src/db/sqlite.repository');
const config = require('../../src/config');

// C3 — pigeon delivery tuning is "verify, not fix": the weighted selection
// (floor proximity, high-floor priority, verified multiplier, age boost,
// repeat-sender penalty, jitter) is already implemented. These tests lock that
// each factor is applied exactly once with its configured multiplier, so the
// constants can be retuned later without the weighting logic silently regressing.
// Math.random is fixed during the ratio checks so jitter cancels out of ratios.
function baseMsg(over = {}) {
  return {
    from_floor: 0,
    from_verified: false,
    from_session: 'from-1',
    // slightly in the future -> ageBoost contribution is zero (fresh baseline)
    created: new Date(Date.now() + 60000).toISOString(),
    ...over,
  };
}
function baseRecipient(over = {}) {
  // far from from_floor 0 -> proximity factor is 1; no repeat-sender memory
  return { floor: 100, last_from_session_delivered: null, ...over };
}

function ratioWithFixedJitter(msgA, recA, msgB, recB) {
  const saved = Math.random;
  try {
    Math.random = () => 0; // jitter multiplier == randomJitterMin for both, cancels
    return repo.messageWeight(msgA, recA) / repo.messageWeight(msgB, recB);
  } finally {
    Math.random = saved;
  }
}

describe('Pigeon delivery weighting (unit)', () => {
  it('floors within proximity range boost weight, far floors do not', () => {
    const near = ratioWithFixedJitter(
      baseMsg(), baseRecipient({ floor: 0 }),     // delta 0
      baseMsg(), baseRecipient({ floor: 100 })    // delta 100 (> range)
    );
    const expected = 1 + 0.5 * (1 - 0 / (config.floorProximityRange + 1));
    expect(near).to.be.closeTo(expected, 1e-9);
  });

  it('higher from_floor is favored by the high-floor weight', () => {
    const F = 10;
    const ratio = ratioWithFixedJitter(
      baseMsg({ from_floor: F }), baseRecipient({ floor: 100 }),
      baseMsg({ from_floor: 0 }), baseRecipient({ floor: 100 })
    );
    expect(ratio).to.be.closeTo(1 + config.priorityHighFloorWeight * F, 1e-9);
  });

  it('applies the verified multiplier exactly once', () => {
    const ratio = ratioWithFixedJitter(
      baseMsg({ from_verified: true }), baseRecipient(),
      baseMsg({ from_verified: false }), baseRecipient()
    );
    expect(ratio).to.be.closeTo(config.priorityVerifiedMultiplier, 1e-9);
  });

  it('boosts an aged pigeon up to the configured cap', () => {
    const aged = new Date(Date.now() - (config.ageBoostFullSeconds * 1000 + 60000)).toISOString();
    const fresh = new Date(Date.now() + 60000).toISOString();
    const ratio = ratioWithFixedJitter(
      baseMsg({ created: aged }), baseRecipient(),
      baseMsg({ created: fresh }), baseRecipient()
    );
    expect(ratio).to.be.closeTo(1 + config.ageBoostMax, 1e-9);
  });

  it('penalizes a repeat sender by the configured penalty', () => {
    const ratio = ratioWithFixedJitter(
      baseMsg({ from_session: 'dup' }), baseRecipient({ last_from_session_delivered: 'dup' }),
      baseMsg({ from_session: 'dup' }), baseRecipient({ last_from_session_delivered: null })
    );
    expect(ratio).to.be.closeTo(config.repeatSenderPenalty, 1e-9);
  });

  it('jitter keeps the weight within the configured band', () => {
    const msg = baseMsg();
    const rec = baseRecipient();
    let min = Infinity;
    let max = -Infinity;
    for (let i = 0; i < 400; i++) {
      const w = repo.messageWeight(msg, rec); // all factors = 1, weight == jitter
      expect(w).to.be.at.least(config.randomJitterMin - 1e-9);
      expect(w).to.be.at.most(config.randomJitterMax + 1e-9);
      if (w < min) min = w;
      if (w > max) max = w;
    }
    expect(max).to.be.greaterThan(min); // actually varies
  });

  it('ageBoost is bounded in [0, ageBoostMax] and clamps malformed dates to 0', () => {
    expect(repo.ageBoost(new Date(Date.now() + 60000).toISOString())).to.equal(0);
    const old = new Date(Date.now() - 10 * 60000).toISOString();
    expect(repo.ageBoost(old)).to.be.at.most(config.ageBoostMax + 1e-9);
    expect(repo.ageBoost(old)).to.be.at.least(0);
    expect(repo.ageBoost('not-a-date')).to.equal(0);
  });

  it('messageWeight stays finite (never poisons selection) on corrupt inputs', () => {
    // A corrupted created date or non-numeric floor must not yield a NaN weight:
    // one NaN would make the summed totalWeight NaN and stall the whole draw.
    const withBadDate = repo.messageWeight(baseMsg({ created: 'garbage-date' }), baseRecipient());
    expect(Number.isFinite(withBadDate)).to.equal(true);
    expect(withBadDate).to.be.at.least(0);

    const withBadFloor = repo.messageWeight(baseMsg({ from_floor: 'not-a-number' }), baseRecipient({ floor: 'nope' }));
    expect(Number.isFinite(withBadFloor)).to.equal(true);
    expect(withBadFloor).to.equal(0);
  });
});
