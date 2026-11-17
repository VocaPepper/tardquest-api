const { expect } = require('chai');
const { VocaGuardValidator } = require('../../src/services/vocaguard.service');

// B2 — anti-cheat progress validation. Each known cheat payload must be rejected
// by VocaGuard with the specific cheat_type the abuse pipeline keys on, and a
// legitimate progression must still pass. Uses the validator directly so the
// rules are exercised deterministically without HTTP/session scaffolding.
describe('VocaGuard progress validation (unit)', () => {
  let v;
  let sid;
  let n;
  beforeEach(() => {
    v = new VocaGuardValidator();
    sid = `prog-${process.pid}-${Date.now()}-${(n = (n || 0) + 1)}`;
  });

  function check(cur, next, lastFloorUpdate = null) {
    return v.validateProgressUpdate(
      cur.floor, cur.level, cur.exp,
      next.floor, next.level, next.exp,
      sid, lastFloorUpdate
    );
  }

  it('accepts a legitimate single-floor increment', () => {
    const res = check({ floor: 1, level: 1, exp: 0 }, { floor: 2, level: 1, exp: 10 });
    expect(res.valid).to.equal(true);
    expect(res.abuse).to.equal(null);
  });

  it('rejects floor regression', () => {
    const res = check({ floor: 5, level: 1, exp: 100 }, { floor: 4, level: 1, exp: 100 });
    expect(res.valid).to.equal(false);
    expect(res.error).to.equal('Floor regression detected');
    expect(res.abuse.cheat_type).to.equal('floor_regression');
  });

  it('rejects level regression on the same floor', () => {
    const res = check({ floor: 5, level: 10, exp: 1000 }, { floor: 5, level: 9, exp: 1000 });
    expect(res.valid).to.equal(false);
    expect(res.error).to.equal('Level regression detected on same floor');
    expect(res.abuse.cheat_type).to.equal('level_regression');
  });

  it('rejects EXP regression', () => {
    const res = check({ floor: 5, level: 10, exp: 100 }, { floor: 5, level: 10, exp: 90 });
    expect(res.valid).to.equal(false);
    expect(res.error).to.equal('EXP regression detected');
    expect(res.abuse.cheat_type).to.equal('exp_regression');
  });

  it('rejects a multi-floor skip', () => {
    const res = check({ floor: 5, level: 10, exp: 5000 }, { floor: 8, level: 10, exp: 5000 });
    expect(res.valid).to.equal(false);
    expect(res.error).to.equal('Abnormal floor jump detected');
    expect(res.abuse.cheat_type).to.equal('floor_skip');
    expect(res.abuse.skip_distance).to.equal(3);
  });

  it('rejects a multi-level jump on the same floor', () => {
    const res = check({ floor: 5, level: 10, exp: 5000 }, { floor: 5, level: 13, exp: 5000 });
    expect(res.valid).to.equal(false);
    expect(res.error).to.equal('Abnormal level jump detected');
    expect(res.abuse.cheat_type).to.equal('level_jump');
    expect(res.abuse.jump_distance).to.equal(3);
  });

  it('rejects insufficient EXP for the claimed level', () => {
    // Level 1 -> 2 requires ((2-1)*2/2)*10 = 10 EXP; supply none.
    const res = check({ floor: 5, level: 1, exp: 0 }, { floor: 5, level: 2, exp: 0 });
    expect(res.valid).to.equal(false);
    expect(res.error).to.equal('Insufficient EXP for level');
    expect(res.abuse.cheat_type).to.equal('exp_insufficient');
    expect(res.abuse.required_exp).to.equal(10);
  });

  it('rejects a floor increment that happens too quickly', () => {
    const justNow = new Date().toISOString();
    const res = check({ floor: 1, level: 1, exp: 0 }, { floor: 2, level: 1, exp: 10 }, justNow);
    expect(res.valid).to.equal(false);
    expect(res.error).to.equal('Floor increment too fast!');
    expect(res.abuse.cheat_type).to.equal('floor_speed_hack');
  });

  it('rejects level-up spam beyond the per-minute frequency limit', () => {
    // Drive five same-floor level-ups on one session inside the window; the
    // fifth must trip MAX_LEVELUPS_PER_MINUTE (4).
    let cur = { floor: 1, level: 1, exp: 0 };
    const results = [];
    for (let i = 0; i < 5; i++) {
      const next = { floor: 1, level: cur.level + 1, exp: cur.exp + 100000 };
      results.push(check(cur, next));
      cur = next;
    }
    results.slice(0, 4).forEach(r => expect(r.valid).to.equal(true));
    const fifth = results[4];
    expect(fifth.valid).to.equal(false);
    expect(fifth.error).to.equal('Level-up frequency limit exceeded');
    expect(fifth.abuse.cheat_type).to.equal('levelup_spam');
  });
});
