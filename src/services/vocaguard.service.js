const crypto = require('node:crypto');
const config = require('../config');

class BehaviorProfile {
  constructor() {
    this.updateTs = [];
    this.floorEnterTs = {};
    this.levelupTs = [];
    this.createdAt = Date.now() / 1000;
  }
}

class BehavioralFingerprinter {
  constructor() {
    this._profiles = new Map();
    this.MIN_UPDATE_SAMPLES = 6;
    this.MIN_FLOOR_TRANSITIONS = 3;
    this.INTERVAL_CV_HARD = 0.05;
    this.INTERVAL_CV_SOFT = 0.10;
    this.FLOOR_TIME_CV_HARD = 0.08;
    this.FLOOR_TIME_CV_SOFT = 0.12;
    this.BURST_CLUSTER_RATIO = 0.60;
    this.BURST_RANGE_FRACTION = 0.20;
    this.SUSPICION_HARD_THRESHOLD = 0.75;
    this.PROFILE_TTL_SECONDS = 2 * 60 * 60;
  }

  recordUpdate(sessionId, currentFloor, currentLevel, newFloor, newLevel) {
    let profile = this._profiles.get(sessionId);
    if (!profile) {
      profile = new BehaviorProfile();
      this._profiles.set(sessionId, profile);
    }
    const now = Date.now() / 1000;
    profile.updateTs.push(now);
    if (newFloor > currentFloor) {
      profile.floorEnterTs[newFloor] = now;
      if (!(currentFloor in profile.floorEnterTs)) {
        profile.floorEnterTs[currentFloor] = profile.createdAt;
      }
    }
    if (newLevel > currentLevel) {
      profile.levelupTs.push(now);
    }
  }

  analyze(sessionId) {
    const profile = this._profiles.get(sessionId);
    if (!profile || profile.updateTs.length < this.MIN_UPDATE_SAMPLES) {
      return { score: 0, details: { reason: 'insufficient_data' } };
    }

    const signals = [];
    const details = {};

    const intervals = this._intervals(profile.updateTs);
    if (intervals.length >= 3) {
      const cv = this._cv(intervals);
      details.interval_cv = Math.round(cv * 10000) / 10000;
      const { score: sig, verdict } = this._scoreCv(cv, this.INTERVAL_CV_HARD, this.INTERVAL_CV_SOFT);
      signals.push(sig);
      details.interval_verdict = verdict;
    }

    const floorDurs = this._floorDurations(profile);
    if (floorDurs.length >= this.MIN_FLOOR_TRANSITIONS) {
      const cv = this._cv(floorDurs);
      details.floor_time_cv = Math.round(cv * 10000) / 10000;
      const { score: sig, verdict } = this._scoreCv(cv, this.FLOOR_TIME_CV_HARD, this.FLOOR_TIME_CV_SOFT);
      signals.push(sig);
      details.floor_verdict = verdict;
    }

    if (profile.levelupTs.length >= this.MIN_UPDATE_SAMPLES) {
      const luIntervals = this._intervals(profile.levelupTs);
      if (luIntervals.length >= 3) {
        const cv = this._cv(luIntervals);
        details.levelup_cv = Math.round(cv * 10000) / 10000;
        const { score: sig, verdict } = this._scoreCv(cv, this.INTERVAL_CV_HARD, this.INTERVAL_CV_SOFT);
        signals.push(sig);
        details.levelup_verdict = verdict;
      }
    }

    if (intervals.length >= 5) {
      const { isBurst, ratio } = this._detectBurst(intervals);
      details.burst_ratio = Math.round(ratio * 10000) / 10000;
      if (isBurst) {
        signals.push(0.8);
        details.burst_verdict = 'scripted';
      } else {
        signals.push(0.0);
        details.burst_verdict = 'natural';
      }
    }

    if (signals.length === 0) {
      return { score: 0, details };
    }

    const score = Math.round((signals.reduce((a, b) => a + b, 0) / signals.length) * 10000) / 10000;
    details.score = score;
    details.signal_count = signals.length;
    return { score, details };
  }

  cleanupStale() {
    const cutoff = Date.now() / 1000 - this.PROFILE_TTL_SECONDS;
    let count = 0;
    for (const [sid, profile] of this._profiles) {
      if (profile.createdAt < cutoff) {
        this._profiles.delete(sid);
        count++;
      }
    }
    return count;
  }

  removeProfile(sessionId) {
    this._profiles.delete(sessionId);
  }

  _intervals(timestamps) {
    const result = [];
    for (let i = 1; i < timestamps.length; i++) {
      result.push(timestamps[i] - timestamps[i - 1]);
    }
    return result;
  }

  _cv(values) {
    if (values.length < 2) return Infinity;
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    if (mean === 0) return 0;
    const variance = values.reduce((sum, v) => sum + (v - mean) ** 2, 0) / values.length;
    return Math.sqrt(variance) / mean;
  }

  _scoreCv(cv, hard, soft) {
    if (cv < hard) return { score: 1.0, verdict: 'mechanical' };
    if (cv < soft) return { score: 0.5, verdict: 'suspicious' };
    return { score: 0.0, verdict: 'natural' };
  }

  _floorDurations(profile) {
    const sorted = Object.entries(profile.floorEnterTs).sort((a, b) => a[0] - b[0]);
    const durations = [];
    for (let i = 1; i < sorted.length; i++) {
      const dur = sorted[i][1] - sorted[i - 1][1];
      if (dur > 0) durations.push(dur);
    }
    return durations;
  }

  _detectBurst(intervals) {
    if (intervals.length === 0) return { isBurst: false, ratio: 0 };
    const sorted = [...intervals].sort((a, b) => a - b);
    const totalRange = sorted[sorted.length - 1] - sorted[0];
    if (totalRange <= 0) return { isBurst: true, ratio: 1.0 };
    const threshold = sorted[0] + totalRange * this.BURST_RANGE_FRACTION;
    const clustered = sorted.filter(v => v <= threshold).length;
    const ratio = clustered / sorted.length;
    return { isBurst: ratio >= this.BURST_CLUSTER_RATIO, ratio };
  }
}

class VocaGuardValidator {
  constructor() {
    this._activeChallenges = new Map();
    this._levelupHistory = new Map();
    this._fingerprinter = new BehavioralFingerprinter();

    this.MIN_FLOOR_INCREMENT_SECONDS = 10;
    this.POW_CHALLENGE_EXPIRY_SECONDS = 24 * 60 * 60;
    this.MAX_LEVELUPS_PER_MINUTE = 4;
    this.LEVELUP_FREQUENCY_WINDOW_SECONDS = 60;
  }

  validateProgressUpdate(currentFloor, currentLevel, currentExp, newFloor, newLevel, newExp, sessionId, lastFloorUpdate) {
    if (newFloor < currentFloor) {
      return { valid: false, error: 'Floor regression detected', abuse: { cheat_type: 'floor_regression', current_floor: currentFloor, attempted_floor: newFloor } };
    }
    if (newFloor === currentFloor && newLevel < currentLevel) {
      return { valid: false, error: 'Level regression detected on same floor', abuse: { cheat_type: 'level_regression', current_level: currentLevel, attempted_level: newLevel } };
    }
    if (newExp < currentExp) {
      return { valid: false, error: 'EXP regression detected', abuse: { cheat_type: 'exp_regression', current_exp: currentExp, attempted_exp: newExp } };
    }
    if (newFloor > currentFloor && newFloor - currentFloor > 1) {
      return { valid: false, error: 'Abnormal floor jump detected', abuse: { cheat_type: 'floor_skip', current_floor: currentFloor, attempted_floor: newFloor, skip_distance: newFloor - currentFloor } };
    }
    if (newLevel > currentLevel && newLevel - currentLevel > 1 && newFloor === currentFloor) {
      return { valid: false, error: 'Abnormal level jump detected', abuse: { cheat_type: 'level_jump', current_level: currentLevel, attempted_level: newLevel, jump_distance: newLevel - currentLevel } };
    }

    const requiredExp = ((newLevel - 1) * newLevel / 2) * 10;
    if (newExp < requiredExp) {
      return { valid: false, error: 'Insufficient EXP for level', abuse: { cheat_type: 'exp_insufficient', new_level: newLevel, required_exp: requiredExp, attempted_exp: newExp } };
    }

    if (newFloor > currentFloor && lastFloorUpdate) {
      try {
        const timeSinceLast = (Date.now() - new Date(lastFloorUpdate).getTime()) / 1000;
        if (timeSinceLast < this.MIN_FLOOR_INCREMENT_SECONDS) {
          return { valid: false, error: 'Floor increment too fast!', abuse: { cheat_type: 'floor_speed_hack', time_since_last_seconds: timeSinceLast, min_required_seconds: this.MIN_FLOOR_INCREMENT_SECONDS } };
        }
      } catch (e) { }
    }

    if (newLevel > currentLevel) {
      if (!this._levelupHistory.has(sessionId)) {
        this._levelupHistory.set(sessionId, []);
      }
      const now = Date.now() / 1000;
      const cutoff = now - this.LEVELUP_FREQUENCY_WINDOW_SECONDS;
      const history = this._levelupHistory.get(sessionId).filter(ts => ts > cutoff);
      if (history.length >= this.MAX_LEVELUPS_PER_MINUTE) {
        return { valid: false, error: 'Level-up frequency limit exceeded', abuse: { cheat_type: 'levelup_spam', levelups_in_window: history.length, max_allowed: this.MAX_LEVELUPS_PER_MINUTE, window_seconds: this.LEVELUP_FREQUENCY_WINDOW_SECONDS } };
      }
      history.push(now);
      this._levelupHistory.set(sessionId, history);
    }

    this._fingerprinter.recordUpdate(sessionId, currentFloor, currentLevel, newFloor, newLevel);
    const { score, details } = this._fingerprinter.analyze(sessionId);
    if (score >= this._fingerprinter.SUSPICION_HARD_THRESHOLD) {
      return { valid: false, error: 'Unusual activity pattern detected', abuse: { cheat_type: 'behavioral_anomaly', suspicion_score: score, ...details } };
    }

    return { valid: true, error: null, abuse: null };
  }

  validateSubmission(sessionFloor, sessionLevel, submittedFloor, submittedLevel) {
    if (sessionFloor !== submittedFloor || sessionLevel !== submittedLevel) {
      return { valid: false, error: "Progress mismatch: submitted values don't match tracked session progress" };
    }
    return { valid: true, error: null };
  }

  generateChallenge(sessionId) {
    const challengeId = crypto.randomBytes(16).toString('hex');
    const challengeSalt = crypto.randomBytes(32).toString('hex');
    this._activeChallenges.set(challengeId, {
      sessionId,
      secret: challengeSalt,
      createdAt: new Date().toISOString(),
    });
    return { challengeId, challengeSalt };
  }

  verifyChallengeProof(sessionId, challengeId, clientProof, difficulty) {
    const challengeData = this._activeChallenges.get(challengeId);
    if (!challengeData) {
      return { valid: false, error: 'Invalid or expired challenge ID' };
    }
    if (challengeData.sessionId !== sessionId) {
      return { valid: false, error: 'Challenge does not match session' };
    }
    try {
      const age = (Date.now() - new Date(challengeData.createdAt).getTime()) / 1000;
      if (age > this.POW_CHALLENGE_EXPIRY_SECONDS) {
        this._activeChallenges.delete(challengeId);
        return { valid: false, error: 'Challenge has expired' };
      }
    } catch (e) {
      return { valid: false, error: 'Invalid challenge timestamp' };
    }

    const proof = (clientProof || '').trim().toLowerCase();
    if (!proof) {
      return { valid: false, error: 'Proof-of-work value missing' };
    }

    const requiredPrefix = '0'.repeat(Math.max(1, difficulty || config.powDifficultyPrefixZeros));

    if (proof.includes(':')) {
      const colonIdx = proof.indexOf(':');
      const nonce = proof.slice(0, colonIdx);
      const submittedHash = proof.slice(colonIdx + 1);
      if (!nonce || submittedHash.length !== 64) {
        return { valid: false, error: 'Invalid proof format' };
      }
      const expectedHash = crypto.createHash('sha256')
        .update(`${sessionId}:${challengeId}:${challengeData.secret}:${nonce}`)
        .digest('hex');

      if (!crypto.timingSafeEqual(Buffer.from(submittedHash), Buffer.from(expectedHash))) {
        return { valid: false, error: 'Proof-of-work verification failed' };
      }
      if (!submittedHash.startsWith(requiredPrefix)) {
        return { valid: false, error: 'Proof-of-work difficulty not met' };
      }
      this._activeChallenges.delete(challengeId);
      return { valid: true, error: null };
    }

    return { valid: false, error: 'Invalid proof format (nonce:hash required)' };
  }

  refreshChallengeForSession(sessionId) {
    if (!sessionId) return false;
    let newestChallengeId = null;
    let newestCreatedAt = null;

    for (const [cid, data] of this._activeChallenges) {
      if (data.sessionId !== sessionId) continue;
      try {
        const createdAt = new Date(data.createdAt).getTime();
        if (!newestCreatedAt || createdAt > newestCreatedAt) {
          newestCreatedAt = createdAt;
          newestChallengeId = cid;
        }
      } catch (e) { }
    }

    if (!newestChallengeId) return false;
    this._activeChallenges.get(newestChallengeId).createdAt = new Date().toISOString();
    return true;
  }

  cleanupExpired() {
    let count = 0;
    const now = Date.now();
    for (const [cid, data] of this._activeChallenges) {
      try {
        const age = (now - new Date(data.createdAt).getTime()) / 1000;
        if (age > this.POW_CHALLENGE_EXPIRY_SECONDS) {
          this._activeChallenges.delete(cid);
          count++;
        }
      } catch (e) {
        this._activeChallenges.delete(cid);
        count++;
      }
    }

    count += this._fingerprinter.cleanupStale();

    const levelupCutoff = Date.now() / 1000 - this._fingerprinter.PROFILE_TTL_SECONDS;
    for (const [sid, timestamps] of this._levelupHistory) {
      if (timestamps.length === 0 || Math.max(...timestamps) < levelupCutoff) {
        this._levelupHistory.delete(sid);
        count++;
      }
    }

    return count;
  }

  getBehaviorScore(sessionId) {
    return this._fingerprinter.analyze(sessionId);
  }

  removeBehaviorProfile(sessionId) {
    this._fingerprinter.removeProfile(sessionId);
    this._levelupHistory.delete(sessionId);
  }
}

const validator = new VocaGuardValidator();

module.exports = { VocaGuardValidator, validator, BehavioralFingerprinter };
