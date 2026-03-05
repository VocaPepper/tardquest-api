# VocaGuard Anti-Cheat Module
# Provides modular anti-cheat validation for game progress updates
# Developers can use this module or implement their own validation logic

from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple, Optional
import hashlib
import math
import secrets


# ---------------------------------------------------------------------------
# Behavioral Fingerprinting
# ---------------------------------------------------------------------------

class BehaviorProfile:
    """Per-session accumulator for behavioral timing signals.

    Stores raw timestamps so that statistical features can be computed
    on-demand without needing the original request data.
    """
    __slots__ = ('update_ts', 'floor_enter_ts', 'levelup_ts', 'created_at')

    def __init__(self) -> None:
        self.update_ts: List[float] = []       # epoch of each /api/update
        self.floor_enter_ts: Dict[int, float] = {}  # floor -> epoch entered
        self.levelup_ts: List[float] = []      # epoch of each level-up
        self.created_at: float = datetime.utcnow().timestamp()


class BehavioralFingerprinter:
    """Detect bot-like behavior by analyzing timing patterns.

    All analysis is server-side only — no client cooperation required.
    Signals tracked:
      * Update-interval regularity  (bots send at fixed cadence)
      * Floor-completion-time uniformity  (bots clear each floor identically)
      * Level-up rhythm consistency  (bots level up mechanically)
      * Burst patterns  (scripted rapid-fire followed by silence)
    """

    # -- Tuning knobs -------------------------------------------------------
    # Minimum data points before behavioral analysis activates.
    MIN_UPDATE_SAMPLES = 6
    MIN_FLOOR_TRANSITIONS = 3

    # Coefficient-of-variation thresholds (stdev / mean).
    # Real humans typically show CV > 0.15; bots < 0.05.
    INTERVAL_CV_HARD = 0.05   # below → mechanical (score 1.0)
    INTERVAL_CV_SOFT = 0.10   # below → somewhat suspicious (score 0.5)
    FLOOR_TIME_CV_HARD = 0.08
    FLOOR_TIME_CV_SOFT = 0.12

    # Burst detection: flag if ≥60 % of intervals fall in the shortest 20 %
    # of the observed range — a sign of scripted rapid-fire.
    BURST_CLUSTER_RATIO = 0.60
    BURST_RANGE_FRACTION = 0.20

    # Overall suspicion score thresholds (0.0 = human, 1.0 = definite bot).
    SUSPICION_HARD_THRESHOLD = 0.75  # reject the update

    # Profile time-to-live — should be ≥ session timeout (default 2 h).
    PROFILE_TTL_SECONDS = 2 * 60 * 60

    def __init__(self) -> None:
        self._profiles: Dict[str, BehaviorProfile] = {}

    # -- Public API ---------------------------------------------------------

    def record_update(
        self,
        session_id: str,
        current_floor: int,
        current_level: int,
        new_floor: int,
        new_level: int,
    ) -> None:
        """Record a progress-update event for later analysis."""
        profile = self._profiles.get(session_id)
        if profile is None:
            profile = BehaviorProfile()
            self._profiles[session_id] = profile

        now = datetime.utcnow().timestamp()
        profile.update_ts.append(now)

        if new_floor > current_floor:
            profile.floor_enter_ts[new_floor] = now
            # Back-fill the starting floor if we haven't seen it yet
            if current_floor not in profile.floor_enter_ts:
                profile.floor_enter_ts[current_floor] = profile.created_at

        if new_level > current_level:
            profile.levelup_ts.append(now)

    def analyze(self, session_id: str) -> Tuple[float, Dict[str, Any]]:
        """Return *(suspicion_score, details)* for *session_id*.

        The score ranges from 0.0 (natural) to 1.0 (mechanical).
        *details* contains the contributing signal verdicts.
        """
        profile = self._profiles.get(session_id)
        if profile is None or len(profile.update_ts) < self.MIN_UPDATE_SAMPLES:
            return 0.0, {'reason': 'insufficient_data'}

        signals: List[float] = []
        details: Dict[str, Any] = {}

        # Signal 1 — update-interval regularity
        intervals = self._intervals(profile.update_ts)
        if len(intervals) >= 3:
            cv = self._cv(intervals)
            details['interval_cv'] = round(cv, 4)
            sig, verdict = self._score_cv(cv, self.INTERVAL_CV_HARD, self.INTERVAL_CV_SOFT)
            signals.append(sig)
            details['interval_verdict'] = verdict

        # Signal 2 — floor-completion-time uniformity
        floor_durs = self._floor_durations(profile)
        if len(floor_durs) >= self.MIN_FLOOR_TRANSITIONS:
            cv = self._cv(floor_durs)
            details['floor_time_cv'] = round(cv, 4)
            sig, verdict = self._score_cv(cv, self.FLOOR_TIME_CV_HARD, self.FLOOR_TIME_CV_SOFT)
            signals.append(sig)
            details['floor_verdict'] = verdict

        # Signal 3 — level-up rhythm
        if len(profile.levelup_ts) >= self.MIN_UPDATE_SAMPLES:
            lu_intervals = self._intervals(profile.levelup_ts)
            if len(lu_intervals) >= 3:
                cv = self._cv(lu_intervals)
                details['levelup_cv'] = round(cv, 4)
                sig, verdict = self._score_cv(cv, self.INTERVAL_CV_HARD, self.INTERVAL_CV_SOFT)
                signals.append(sig)
                details['levelup_verdict'] = verdict

        # Signal 4 — burst detection
        if len(intervals) >= 5:
            is_burst, burst_ratio = self._detect_burst(intervals)
            details['burst_ratio'] = round(burst_ratio, 4)
            if is_burst:
                signals.append(0.8)
                details['burst_verdict'] = 'scripted'
            else:
                signals.append(0.0)
                details['burst_verdict'] = 'natural'

        if not signals:
            return 0.0, details

        score = round(sum(signals) / len(signals), 4)
        details['score'] = score
        details['signal_count'] = len(signals)
        return score, details

    def cleanup_stale_profiles(self) -> int:
        """Remove profiles older than *PROFILE_TTL_SECONDS*."""
        cutoff = datetime.utcnow().timestamp() - self.PROFILE_TTL_SECONDS
        stale = [sid for sid, p in self._profiles.items() if p.created_at < cutoff]
        for sid in stale:
            del self._profiles[sid]
        return len(stale)

    def remove_profile(self, session_id: str) -> None:
        """Explicitly drop a session's profile (e.g. on session delete)."""
        self._profiles.pop(session_id, None)

    # -- Private helpers ----------------------------------------------------

    @staticmethod
    def _intervals(timestamps: List[float]) -> List[float]:
        return [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]

    @staticmethod
    def _cv(values: List[float]) -> float:
        """Coefficient of variation (σ / μ). Returns inf when < 2 samples."""
        n = len(values)
        if n < 2:
            return float('inf')
        mean = sum(values) / n
        if mean == 0:
            return 0.0
        variance = sum((v - mean) ** 2 for v in values) / n
        return math.sqrt(variance) / mean

    @staticmethod
    def _score_cv(cv: float, hard: float, soft: float) -> Tuple[float, str]:
        """Map a CV value to a (signal_score, verdict) pair."""
        if cv < hard:
            return 1.0, 'mechanical'
        if cv < soft:
            return 0.5, 'suspicious'
        return 0.0, 'natural'

    @staticmethod
    def _floor_durations(profile: BehaviorProfile) -> List[float]:
        sorted_floors = sorted(profile.floor_enter_ts.items())
        durations = []
        for i in range(1, len(sorted_floors)):
            dur = sorted_floors[i][1] - sorted_floors[i - 1][1]
            if dur > 0:
                durations.append(dur)
        return durations

    def _detect_burst(self, intervals: List[float]) -> Tuple[bool, float]:
        """Return *(is_burst, cluster_ratio)*."""
        if not intervals:
            return False, 0.0
        s = sorted(intervals)
        total_range = s[-1] - s[0]
        if total_range <= 0:
            return True, 1.0  # all identical → definite burst
        threshold = s[0] + total_range * self.BURST_RANGE_FRACTION
        clustered = sum(1 for v in s if v <= threshold)
        ratio = clustered / len(s)
        return ratio >= self.BURST_CLUSTER_RATIO, ratio


class VocaGuardValidator:
    """
    Anti-cheat validator for game progress.
    
    Detects and reports:
    - Floor regression (going backwards)
    - Level regression (going backwards on same floor)
    - Floor skips (jumping more than 1 floor)
    - Level jumps (jumping more than 1 level on same floor)
    - EXP validation (ensuring EXP matches level progression)
    - Level-up frequency abuse (max N level-ups per window)
    - Behavioral fingerprinting (timing-pattern anomaly detection)
    """
    
    # Minimum seconds between floor increments (prevents speed hacking)
    MIN_FLOOR_INCREMENT_SECONDS = 10
    # Proof-of-work challenge expiration in seconds
    POW_CHALLENGE_EXPIRY_SECONDS = 24 * 60 * 60  # 24 hours
    # Level-up frequency limits
    MAX_LEVELUPS_PER_MINUTE = 4
    LEVELUP_FREQUENCY_WINDOW_SECONDS = 60
    
    def __init__(self):
        """Initialize the validator."""
        # Store active challenges: {challenge_id: {session_id, secret, created_at}}
        self._active_challenges: Dict[str, Dict] = {}
        # Track level-up timestamps per session (epoch floats)
        self._levelup_history: Dict[str, List[float]] = {}
        # Behavioral fingerprinter
        self._fingerprinter = BehavioralFingerprinter()
    
    def validate_progress_update(
        self,
        current_floor: int,
        current_level: int,
        current_exp: int,
        new_floor: int,
        new_level: int,
        new_exp: int,
        session_id: str,
        last_floor_update: Optional[str] = None
    ) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Validate a progress update against anti-cheat rules.
        
        Args:
            current_floor: Current floor from database
            current_level: Current level from database
            current_exp: Current EXP from database
            new_floor: Attempted new floor
            new_level: Attempted new level
            new_exp: Attempted new EXP
            session_id: Session identifier for tracking level-up frequency
            last_floor_update: ISO format timestamp of last floor increment
        
        Returns:
            Tuple of (is_valid, error_message, abuse_details)
            - is_valid: True if update passes all checks
            - error_message: Human-readable error if invalid, None if valid
            - abuse_details: Dict with cheat detection info for logging, None if valid
        """
        
        # Check 1: Floor regression
        if new_floor < current_floor:
            return False, "Floor regression detected", {
                "cheat_type": "floor_regression",
                "current_floor": current_floor,
                "attempted_floor": new_floor
            }
        
        # Check 2: Level regression on same floor
        if new_floor == current_floor and new_level < current_level:
            return False, "Level regression detected on same floor", {
                "cheat_type": "level_regression",
                "current_level": current_level,
                "attempted_level": new_level
            }
        
        # Check 3: EXP regression
        if new_exp < current_exp:
            return False, "EXP regression detected", {
                "cheat_type": "exp_regression",
                "current_exp": current_exp,
                "attempted_exp": new_exp
            }
        
        # Check 4: Floor skip (can only advance 1 floor at a time)
        if new_floor > current_floor and new_floor - current_floor > 1:
            return False, "Abnormal floor jump detected", {
                "cheat_type": "floor_skip",
                "current_floor": current_floor,
                "attempted_floor": new_floor,
                "skip_distance": new_floor - current_floor
            }
        
        # Check 5: Level jump (can only advance 1 level at a time on same floor)
        if new_level > current_level and new_level - current_level > 1 and new_floor == current_floor:
            return False, "Abnormal level jump detected", {
                "cheat_type": "level_jump",
                "current_level": current_level,
                "attempted_level": new_level,
                "jump_distance": new_level - current_level
            }
        
        # Check 6: EXP validation for level progression
        # Each level costs incrementally more: Level 1>2 costs 10, Level 2>3 costs 20, etc.
        # Total EXP for level N = 10 + 20 + 30 + ... + (N-1)*10 = (N-1)*N/2 * 10
        required_exp_for_level = (new_level - 1) * new_level // 2 * 10
        
        # New EXP must be at least the required amount for the new level
        if new_exp < required_exp_for_level:
            return False, "Insufficient EXP for level", {
                "cheat_type": "exp_insufficient",
                "new_level": new_level,
                "required_exp": required_exp_for_level,
                "attempted_exp": new_exp
            }
        
        # Check 7: Floor speed hack (can't advance floor too quickly)
        if new_floor > current_floor:
            if last_floor_update:
                try:
                    last_update_dt = datetime.fromisoformat(last_floor_update)
                    time_since_last = (datetime.utcnow() - last_update_dt).total_seconds()
                    if time_since_last < self.MIN_FLOOR_INCREMENT_SECONDS:
                        return False, "Floor increment too fast!", {
                            "cheat_type": "floor_speed_hack",
                            "time_since_last_seconds": time_since_last,
                            "min_required_seconds": self.MIN_FLOOR_INCREMENT_SECONDS
                        }
                except (ValueError, TypeError):
                    # Invalid timestamp format, treat as valid (don't block)
                    pass
        
        # Check 8: Level-up frequency abuse
        if new_level > current_level:
            if session_id not in self._levelup_history:
                self._levelup_history[session_id] = []
            
            now = datetime.utcnow()
            now_ts = now.timestamp()
            
            # Remove old entries outside the time window
            cutoff_ts = (now - timedelta(seconds=self.LEVELUP_FREQUENCY_WINDOW_SECONDS)).timestamp()
            self._levelup_history[session_id] = [
                ts for ts in self._levelup_history[session_id] if ts > cutoff_ts
            ]
            
            if len(self._levelup_history[session_id]) >= self.MAX_LEVELUPS_PER_MINUTE:
                return False, "Level-up frequency limit exceeded", {
                    "cheat_type": "levelup_spam",
                    "levelups_in_window": len(self._levelup_history[session_id]),
                    "max_allowed": self.MAX_LEVELUPS_PER_MINUTE,
                    "window_seconds": self.LEVELUP_FREQUENCY_WINDOW_SECONDS
                }
            
            self._levelup_history[session_id].append(now_ts)
        
        # Check 9: Behavioral fingerprinting
        # Record timing data and analyze for bot-like patterns.
        self._fingerprinter.record_update(
            session_id, current_floor, current_level, new_floor, new_level
        )
        score, behavior_details = self._fingerprinter.analyze(session_id)
        if score >= BehavioralFingerprinter.SUSPICION_HARD_THRESHOLD:
            return False, "Unusual activity pattern detected", {
                "cheat_type": "behavioral_anomaly",
                "suspicion_score": score,
                **behavior_details
            }

        # All checks passed
        return True, None, None
    
    def validate_submission(
        self,
        session_floor: int,
        session_level: int,
        submitted_floor: int,
        submitted_level: int
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate a final submission before leaderboard post.
        
        Ensures that the submitted progress exactly matches the session's tracked progress.
        This prevents players from manually editing their scores after earning them.
        
        Args:
            session_floor: Floor value stored in the session
            session_level: Level value stored in the session
            submitted_floor: Floor value being submitted
            submitted_level: Level value being submitted
        
        Returns:
            Tuple of (is_valid, error_message)
            - is_valid: True if submission matches session progress
            - error_message: Human-readable error if invalid, None if valid
        """
        
        if session_floor != submitted_floor or session_level != submitted_level:
            return False, "Progress mismatch: submitted values don't match tracked session progress"
        
        return True, None
    
    def generate_challenge(self, session_id: str) -> Tuple[str, str]:
        """
        Generate a cryptographic challenge for a session.
        
        The challenge should be stored on the client and included in the final submission.
        This prevents offline modification of session data.
        
        Args:
            session_id: The session identifier
        
        Returns:
            Tuple of (challenge_id, challenge_secret)
            - challenge_id: Public identifier returned to client (include in submission)
            - challenge_secret: Server-side secret used to verify proof
        """
        challenge_id = secrets.token_hex(16)  # 32 character hex string
        challenge_secret = secrets.token_hex(32)  # 64 character hex string
        
        self._active_challenges[challenge_id] = {
            'session_id': session_id,
            'secret': challenge_secret,
            'created_at': datetime.utcnow().isoformat()
        }
        
        return challenge_id, challenge_secret
    
    def verify_challenge_proof(
        self,
        session_id: str,
        challenge_id: str,
        client_proof: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify that client has valid proof-of-work for their session.
        
        The client receives a secret and must compute SHA256(secret + session_id).
        By including this proof in submission, they prove they had the server-issued secret.
        
        Args:
            session_id: The session identifier
            challenge_id: The challenge identifier
            client_proof: The computed proof from client (SHA256 hex digest)
        
        Returns:
            Tuple of (is_valid, error_message)
            - is_valid: True if proof is valid and challenge not expired
            - error_message: Reason if invalid, None if valid
        """
        
        # Check if challenge exists
        if challenge_id not in self._active_challenges:
            return False, "Invalid or expired challenge ID"
        
        challenge_data = self._active_challenges[challenge_id]
        
        # Verify session ID matches
        if challenge_data['session_id'] != session_id:
            return False, "Challenge does not match session"
        
        # Check expiration
        try:
            created_at = datetime.fromisoformat(challenge_data['created_at'])
            age = (datetime.utcnow() - created_at).total_seconds()
            if age > self.POW_CHALLENGE_EXPIRY_SECONDS:
                # Clean up expired challenge
                del self._active_challenges[challenge_id]
                return False, "Challenge has expired"
        except (ValueError, TypeError):
            return False, "Invalid challenge timestamp"
        
        # Compute expected proof
        secret = challenge_data['secret']
        expected_proof = hashlib.sha256(
            (secret + session_id).encode('utf-8')
        ).hexdigest()
        
        # Verify proof matches (constant-time comparison to prevent timing attacks)
        is_valid = secrets.compare_digest(client_proof, expected_proof)
        
        if is_valid:
            # Clean up challenge after successful use
            del self._active_challenges[challenge_id]
            return True, None
        else:
            return False, "Proof-of-work verification failed"
    
    def cleanup_expired_challenges(self) -> int:
        """
        Remove expired challenges from memory.
        
        Should be called periodically by the application to prevent memory leaks.
        
        Returns:
            Number of challenges removed
        """
        expired_count = 0
        challenges_to_remove = []
        
        for challenge_id, challenge_data in self._active_challenges.items():
            try:
                created_at = datetime.fromisoformat(challenge_data['created_at'])
                age = (datetime.utcnow() - created_at).total_seconds()
                if age > self.POW_CHALLENGE_EXPIRY_SECONDS:
                    challenges_to_remove.append(challenge_id)
            except (ValueError, TypeError):
                # Invalid timestamp, remove it
                challenges_to_remove.append(challenge_id)
        
        for challenge_id in challenges_to_remove:
            del self._active_challenges[challenge_id]
            expired_count += 1
        
        # Also clean up stale behavioral profiles
        expired_count += self._fingerprinter.cleanup_stale_profiles()
        
        # Clean up levelup history for sessions with no recent activity
        levelup_cutoff = datetime.utcnow().timestamp() - BehavioralFingerprinter.PROFILE_TTL_SECONDS
        stale_sessions = [
            sid for sid, timestamps in self._levelup_history.items()
            if not timestamps or max(timestamps) < levelup_cutoff
        ]
        for sid in stale_sessions:
            del self._levelup_history[sid]
        expired_count += len(stale_sessions)
        
        return expired_count

    def get_behavior_score(self, session_id: str) -> Tuple[float, Dict]:
        """Return the current behavioral suspicion score for a session.

        Returns:
            (score, details) — score is 0.0–1.0, details explains signals.
        """
        return self._fingerprinter.analyze(session_id)

    def remove_behavior_profile(self, session_id: str) -> None:
        """Drop behavioral and timing data for a session (e.g. after deletion)."""
        self._fingerprinter.remove_profile(session_id)
        self._levelup_history.pop(session_id, None)


# Global validator instance
validator = VocaGuardValidator()
