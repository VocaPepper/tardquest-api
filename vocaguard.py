# VocaGuard Anti-Cheat Module
# Provides modular anti-cheat validation for game progress updates
# Developers can use this module or implement their own validation logic

from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional
import hashlib
import secrets


class VocaGuardValidator:
    """
    Anti-cheat validator for game progress.
    
    Detects and reports:
    - Floor regression (level going backwards)
    - Level regression (level going backwards on same floor)
    - Floor skips (jumping more than 1 floor)
    - Level jumps (jumping more than 1 level on same floor)
    - EXP validation (ensuring EXP matches level progression)
    - Level-up frequency abuse (max 10 level-ups per 60 seconds)
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
        # Track level-up history per session: {session_id: [timestamps]}
        self._levelup_history: Dict[str, list] = {}
    
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
        
        # Check 8: Level-up frequency abuse (max 10 level-ups per 60 seconds)
        if new_level > current_level:
            # Initialize session history if needed
            if session_id not in self._levelup_history:
                self._levelup_history[session_id] = []
            
            # Get current time
            now = datetime.utcnow()
            history = self._levelup_history[session_id]
            
            # Remove old entries outside the time window
            cutoff_time = now - timedelta(seconds=self.LEVELUP_FREQUENCY_WINDOW_SECONDS)
            self._levelup_history[session_id] = [
                ts for ts in history if datetime.fromisoformat(ts) > cutoff_time
            ]
            
            # Check if we've hit the limit
            if len(self._levelup_history[session_id]) >= self.MAX_LEVELUPS_PER_MINUTE:
                return False, "Level-up frequency limit exceeded", {
                    "cheat_type": "levelup_spam",
                    "levelups_in_last_60s": len(self._levelup_history[session_id]),
                    "max_allowed": self.MAX_LEVELUPS_PER_MINUTE
                }
            
            # Record this level-up
            self._levelup_history[session_id].append(now.isoformat())
        
        # All checks passed
        return True, None, None
    
    def get_timestamp_now(self) -> str:
        """
        Get current UTC timestamp in ISO format.
        
        Returns:
            ISO format timestamp string
        """
        return datetime.utcnow().isoformat()
    
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
        
        return expired_count


# Global validator instance
validator = VocaGuardValidator()
