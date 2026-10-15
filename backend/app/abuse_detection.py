"""
Security abuse detection module.

Implements detection for BOLA, scraping, and token replay misuse patterns.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Set, Tuple
import hashlib


def _cutoff_time(max_age_hours: int) -> datetime:
    """Calculate cutoff time for pruning old records."""
    return datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=max_age_hours)


class BOLADetector:
    """Detects Broken Object-Level Authorization (BOLA) vulnerabilities.

    BOLA occurs when a user accesses objects they're not authorized for.
    This detector uses explicit authorization context rather than assuming
    every different user ID indicates an attack.
    """

    def detect(
        self,
        user_id: str,
        resource_id: str,
        authorized_resource_ids: Set[str]
    ) -> Tuple[bool, str]:
        """Detect unauthorized access attempt.

        Args:
            user_id: The user making the request.
            resource_id: The resource being accessed.
            authorized_resource_ids: Set of resources this user is authorized to access.

        Returns:
            (is_bola: bool, reason: str)
        """
        if resource_id not in authorized_resource_ids:
            return True, f"User {user_id} accessed unauthorized resource {resource_id}"
        return False, ""


class ScrapingDetector:
    """Detects scraping patterns based on request rate and object diversity.

    Scraping is detected when:
    - Request rate exceeds threshold in time window, OR
    - Number of distinct objects accessed exceeds threshold
    """

    def __init__(self):
        self.request_history: Dict[str, List[Tuple[str, datetime]]] = defaultdict(list)

    def record_request(self, user_id: str, object_id: str, timestamp: datetime):
        """Record a request for tracking.

        Args:
            user_id: The user making the request.
            object_id: The object being requested.
            timestamp: When the request occurred.
        """
        self.request_history[user_id].append((object_id, timestamp))

    def detect(
        self,
        user_id: str,
        time_window_seconds: int = 60,
        rate_threshold: int = 10,
        distinct_threshold: int = 20,
        min_distinct_for_rate: int = 1,
    ) -> Tuple[bool, str]:
        """Detect scraping behavior.

        Args:
            user_id: The user to check.
            time_window_seconds: Time window for rate analysis (default 60s).
            rate_threshold: Max requests per time window (default 10).
            distinct_threshold: Max distinct objects per time window (default 20).
            min_distinct_for_rate: The rate rule only fires when at least this
                many distinct objects were requested, so a client refreshing
                the same few resources is not "scraping" (default 1 = off).

        Returns:
            (is_scraping: bool, reason: str)
        """
        if user_id not in self.request_history:
            return False, ""

        requests = self.request_history[user_id]
        if not requests:
            return False, ""

        now = requests[-1][1]  # Use most recent timestamp
        cutoff = now - timedelta(seconds=time_window_seconds)

        # Filter requests within time window
        recent_requests = [(obj, ts) for obj, ts in requests if ts >= cutoff]

        # Check rate threshold (repeat access to a tiny resource set is not harvesting)
        if (
            len(recent_requests) > rate_threshold
            and len({obj for obj, _ in recent_requests}) >= min_distinct_for_rate
        ):
            return True, f"User {user_id} made {len(recent_requests)} requests in {time_window_seconds}s (threshold: {rate_threshold})"

        # Check distinct objects threshold
        distinct_objects = set(obj for obj, _ in recent_requests)
        if len(distinct_objects) > distinct_threshold:
            return True, f"User {user_id} accessed {len(distinct_objects)} distinct objects in {time_window_seconds}s (threshold: {distinct_threshold})"

        return False, ""

    def clear_old_history(self, max_age_hours: int = 24):
        """Remove old request history to prevent unbounded growth.

        Args:
            max_age_hours: How many hours to keep history for (default 24).
        """
        cutoff = _cutoff_time(max_age_hours)
        for user_id in self.request_history:
            self.request_history[user_id] = [
                (obj, ts) for obj, ts in self.request_history[user_id]
                if ts >= cutoff
            ]


class TokenReplayDetector:
    """Detects token replay and misuse patterns.

    Uses token fingerprints (never stores raw tokens) to detect:
    - Same token used from multiple IPs
    - Token used after expiration
    - Unusual token patterns
    """

    def __init__(self):
        self.token_usage: Dict[str, List[Tuple[str, datetime, str]]] = defaultdict(list)

    @staticmethod
    def fingerprint_token(token: str) -> str:
        """Create a safe fingerprint of a token (never stores raw token).

        Args:
            token: The token to fingerprint.

        Returns:
            Hex fingerprint (truncated SHA256).
        """
        return hashlib.sha256(token.encode()).hexdigest()[:16]

    def record_token_use(
        self,
        token: str,
        user_id: str,
        ip_address: str,
        timestamp: datetime
    ):
        """Record a token use for tracking.

        Args:
            token: The token (will be fingerprinted, not stored).
            user_id: The user using the token.
            ip_address: IP address making the request.
            timestamp: When the token was used.
        """
        fingerprint = self.fingerprint_token(token)
        self.token_usage[fingerprint].append((user_id, timestamp, ip_address))

    def detect(
        self,
        token: str,
        user_id: str,
        ip_address: str,
        timestamp: datetime,
        max_ip_changes: int = 3
    ) -> Tuple[bool, str]:
        """Detect token replay or misuse.

        Args:
            token: The token being used.
            user_id: Expected user for this token.
            ip_address: IP address of current request.
            timestamp: Current timestamp.
            max_ip_changes: Max IPs token can be used from (default 3).

        Returns:
            (is_replay: bool, reason: str)
        """
        fingerprint = self.fingerprint_token(token)

        if fingerprint not in self.token_usage:
            return False, ""

        usage_history = self.token_usage[fingerprint]

        # Check if token used by different user
        users = set(hist[0] for hist in usage_history)
        if len(users) > 1:
            return True, f"Token fingerprint used by multiple users: {users}"

        if users and user_id not in users:
            return True, f"Token used by unexpected user. Expected {user_id}, actual {users}"

        # Check if token used from too many different IPs
        ips = set(hist[2] for hist in usage_history)
        if len(ips) > max_ip_changes:
            return True, f"Token used from {len(ips)} different IPs (threshold: {max_ip_changes})"

        if ips and ip_address not in ips:
            ips_list = list(ips)
            if len(ips) >= max_ip_changes:
                return True, f"Token from new IP {ip_address}. Known IPs: {ips_list}"

        return False, ""

    def clear_old_usage(self, max_age_hours: int = 24):
        """Remove old token usage data.

        Args:
            max_age_hours: How many hours to keep usage data (default 24).
        """
        cutoff = _cutoff_time(max_age_hours)
        for fingerprint in self.token_usage:
            self.token_usage[fingerprint] = [
                (user, ts, ip) for user, ts, ip in self.token_usage[fingerprint]
                if ts >= cutoff
            ]
