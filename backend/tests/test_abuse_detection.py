"""
Tests for abuse detection module.

Tests cover normal traffic, edge cases, and simulated abusive patterns.
"""

import pytest
from datetime import datetime, timedelta
from app.abuse_detection import BOLADetector, ScrapingDetector, TokenReplayDetector


class TestBOLADetector:
    """Tests for BOLA (Broken Object Level Authorization) detection."""

    def test_authorized_access_allowed(self):
        """Legitimate access to authorized resources should pass."""
        detector = BOLADetector()
        authorized = {"resource_1", "resource_2", "resource_3"}

        is_bola, reason = detector.detect("user_123", "resource_1", authorized)

        assert not is_bola
        assert reason == ""

    def test_unauthorized_access_detected(self):
        """Access to unauthorized resources should be flagged."""
        detector = BOLADetector()
        authorized = {"resource_1", "resource_2"}

        is_bola, reason = detector.detect("user_123", "resource_99", authorized)

        assert is_bola
        assert "unauthorized" in reason.lower()
        assert "resource_99" in reason

    def test_empty_authorization_set(self):
        """User with no authorized resources should not access anything."""
        detector = BOLADetector()

        is_bola, reason = detector.detect("user_456", "resource_1", set())

        assert is_bola
        assert "unauthorized" in reason.lower()

    def test_multiple_authorized_resources(self):
        """User can access any resource in their authorized set."""
        detector = BOLADetector()
        authorized = {"resource_1", "resource_2", "resource_3"}

        for resource_id in authorized:
            is_bola, _ = detector.detect("user_789", resource_id, authorized)
            assert not is_bola


class TestScrapingDetector:
    """Tests for scraping pattern detection."""

    def test_normal_request_rate_passes(self):
        """Normal request rate should not trigger scraping alert."""
        detector = ScrapingDetector()
        base_time = datetime.utcnow()

        # 5 requests in 60s (below threshold of 10)
        for i in range(5):
            detector.record_request(
                "user_100",
                f"object_{i}",
                base_time + timedelta(seconds=i*10)
            )

        is_scraping, reason = detector.detect(
            "user_100",
            time_window_seconds=60,
            rate_threshold=10,
            distinct_threshold=20
        )

        assert not is_scraping
        assert reason == ""

    def test_high_request_rate_detected(self):
        """High request rate should trigger scraping alert."""
        detector = ScrapingDetector()
        base_time = datetime.utcnow()

        # 15 requests in 60s (above threshold of 10)
        for i in range(15):
            detector.record_request(
                "user_200",
                f"object_{i}",
                base_time + timedelta(seconds=i*3)
            )

        is_scraping, reason = detector.detect(
            "user_200",
            time_window_seconds=60,
            rate_threshold=10,
            distinct_threshold=20
        )

        assert is_scraping
        assert "requests" in reason.lower()
        assert "15" in reason

    def test_many_distinct_objects_detected(self):
        """Accessing many distinct objects should trigger scraping alert."""
        detector = ScrapingDetector()
        base_time = datetime.utcnow()

        # 25 distinct objects in 60s (above threshold of 20)
        for i in range(25):
            detector.record_request(
                "user_300",
                f"object_{i}",
                base_time + timedelta(seconds=i*2)
            )

        is_scraping, reason = detector.detect(
            "user_300",
            time_window_seconds=60,
            rate_threshold=50,  # Set high so rate doesn't trigger
            distinct_threshold=20
        )

        assert is_scraping
        assert "distinct" in reason.lower()
        assert "25" in reason

    def test_old_requests_ignored(self):
        """Requests older than time window should be ignored."""
        detector = ScrapingDetector()
        base_time = datetime.utcnow()

        # Add old request (outside window)
        detector.record_request(
            "user_400",
            "old_object",
            base_time - timedelta(seconds=120)
        )

        # Add recent request (inside window)
        detector.record_request(
            "user_400",
            "recent_object",
            base_time
        )

        is_scraping, reason = detector.detect(
            "user_400",
            time_window_seconds=60,
            rate_threshold=10,
            distinct_threshold=20
        )

        assert not is_scraping

    def test_unknown_user_returns_false(self):
        """Unknown user should not trigger alert."""
        detector = ScrapingDetector()

        is_scraping, reason = detector.detect("unknown_user")

        assert not is_scraping
        assert reason == ""

    def test_clear_old_history(self):
        """Old history should be cleared to prevent unbounded growth."""
        detector = ScrapingDetector()
        base_time = datetime.utcnow()

        # Add old request
        detector.record_request("user_500", "object_1", base_time - timedelta(hours=25))

        # Add recent request
        detector.record_request("user_500", "object_2", base_time)

        detector.clear_old_history(max_age_hours=24)

        # Only recent request should remain
        assert len(detector.request_history["user_500"]) == 1
        assert detector.request_history["user_500"][0][0] == "object_2"


class TestTokenReplayDetector:
    """Tests for token replay and misuse detection."""

    def test_normal_single_use_allowed(self):
        """Single IP use of token should be allowed."""
        detector = TokenReplayDetector()
        now = datetime.utcnow()
        token = "secret_token_123"

        detector.record_token_use(token, "user_600", "192.168.1.1", now)

        is_replay, reason = detector.detect(
            token,
            "user_600",
            "192.168.1.1",
            now,
            max_ip_changes=3
        )

        assert not is_replay
        assert reason == ""

    def test_token_used_by_different_user_detected(self):
        """Token used by different user should be flagged."""
        detector = TokenReplayDetector()
        now = datetime.utcnow()
        token = "secret_token_456"

        # User 1 uses token
        detector.record_token_use(token, "user_700", "192.168.1.1", now)

        # Check with different user
        is_replay, reason = detector.detect(
            token,
            "user_800",
            "192.168.1.1",
            now + timedelta(seconds=10)
        )

        assert is_replay
        assert "multiple users" in reason.lower() or "unexpected user" in reason.lower()

    def test_token_used_from_many_ips_detected(self):
        """Token used from too many IPs should be flagged."""
        detector = TokenReplayDetector()
        now = datetime.utcnow()
        token = "secret_token_789"

        # Record token use from 4 different IPs
        ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"]
        for i, ip in enumerate(ips):
            detector.record_token_use(
                token,
                "user_900",
                ip,
                now + timedelta(seconds=i*5)
            )

        # New IP should trigger alert (exceeded threshold of 3)
        is_replay, reason = detector.detect(
            token,
            "user_900",
            "192.168.1.5",
            now + timedelta(seconds=20),
            max_ip_changes=3
        )

        assert is_replay
        assert "ips" in reason.lower()

    def test_token_fingerprint_consistent(self):
        """Same token should produce same fingerprint."""
        token = "my_token_123"
        fp1 = TokenReplayDetector.fingerprint_token(token)
        fp2 = TokenReplayDetector.fingerprint_token(token)

        assert fp1 == fp2

    def test_different_tokens_different_fingerprints(self):
        """Different tokens should produce different fingerprints."""
        fp1 = TokenReplayDetector.fingerprint_token("token_1")
        fp2 = TokenReplayDetector.fingerprint_token("token_2")

        assert fp1 != fp2

    def test_fingerprint_safe_length(self):
        """Fingerprints should be short (not full token hash)."""
        token = "this_is_a_very_long_secret_token_that_should_be_fingerprinted"
        fingerprint = TokenReplayDetector.fingerprint_token(token)

        # Should be truncated (16 chars)
        assert len(fingerprint) == 16
        assert fingerprint != token

    def test_clear_old_usage(self):
        """Old token usage data should be cleared."""
        detector = TokenReplayDetector()
        now = datetime.utcnow()
        token = "token_old"

        # Record old use
        detector.record_token_use(token, "user_old", "192.168.1.1", now - timedelta(hours=25))

        # Record recent use
        detector.record_token_use(token, "user_old", "192.168.1.2", now)

        detector.clear_old_usage(max_age_hours=24)

        # Only recent use should remain
        fingerprint = TokenReplayDetector.fingerprint_token(token)
        assert len(detector.token_usage[fingerprint]) == 1


class TestFalsePositives:
    """Tests to ensure legitimate use is not flagged as abuse."""

    def test_bola_no_false_positive_with_different_users_authorized_separately(self):
        """Different users with different authorized sets should not collide."""
        detector = BOLADetector()

        user1_auth = {"resource_1", "resource_2"}
        user2_auth = {"resource_3", "resource_4"}

        # User 1 accessing their resource
        is_bola_1, _ = detector.detect("user_1", "resource_1", user1_auth)
        # User 2 accessing their resource
        is_bola_2, _ = detector.detect("user_2", "resource_3", user2_auth)

        assert not is_bola_1
        assert not is_bola_2

    def test_scraping_no_false_positive_with_threshold_at_boundary(self):
        """Requests at exactly the threshold should pass."""
        detector = ScrapingDetector()
        base_time = datetime.utcnow()

        # Exactly 10 requests (equals threshold)
        for i in range(10):
            detector.record_request(
                "user_boundary",
                f"object_{i}",
                base_time + timedelta(seconds=i*5)
            )

        is_scraping, _ = detector.detect(
            "user_boundary",
            time_window_seconds=60,
            rate_threshold=10,
            distinct_threshold=20
        )

        assert not is_scraping

    def test_token_same_ip_different_sessions_allowed(self):
        """Same token from same IP in different sessions should be allowed."""
        detector = TokenReplayDetector()
        token = "recurring_token"
        now = datetime.utcnow()

        # Use token from same IP twice
        detector.record_token_use(token, "user_recurring", "192.168.1.100", now)
        detector.record_token_use(token, "user_recurring", "192.168.1.100", now + timedelta(hours=1))

        is_replay, _ = detector.detect(
            token,
            "user_recurring",
            "192.168.1.100",
            now + timedelta(hours=2)
        )

        assert not is_replay
