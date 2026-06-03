"""Unit tests for auth.py — RateLimiter, AuditLogger, AuthConfig, webhook."""

from __future__ import annotations

import json
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from spring2shell.utils.auth import (
    AuditLogger,
    AuthConfig,
    RateLimiter,
    configure_auth,
    get_auth_config,
)

# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------


class TestRateLimiter:
    def test_unlimited_does_not_block(self):
        """RateLimiter(0) should never block."""
        rl = RateLimiter(0)
        start = time.monotonic()
        for _ in range(10):
            rl.acquire()
        elapsed = time.monotonic() - start
        assert elapsed < 0.1, "Unlimited rate limiter should not block"

    def test_rate_limiting_slows_requests(self):
        """RateLimiter should call sleep when tokens are exhausted."""
        rl = RateLimiter(1)  # 1 rps — any 2nd+ request must wait
        sleep_calls: list[float] = []

        def mock_sleep(secs: float) -> None:
            sleep_calls.append(secs)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(time, "sleep", mock_sleep)
            for _ in range(4):
                rl.acquire()

        # After the first "free" token, subsequent requests must have caused waits
        assert len(sleep_calls) >= 1, "Rate limiter should have slept at least once"
        assert all(s > 0 for s in sleep_calls), "All sleeps should be positive"

    def test_thread_safety(self):
        """Multiple threads should not cause race conditions."""
        rl = RateLimiter(100)
        errors: list[Exception] = []

        def worker():
            try:
                for _ in range(5):
                    rl.acquire()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread safety errors: {errors}"


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------


class TestAuditLogger:
    def test_writes_valid_jsonl(self, tmp_path):
        """Each logged request should produce a valid JSON line."""
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file)

        logger.log_request("POST", "http://target.example/api", 200, '{"query":"test"}', "ok")
        logger.log_request("GET", "http://target.example/health", 404, None, "not_found")

        lines = log_file.read_text().strip().splitlines()
        assert len(lines) == 2

        rec1 = json.loads(lines[0])
        assert rec1["method"] == "POST"
        assert rec1["url"] == "http://target.example/api"
        assert rec1["status"] == 200
        assert len(rec1["ph"]) == 12  # payload hash length

        rec2 = json.loads(lines[1])
        assert rec2["method"] == "GET"
        assert rec2["status"] == 404

    def test_thread_safe_writes(self, tmp_path):
        """Concurrent writes should not corrupt the JSONL file."""
        log_file = tmp_path / "concurrent_audit.jsonl"
        logger = AuditLogger(log_file)

        def write_entries():
            for i in range(20):
                logger.log_request("POST", f"http://example.com/{i}", 200, f"payload_{i}", "ok")

        threads = [threading.Thread(target=write_entries) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        lines = log_file.read_text().strip().splitlines()
        assert len(lines) == 100  # 5 threads × 20 writes
        for line in lines:
            json.loads(line)  # should not raise

    def test_creates_parent_dirs(self, tmp_path):
        """AuditLogger should create missing parent directories."""
        log_file = tmp_path / "nested" / "deep" / "audit.jsonl"
        logger = AuditLogger(log_file)
        logger.log_request("GET", "http://example.com", 200, None, "")
        assert log_file.exists()


# ---------------------------------------------------------------------------
# AuthConfig
# ---------------------------------------------------------------------------


class TestConfigureAuth:
    def _make_args(self, **kwargs):
        args = MagicMock()
        for key in ["auth_bearer", "auth_basic", "auth_cookie", "auth_header"]:
            setattr(args, key, kwargs.get(key))
        return args

    def test_bearer_token(self):
        args = self._make_args(auth_bearer="test-token-xyz")
        configure_auth(args)
        cfg = get_auth_config()
        assert cfg.bearer == "test-token-xyz"

    def test_basic_auth(self):
        args = self._make_args(auth_basic="admin:secret123")
        configure_auth(args)
        cfg = get_auth_config()
        assert cfg.basic == ("admin", "secret123")

    def test_basic_auth_colon_in_password(self):
        """Password may contain colons — only split on the first one."""
        args = self._make_args(auth_basic="user:pass:word")
        configure_auth(args)
        cfg = get_auth_config()
        assert cfg.basic == ("user", "pass:word")

    def test_cookie_parsing(self):
        args = self._make_args(auth_cookie="session=abc123; csrftoken=xyz789")
        configure_auth(args)
        cfg = get_auth_config()
        assert cfg.cookies["session"] == "abc123"
        assert cfg.cookies["csrftoken"] == "xyz789"

    def test_custom_header_parsing(self):
        args = self._make_args(auth_header="X-API-Key:my-key;X-Tenant:acme")
        configure_auth(args)
        cfg = get_auth_config()
        assert cfg.headers["X-API-Key"] == "my-key"
        assert cfg.headers["X-Tenant"] == "acme"

    def test_is_configured_empty(self):
        cfg = AuthConfig()
        assert not cfg.is_configured

    def test_is_configured_with_bearer(self):
        cfg = AuthConfig(bearer="tok")
        assert cfg.is_configured


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------


class TestWebhook:
    def test_send_webhook_no_url(self):
        """send_webhook should be a no-op when no URL is configured."""
        # Ensure no webhook is set
        import spring2shell.utils.auth as auth_mod
        from spring2shell.utils.auth import send_webhook

        original = auth_mod._webhook_url
        auth_mod._webhook_url = None
        try:
            # Should not raise
            send_webhook({"url": "http://example.com", "status": "confirmed"})
        finally:
            auth_mod._webhook_url = original

    @patch("requests.post")
    def test_send_webhook_posts_json(self, mock_post):
        """send_webhook should POST a JSON payload with correct fields."""
        import spring2shell.utils.auth as auth_mod

        auth_mod._webhook_url = "https://hooks.example.com/webhook"
        mock_post.return_value = MagicMock(status_code=200)

        from spring2shell.utils.auth import send_webhook

        send_webhook(
            {
                "url": "http://target.example",
                "endpoint": "http://target.example/api/graphql",
                "status": "confirmed",
                "evidence": "RCE_MARKER found",
                "cve": "CVE-2025-55182",
            }
        )

        assert mock_post.called
        call_kwargs = mock_post.call_args[1]
        payload = call_kwargs["json"]
        assert "🚨" in payload["text"]
        assert payload["severity"] == "critical"
        assert payload["cve"] == "CVE-2025-55182"

        # Cleanup
        auth_mod._webhook_url = None
