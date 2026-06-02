"""Unit tests for dry_run.py — C3: dry-run mode."""
from __future__ import annotations

import pytest

import spring2shell.utils.dry_run as dr_module
from spring2shell.utils.dry_run import (
    DryRunSession,
    disable_dry_run,
    enable_dry_run,
    is_dry_run,
)


@pytest.fixture(autouse=True)
def reset_dry_run():
    """Always reset dry-run state between tests."""
    disable_dry_run()
    yield
    disable_dry_run()


class TestDryRunFlag:
    def test_disabled_by_default(self):
        assert not is_dry_run()

    def test_enable_sets_flag(self):
        enable_dry_run()
        assert is_dry_run()

    def test_disable_clears_flag(self):
        enable_dry_run()
        disable_dry_run()
        assert not is_dry_run()


class TestDryRunSession:
    def test_get_returns_fake_response(self):
        session = DryRunSession()
        resp = session.get("http://example.com/test")
        assert resp.status_code == 200
        assert resp.text == "DRY_RUN_RESPONSE"

    def test_post_returns_fake_response(self):
        session = DryRunSession()
        resp = session.post("http://example.com/api", data='{"key": "value"}')
        assert resp.status_code == 200

    def test_all_http_methods_work(self):
        session = DryRunSession()
        for method in [session.get, session.post, session.put,
                       session.patch, session.delete, session.head]:
            resp = method("http://example.com/")
            assert resp.status_code == 200

    def test_prints_method_and_url(self, capsys):
        session = DryRunSession()
        session.get("http://target.example/api/graphql")
        captured = capsys.readouterr()
        assert "[DRY-RUN]" in captured.out
        assert "GET" in captured.out
        assert "target.example" in captured.out

    def test_prints_post_body(self, capsys):
        session = DryRunSession()
        session.post("http://example.com/api", data='{"query": "test"}')
        captured = capsys.readouterr()
        assert "query" in captured.out

    def test_prints_headers(self, capsys):
        session = DryRunSession()
        session.get("http://example.com", headers={"Content-Type": "application/json"})
        captured = capsys.readouterr()
        assert "Content-Type" in captured.out

    def test_redacts_authorization_header(self, capsys):
        session = DryRunSession()
        session.get("http://example.com", headers={"Authorization": "Bearer secret-token"})
        captured = capsys.readouterr()
        # Authorization header should NOT appear in output
        assert "secret-token" not in captured.out

    def test_prints_query_params(self, capsys):
        session = DryRunSession()
        session.get("http://example.com/search", params={"q": "test", "page": "1"})
        captured = capsys.readouterr()
        assert "q=test" in captured.out or "q" in captured.out

    def test_mount_does_not_crash(self):
        session = DryRunSession()
        session.mount("https://", None)  # should not raise

    def test_fake_response_json_returns_empty_dict(self):
        session = DryRunSession()
        resp = session.post("http://example.com")
        assert resp.json() == {}

    def test_fake_response_raise_for_status_no_op(self):
        session = DryRunSession()
        resp = session.get("http://example.com")
        resp.raise_for_status()  # should not raise


class TestSessionIntegration:
    def test_create_stealth_session_returns_dry_run_session(self):
        """When dry-run is active, create_stealth_session() returns DryRunSession."""
        enable_dry_run()
        from spring2shell.core.session import create_stealth_session
        session = create_stealth_session()
        assert isinstance(session, DryRunSession)
