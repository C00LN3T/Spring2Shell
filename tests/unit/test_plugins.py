"""
Unit tests for dynamic plugin registry and plugins.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from spring2shell.plugins import get_plugins, load_plugins
from spring2shell.plugins.base import BasePlugin


def test_base_plugin_not_implemented():
    """Verify that BasePlugin methods raise NotImplementedError."""
    plugin = BasePlugin()
    session = MagicMock(spec=requests.Session)

    with pytest.raises(NotImplementedError):
        plugin.check(session, "http://t.example", "http://t.example/api", {})

    with pytest.raises(NotImplementedError):
        plugin.exploit(session, "http://t.example", "http://t.example/api", {}, "id")


def test_plugins_discovery():
    """Verify that dynamic plugins are discovered and registered correctly."""
    load_plugins()
    plugins = get_plugins()

    # Check that at least some core plugins are registered
    assert "cve_2025_55182" in plugins
    assert "cve_2025_66478" in plugins
    assert "cve_2021_44228" in plugins
    assert "cve_2022_22965" in plugins
    assert "cve_2022_42889" in plugins

    # Check that plugin class subclasses BasePlugin
    for name, plugin_cls in plugins.items():
        assert issubclass(plugin_cls, BasePlugin)
        assert plugin_cls.name == name
        assert plugin_cls.cve_id is not None


class TestCVE202555182Plugin:
    def test_check_returns_finding_on_reflection(self):
        from spring2shell.plugins.cve_2025_55182 import CVE_2025_55182_Plugin

        plugin = CVE_2025_55182_Plugin()

        session = MagicMock(spec=requests.Session)
        resp = MagicMock(spec=requests.Response)
        # Force reflection of whatever marker is generated
        resp.text = "RCE_999999"
        resp.status_code = 200
        session.post.return_value = resp

        with patch("spring2shell.plugins.cve_2025_55182.waf_engine") as mock_waf, patch(
            "random.randint", return_value=999999
        ), patch("spring2shell.utils.auth.rate_limit_acquire"), patch(
            "spring2shell.utils.auth.audit_log"
        ):
            mock_waf.apply.side_effect = lambda b, h: (b, h)
            finding = plugin.check(session, "http://t.example", "http://t.example/api", {})

        assert finding is not None
        assert finding["status"] == "confirmed"
        assert finding["cve"] == "CVE-2025-55182"
        assert finding["confidence"] == "high"

    def test_exploit_returns_output_on_success(self):
        from spring2shell.plugins.cve_2025_55182 import CVE_2025_55182_Plugin

        plugin = CVE_2025_55182_Plugin()

        session = MagicMock(spec=requests.Session)
        resp = MagicMock(spec=requests.Response)
        resp.text = "root"
        resp.status_code = 200
        session.post.return_value = resp

        output = plugin.exploit(session, "http://t.example", "http://t.example/api", {}, "whoami")
        assert output == "root"


class TestCVE202566478Plugin:
    def test_check_returns_finding_on_reflection(self):
        from spring2shell.plugins.cve_2025_66478 import CVE_2025_66478_Plugin

        plugin = CVE_2025_66478_Plugin()

        session = MagicMock(spec=requests.Session)
        resp = MagicMock(spec=requests.Response)
        resp.text = "RCE_123456"
        resp.status_code = 200
        session.post.return_value = resp

        with patch("spring2shell.plugins.cve_2025_66478.waf_engine") as mock_waf, patch(
            "random.randint", return_value=123456
        ), patch("spring2shell.utils.auth.rate_limit_acquire"), patch(
            "spring2shell.utils.auth.audit_log"
        ):
            mock_waf.apply.side_effect = lambda b, h: (b, h)
            finding = plugin.check(session, "http://t.example", "http://t.example/graphql", {})

        assert finding is not None
        assert finding["status"] == "confirmed"
        assert finding["cve"] == "CVE-2025-66478"


class TestCVE202222965Plugin:
    def test_check_returns_potential_on_status(self):
        from spring2shell.plugins.cve_2022_22965 import CVE_2022_22965_Plugin

        plugin = CVE_2022_22965_Plugin()

        session = MagicMock(spec=requests.Session)
        resp = MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.text = "success"
        session.post.return_value = resp

        with patch("spring2shell.utils.auth.rate_limit_acquire"), patch(
            "spring2shell.utils.auth.audit_log"
        ):
            finding = plugin.check(session, "http://t.example", "http://t.example/api", {})

        assert finding is not None
        assert finding["status"] == "unverified"
        assert finding["cve"] == "CVE-2022-22965"
