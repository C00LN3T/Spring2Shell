"""Unit tests for burp_import.py — B1: Burp Suite target import."""

from __future__ import annotations

from spring2shell.utils.burp_import import (
    _parse_burp_xml,
    _parse_plain_txt,
    _to_base_urls,
    load_targets,
)

_BURP_XML = """<?xml version="1.0" ?>
<!DOCTYPE items [<!ENTITY xxe SYSTEM "">]>
<items burpVersion="2023.1" exportTime="Mon Jan 01 00:00:00 UTC 2023">
  <item>
    <url><![CDATA[https://target.example/api/graphql?query=test]]></url>
  </item>
  <item>
    <url>https://target.example/actuator/env</url>
  </item>
  <item>
    <url>https://other.example:8443/login</url>
  </item>
  <item>
    <url>ftp://skip.example/file</url>
  </item>
</items>
"""

_PLAIN_TXT = """# My test targets
https://alpha.example/api
https://alpha.example/api/v2
http://beta.example:8080/health
# comment line
invalid-line-no-scheme
gamma.example
"""


class TestParseBurpXml:
    def test_extracts_https_urls(self):
        urls = _parse_burp_xml(_BURP_XML)
        assert any("target.example" in u for u in urls)
        assert any("other.example" in u for u in urls)

    def test_skips_non_http_urls(self):
        urls = _parse_burp_xml(_BURP_XML)
        assert not any("ftp://" in u for u in urls)

    def test_handles_cdata_urls(self):
        """URLs inside CDATA sections should still be extracted."""
        xml = """<items>
  <item><url><![CDATA[https://target.example/api/graphql?query=test]]></url></item>
</items>"""
        urls = _parse_burp_xml(xml)
        # CDATA markers are removed — the actual URL should be present
        assert any("graphql" in u and "target.example" in u for u in urls), (
            f"Expected URL with 'graphql' in parsed URLs, got: {urls}"
        )


class TestParsePlainTxt:
    def test_returns_http_urls(self):
        urls = _parse_plain_txt(_PLAIN_TXT)
        assert "https://alpha.example/api" in urls
        assert "http://beta.example:8080/health" in urls

    def test_skips_comments(self):
        urls = _parse_plain_txt(_PLAIN_TXT)
        assert not any(u.startswith("#") for u in urls)

    def test_handles_bare_hostname(self):
        urls = _parse_plain_txt(_PLAIN_TXT)
        # gamma.example gets https:// prepended
        assert any("gamma.example" in u for u in urls)

    def test_skips_invalid_lines(self):
        urls = _parse_plain_txt(_PLAIN_TXT)
        assert "invalid-line-no-scheme" not in urls


class TestToBaseUrls:
    def test_deduplicates_same_host_different_paths(self):
        raw = [
            "https://example.com/api/v1",
            "https://example.com/api/v2",
            "https://example.com/actuator",
        ]
        bases = _to_base_urls(raw)
        assert bases == ["https://example.com"]

    def test_keeps_non_standard_port(self):
        raw = ["https://example.com:8443/api"]
        bases = _to_base_urls(raw)
        assert "https://example.com:8443" in bases

    def test_strips_default_ports(self):
        raw = ["https://example.com:443/api", "http://example.com:80/api"]
        bases = _to_base_urls(raw)
        assert "https://example.com" in bases
        assert "http://example.com" in bases

    def test_filters_non_http_urls(self):
        raw = ["ftp://example.com/file", "https://ok.example"]
        bases = _to_base_urls(raw)
        assert not any("ftp" in b for b in bases)


class TestLoadTargets:
    def test_xml_file(self, tmp_path):
        xml_file = tmp_path / "burp.xml"
        xml_file.write_text(_BURP_XML)
        targets = load_targets(xml_file)
        assert len(targets) >= 2
        assert all(t.startswith(("http://", "https://")) for t in targets)

    def test_plain_text_file(self, tmp_path):
        txt_file = tmp_path / "targets.txt"
        txt_file.write_text(_PLAIN_TXT)
        targets = load_targets(txt_file)
        assert len(targets) >= 2

    def test_deduplication_across_full_load(self, tmp_path):
        txt_file = tmp_path / "dup_targets.txt"
        txt_file.write_text(
            "https://example.com/api\nhttps://example.com/login\nhttps://example.com/health\n"
        )
        targets = load_targets(txt_file)
        assert targets == ["https://example.com"]
