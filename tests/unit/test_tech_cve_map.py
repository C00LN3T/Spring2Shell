"""Unit tests for tech_cve_map — A1: tech-stack-aware CVE selection."""

from __future__ import annotations

from spring2shell.discovery.fingerprint import TECH_CVE_MAP, get_cves_for_fingerprints


class TestGetCvesForFingerprints:
    def test_spring_boot_returns_spring_cves(self):
        cves = get_cves_for_fingerprints(["spring-boot"])
        assert "CVE-2025-55182" in cves
        assert "CVE-2022-22965" in cves

    def test_graphql_returns_graphql_cves(self):
        cves = get_cves_for_fingerprints(["graphql"])
        assert "CVE-2025-55182" in cves
        assert "CVE-2025-66478" in cves

    def test_activemq_only_activemq_cve(self):
        cves = get_cves_for_fingerprints(["activemq"])
        assert cves == ["CVE-2023-46604"]

    def test_multiple_tech_combines_cves(self):
        cves = get_cves_for_fingerprints(["spring-boot", "graphql"])
        assert "CVE-2025-55182" in cves
        assert "CVE-2025-66478" in cves
        assert "CVE-2022-22965" in cves

    def test_empty_fingerprints_returns_all_cves(self):
        all_cves = get_cves_for_fingerprints([])
        # Should contain CVEs from multiple different tech stacks
        assert "CVE-2025-55182" in all_cves
        assert "CVE-2023-46604" in all_cves
        assert "CVE-2021-44228" in all_cves
        assert len(all_cves) > 5

    def test_unknown_tech_falls_back_to_all_cves(self):
        """Unrecognised fingerprint → fall back to all CVEs."""
        cves = get_cves_for_fingerprints(["unknown-framework-xyz"])
        assert len(cves) > 5  # all CVEs

    def test_result_is_deduplicated(self):
        """Same CVE shouldn't appear twice."""
        cves = get_cves_for_fingerprints(["spring-boot", "spring-boot", "actuator"])
        assert len(cves) == len(set(cves))

    def test_priority_ordering(self):
        """CVE-2025-55182 should be first for spring-boot."""
        cves = get_cves_for_fingerprints(["spring-boot"])
        assert cves[0] == "CVE-2025-55182"

    def test_nextjs_returns_react_cves(self):
        cves = get_cves_for_fingerprints(["next.js"])
        assert "CVE-2025-55182" in cves
        assert "CVE-2025-66478" in cves

    def test_php_cgi_returns_php_cve(self):
        cves = get_cves_for_fingerprints(["php-cgi"])
        assert "CVE-2024-4577" in cves

    def test_log4j_returns_log4shell(self):
        cves = get_cves_for_fingerprints(["log4j"])
        assert "CVE-2021-44228" in cves

    def test_tech_cve_map_has_required_entries(self):
        for tech in ["spring-boot", "graphql", "activemq", "log4j", "next.js", "php-cgi"]:
            assert tech in TECH_CVE_MAP, f"Missing tech in TECH_CVE_MAP: {tech}"
