"""
Unit tests for WAFEvasionEngine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spring2shell.evasion.waf_engine import WAFEvasionEngine, load_waf_bypasses


class TestWAFEvasionEngine:
    def setup_method(self) -> None:
        self.engine = WAFEvasionEngine()

    def test_mutate_body_pad_increases_length(self) -> None:
        body = "test_payload"
        result = self.engine.mutate_body(body, technique="pad")
        assert len(result) > len(body)
        assert result.endswith(body)

    def test_mutate_body_chunk_contains_crlf(self) -> None:
        body = "A" * 100
        result = self.engine.mutate_body(body, technique="chunk")
        assert "\r\n" in result

    def test_mutate_body_xor_returns_base64(self) -> None:
        import base64

        body = "test_payload"
        result = self.engine.mutate_body(body, technique="xor")
        # Should be valid base64
        decoded = base64.b64decode(result)
        assert len(decoded) == len(body)

    def test_mutate_body_unknown_technique_returns_original(self) -> None:
        body = "test_payload"
        result = self.engine.mutate_body(body, technique="nonexistent")
        assert result == body

    def test_mutate_headers_adds_random_header(self) -> None:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        result = self.engine.mutate_headers(headers)
        assert "X-Request-Random" in result
        assert result["Content-Type"] == "application/json"

    def test_apply_returns_tuple(self) -> None:
        body = "payload"
        headers: dict[str, str] = {"Content-Type": "application/json"}
        mutated_body, mutated_headers = self.engine.apply(body, headers)
        assert isinstance(mutated_body, str)
        assert isinstance(mutated_headers, dict)

    def test_junk_cache_is_deterministic(self) -> None:
        junk1 = self.engine._junk(16)
        junk2 = self.engine._junk(16)
        assert junk1 == junk2


class TestLoadWafBypasses:
    def test_load_returns_list(self) -> None:
        # Should return a list even if file is missing
        result = load_waf_bypasses(data_root="/nonexistent/path")
        assert isinstance(result, list)

    def test_load_from_data_dir(self) -> None:
        """Integration: load from the actual data directory."""
        data_root = Path(__file__).parents[2] / "data"
        if not data_root.exists():
            pytest.skip("data/ directory not found")
        result = load_waf_bypasses(data_root=data_root)
        assert isinstance(result, list)
        if result:
            assert "name" in result[0]
            assert "template" in result[0]
