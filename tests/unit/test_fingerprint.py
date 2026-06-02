"""
Unit tests for tech fingerprinting and endpoint discovery.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spring2shell.discovery.endpoints import (
    load_cve_endpoints,
    load_endpoints,
    prioritize_endpoints,
)


class TestLoadEndpoints:
    def _data_root(self) -> Path:
        # tests/unit/ -> tests/ -> project root -> data/
        return Path(__file__).parents[2] / "data"

    def test_load_endpoints_returns_list(self) -> None:
        data_root = self._data_root()
        if not data_root.exists():
            pytest.skip("data/ not found")
        result = load_endpoints(data_root=data_root)
        assert isinstance(result, list)
        assert len(result) > 0

    def test_load_endpoints_all_start_with_slash(self) -> None:
        data_root = self._data_root()
        if not data_root.exists():
            pytest.skip("data/ not found")
        result = load_endpoints(data_root=data_root)
        for ep in result:
            assert ep.startswith("/"), f"Endpoint {ep!r} does not start with '/'"

    def test_load_endpoints_missing_dir_returns_empty(self) -> None:
        result = load_endpoints(data_root="/nonexistent")
        assert result == []

    def test_load_cve_endpoints_returns_list(self) -> None:
        data_root = self._data_root()
        if not data_root.exists():
            pytest.skip("data/ not found")
        result = load_cve_endpoints(data_root=data_root)
        assert isinstance(result, list)


class TestPrioritizeEndpoints:
    def test_graphql_ranked_first_for_graphql_tech(self) -> None:
        endpoints = ["/admin", "/graphql", "/static", "/actuator"]
        result = prioritize_endpoints(endpoints, fingerprints=["graphql"])
        assert result[0] == "/graphql"

    def test_actuator_ranked_high_for_spring_tech(self) -> None:
        endpoints = ["/static", "/actuator", "/wp-admin"]
        result = prioritize_endpoints(endpoints, fingerprints=["spring"])
        assert result[0] == "/actuator"

    def test_returns_same_count(self) -> None:
        endpoints = ["/a", "/b", "/c"]
        result = prioritize_endpoints(endpoints, fingerprints=[])
        assert len(result) == 3

    def test_empty_endpoints(self) -> None:
        result = prioritize_endpoints([], fingerprints=["react"])
        assert result == []

    def test_deduplication(self) -> None:
        endpoints = ["/graphql", "/graphql", "/api"]
        result = prioritize_endpoints(endpoints, fingerprints=[])
        assert len(result) == 2
