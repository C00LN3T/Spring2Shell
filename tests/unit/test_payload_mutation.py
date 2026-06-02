"""
Unit tests for payload mutation utilities.
"""

from __future__ import annotations

import base64

from spring2shell.evasion.mutations import generate_payload_variants


class TestGeneratePayloadVariants:
    def test_returns_list(self) -> None:
        variants = generate_payload_variants('{"query": "test"}')
        assert isinstance(variants, list)

    def test_original_is_first_variant(self) -> None:
        payload = '{"query": "original"}'
        variants = generate_payload_variants(payload)
        assert variants[0] == payload

    def test_base64_variant_is_decodable(self) -> None:
        payload = '{"query": "test"}'
        variants = generate_payload_variants(payload)
        b64_variant = variants[-1]
        decoded = base64.b64decode(b64_variant).decode()
        assert decoded == payload

    def test_four_variants_returned(self) -> None:
        variants = generate_payload_variants("any_payload")
        assert len(variants) == 4

    def test_empty_payload(self) -> None:
        variants = generate_payload_variants("")
        assert isinstance(variants, list)
        assert len(variants) == 4
