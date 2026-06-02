"""
Report encryption for spring2shell using Fernet symmetric encryption.

Key is stored in ~/.spring2shell/key (auto-generated on first use).

Usage:
    from spring2shell.core.crypto import encrypt_report, decrypt_report

    encrypt_report("reports/scan.json")          # → reports/scan.json.enc
    decrypt_report("reports/scan.json.enc")      # → reports/scan.json
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from spring2shell.utils.logging import log_event

_KEY_DIR = Path.home() / ".spring2shell"
_KEY_FILE = _KEY_DIR / "key"


def _load_or_generate_key() -> bytes:
    """Load key from ~/.spring2shell/key, creating it if absent."""
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        raise RuntimeError(
            "The 'cryptography' package is required for report encryption. "
            "Install it with: pip install cryptography"
        )

    _KEY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    if _KEY_FILE.exists():
        key = _KEY_FILE.read_bytes()
        log_event(logging.DEBUG, f"Encryption key loaded from {_KEY_FILE}")
    else:
        key = Fernet.generate_key()
        _KEY_FILE.write_bytes(key)
        _KEY_FILE.chmod(0o600)
        log_event(
            logging.INFO,
            f"New encryption key generated and stored at {_KEY_FILE}. "
            "Keep this file safe — you cannot decrypt reports without it.",
        )
    return key


def encrypt_report(report_path: str | Path, *, remove_original: bool = False) -> Path:
    """Encrypt a report file using Fernet symmetric encryption.

    Args:
        report_path:     Path to the plaintext report file.
        remove_original: If True, delete the plaintext file after encryption.

    Returns:
        Path to the encrypted file (``<original>.enc``).

    Raises:
        FileNotFoundError: If *report_path* does not exist.
        RuntimeError:      If the ``cryptography`` package is not installed.
    """
    from cryptography.fernet import Fernet  # type: ignore

    src = Path(report_path)
    if not src.exists():
        raise FileNotFoundError(f"Report file not found: {src}")

    key = _load_or_generate_key()
    fernet = Fernet(key)
    ciphertext = fernet.encrypt(src.read_bytes())

    dst = src.with_suffix(src.suffix + ".enc")
    dst.write_bytes(ciphertext)
    log_event(logging.INFO, f"Report encrypted: {dst}")

    if remove_original:
        src.unlink()
        log_event(logging.INFO, f"Original report removed: {src}")

    return dst


def decrypt_report(encrypted_path: str | Path, *, output_path: str | Path | None = None) -> Path:
    """Decrypt a Fernet-encrypted report file.

    Args:
        encrypted_path: Path to the ``.enc`` report file.
        output_path:    Destination for the decrypted file.
                        Defaults to *encrypted_path* without the ``.enc`` suffix.

    Returns:
        Path to the decrypted file.

    Raises:
        FileNotFoundError: If *encrypted_path* does not exist.
        RuntimeError:      If the ``cryptography`` package is not installed.
    """
    from cryptography.fernet import Fernet, InvalidToken  # type: ignore

    src = Path(encrypted_path)
    if not src.exists():
        raise FileNotFoundError(f"Encrypted file not found: {src}")

    key = _load_or_generate_key()
    fernet = Fernet(key)

    try:
        plaintext = fernet.decrypt(src.read_bytes())
    except InvalidToken as exc:
        raise ValueError(
            "Decryption failed — wrong key or corrupted file."
        ) from exc

    if output_path:
        dst = Path(output_path)
    else:
        # Strip trailing .enc suffix
        dst = src.with_suffix("") if src.suffix == ".enc" else src.with_name(src.stem)

    dst.write_bytes(plaintext)
    log_event(logging.INFO, f"Report decrypted: {dst}")
    return dst
