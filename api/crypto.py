"""Encryption helpers for sensitive integration secrets."""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from api._compat import getenv_compat

logger = logging.getLogger(__name__)

_KEY_FILE = Path(
    getenv_compat("HOTWASH_KEY_PATH", "PLAYBOOK_FORGE_KEY_PATH")
    or str(Path.home() / ".encryption_key")
)
_CIPHER: Fernet | None = None


def _load_encryption_key() -> bytes:
    configured = getenv_compat("HOTWASH_ENCRYPTION_KEY", "PLAYBOOK_FORGE_ENCRYPTION_KEY")
    if configured:
        return configured.encode("utf-8")

    if _KEY_FILE.exists():
        return _KEY_FILE.read_text(encoding="utf-8").strip().encode("utf-8")

    key = Fernet.generate_key()
    _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    _KEY_FILE.write_text(key.decode("utf-8"), encoding="utf-8")
    os.chmod(_KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)
    return key


def get_cipher() -> Fernet:
    global _CIPHER
    if _CIPHER is None:
        _CIPHER = Fernet(_load_encryption_key())
    return _CIPHER


def encrypt_secret(value: str | None) -> str | None:
    if not value:
        return value
    return get_cipher().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str | None) -> str | None:
    if not value:
        return value
    try:
        return get_cipher().decrypt(value.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError) as exc:
        logger.error("Failed to decrypt secret", exc_info=exc)
        return None
