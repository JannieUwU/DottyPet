"""
Application-layer field encryption for sensitive database columns.

Key management:
  - Production: Electron generates a random 32-byte key on first launch, stores
    it in <userData>/encryption.key (mode 0o600), and passes it via the
    DOTTY_ENCRYPTION_KEY environment variable.
  - Development (npm run dev:backend): the env var is not set, so the key is
    loaded directly from the same file path that Electron would use:
    %APPDATA%/dotty-pet/encryption.key on Windows,
    ~/Library/Application Support/dotty-pet/encryption.key on macOS,
    ~/.config/dotty-pet/encryption.key on Linux.
    If the file does not exist yet it is created with a fresh random key.

Legacy key migration:
  - Databases created before this key-management scheme used a key derived from
    platform.node() (hostname) via PBKDF2HMAC-SHA256 with a fixed salt.
  - decrypt() tries the primary key first; on InvalidToken it falls back to the
    legacy key so that _migrate_encrypt_fields() can re-encrypt old rows.
  - The legacy Fernet instance is only used for decryption, never for encryption.

Encryption format:
  - Stored value: "enc:" + Fernet token (urlsafe-base64)
  - Plain values (no "enc:" prefix) are returned as-is for backward compatibility
"""

import base64
import os
import platform
import secrets
import sys

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

# ── Key loading ────────────────────────────────────────────────────────────────

_PREFIX = "enc:"


def _key_file_path() -> str:
    """Return the platform-appropriate path for the persistent key file."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    return os.path.join(base, "dotty-pet", "encryption.key")


def _load_key() -> bytes:
    # Production path: Electron passes the key via environment variable.
    raw = os.environ.get("DOTTY_ENCRYPTION_KEY", "").strip()

    if not raw:
        # Development path: read from (or create) the key file directly.
        key_path = _key_file_path()
        if os.path.exists(key_path):
            with open(key_path, "r", encoding="utf-8") as f:
                raw = f.read().strip()
        else:
            raw = secrets.token_urlsafe(32)
            os.makedirs(os.path.dirname(key_path), exist_ok=True)
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(raw)

    # Fernet expects exactly 32 url-safe base64-encoded bytes.
    padded = raw + "=" * (-len(raw) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    if len(decoded) != 32:
        raise RuntimeError("Encryption key must be 32 bytes encoded as base64url.")
    return base64.urlsafe_b64encode(decoded)  # Fernet-ready form


def _load_legacy_key() -> bytes:
    """Derive the old hostname-based key for migrating pre-existing databases."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=b"dotty-pet-v1", iterations=100_000)
    return base64.urlsafe_b64encode(kdf.derive(platform.node().encode()))


_fernet = Fernet(_load_key())
_fernet_legacy = Fernet(_load_legacy_key())


# ── Encrypt / decrypt helpers ──────────────────────────────────────────────────

def encrypt(value: str) -> str:
    """Return enc:<fernet-token> for the given plaintext string."""
    return _PREFIX + _fernet.encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    """Decrypt an enc:-prefixed value; return plain values unchanged."""
    if not value.startswith(_PREFIX):
        return value
    token = value[len(_PREFIX):].encode()
    try:
        return _fernet.decrypt(token).decode()
    except InvalidToken:
        # Fall back to legacy key — allows _migrate_encrypt_fields() to
        # re-encrypt rows that were written before the key-management change.
        return _fernet_legacy.decrypt(token).decode()


# ── SQLAlchemy TypeDecorator ───────────────────────────────────────────────────

class EncryptedText(TypeDecorator):
    """Transparent encrypt-on-write / decrypt-on-read column type."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if not value:
            return value
        if value.startswith(_PREFIX):
            return value  # already encrypted
        return encrypt(value)

    def process_result_value(self, value, dialect):
        if not value:
            return value
        return decrypt(value)
