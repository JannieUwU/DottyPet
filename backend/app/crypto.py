"""
Application-layer field encryption for sensitive database columns.

Key management:
  - Key is generated once at first launch by the Electron host and stored in
    <userData>/encryption.key (mode 0o600, readable only by the current user).
  - Passed to this process via the DOTTY_ENCRYPTION_KEY environment variable.
  - The key is a 32-byte random value encoded as base64url, which is used
    directly as a Fernet key (Fernet requires 32 url-safe base64 bytes).

Encryption format:
  - Stored value: "enc:" + Fernet token (urlsafe-base64)
  - Plain values (no "enc:" prefix) are returned as-is for backward compatibility
"""

import base64
import os

from cryptography.fernet import Fernet
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

# ── Key loading ────────────────────────────────────────────────────────────────

_PREFIX = "enc:"


def _load_key() -> bytes:
    raw = os.environ.get("DOTTY_ENCRYPTION_KEY", "")
    if not raw:
        raise RuntimeError(
            "DOTTY_ENCRYPTION_KEY environment variable is not set. "
            "The Electron host must generate and pass this key on startup."
        )
    # Fernet expects exactly 32 url-safe base64-encoded bytes (44 chars with padding).
    # Our key is base64url without padding; add padding and verify length.
    padded = raw + "=" * (-len(raw) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    if len(decoded) != 32:
        raise RuntimeError("DOTTY_ENCRYPTION_KEY must be 32 bytes encoded as base64url.")
    return base64.urlsafe_b64encode(decoded)  # Fernet-ready form


_fernet = Fernet(_load_key())


# ── Encrypt / decrypt helpers ──────────────────────────────────────────────────

def encrypt(value: str) -> str:
    """Return enc:<fernet-token> for the given plaintext string."""
    return _PREFIX + _fernet.encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    """Decrypt an enc:-prefixed value; return plain values unchanged."""
    if value.startswith(_PREFIX):
        return _fernet.decrypt(value[len(_PREFIX):].encode()).decode()
    return value


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
