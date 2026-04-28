"""Symmetric encryption for scan credentials stored in ``scans.options``.

The web request has plaintext credentials in memory. The scanner worker is
a separate process that only sees what's been persisted to Postgres. We
encrypt the handful of secret fields with a Fernet key derived from
``app_secret`` so a raw DB dump doesn't leak them; the worker holds the
same secret and decrypts on load.

Only three option fields are encrypted: ``auth_password``,
``google_id_token``, ``private_key``. Everything else in ``scan.options``
stays plaintext.
"""
from __future__ import annotations

import base64
import hashlib
from functools import lru_cache
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from ..config import get_settings

SECRET_OPTION_KEYS: tuple[str, ...] = (
    "auth_password",
    "google_id_token",
    "private_key",
)

_PREFIX = "enc:v1:"


@lru_cache
def _fernet() -> Fernet:
    key = hashlib.sha256(get_settings().app_secret.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt(plaintext: str) -> str:
    token = _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")
    return _PREFIX + token


def decrypt(ciphertext: str) -> str:
    if not ciphertext.startswith(_PREFIX):
        # Legacy / unencrypted value — return as-is so old rows still work.
        return ciphertext
    try:
        return _fernet().decrypt(ciphertext[len(_PREFIX):].encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("failed to decrypt scan secret — wrong app_secret?") from exc


def encrypt_option_secrets(options: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``options`` with secret fields encrypted in place."""
    out = dict(options)
    for key in SECRET_OPTION_KEYS:
        v = out.get(key)
        if isinstance(v, str) and v and not v.startswith(_PREFIX):
            out[key] = encrypt(v)
    return out


def decrypt_option_secrets(options: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``options`` with secret fields decrypted."""
    out = dict(options)
    for key in SECRET_OPTION_KEYS:
        v = out.get(key)
        if isinstance(v, str) and v:
            out[key] = decrypt(v)
    return out
