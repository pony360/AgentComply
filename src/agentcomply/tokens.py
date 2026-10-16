"""HMAC-signed execution and approval tokens with single-use nonces.

Tokens are bound to an action hash, expire quickly and can be consumed once.
Nonce tracking is in memory and per process. Multi-process deployments need a
shared store (see docs/GUARDRAILS.md).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
from typing import Any

from .models import canonical_json

MIN_KEY_BYTES = 32


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class TokenSigner:
    def __init__(self, key: bytes | None = None) -> None:
        if key is None:
            key = secrets.token_bytes(32)
        if not isinstance(key, (bytes, bytearray)) or len(key) < MIN_KEY_BYTES:
            raise ValueError(f"signing key must be at least {MIN_KEY_BYTES} bytes")
        self._key = bytes(key)
        self._used: dict[str, int] = {}
        self._lock = threading.Lock()

    def _sign(self, body: str) -> str:
        return _b64(hmac.new(self._key, body.encode("ascii"), hashlib.sha256).digest())

    def issue(self, payload: dict[str, Any]) -> str:
        body = _b64(canonical_json(payload).encode("utf-8"))
        return f"{body}.{self._sign(body)}"

    def verify(self, token: object, *, kind: str, now_epoch: int) -> dict[str, Any] | None:
        """Return the payload if the signature, kind and expiry are valid, else None."""
        try:
            if not isinstance(token, str):
                return None
            body, signature = token.split(".", 1)
            if not hmac.compare_digest(self._sign(body), signature):
                return None
            payload = json.loads(_unb64(body).decode("utf-8"))
        except (ValueError, TypeError, UnicodeDecodeError):
            return None
        if not isinstance(payload, dict) or payload.get("kind") != kind:
            return None
        exp = payload.get("exp")
        if not isinstance(exp, int) or isinstance(exp, bool) or exp <= now_epoch:
            return None
        return payload

    def consume(self, nonce: str, exp: int, now_epoch: int) -> bool:
        """Mark ``nonce`` as used. Returns False if it was already used."""
        with self._lock:
            self._used = {n: e for n, e in self._used.items() if e > now_epoch}
            if nonce in self._used:
                return False
            self._used[nonce] = exp
            return True
