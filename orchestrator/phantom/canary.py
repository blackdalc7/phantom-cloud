"""Honeytokens: fake credentials that identify the session they were planted in.

Each token is `prefix + nonce + MAC(nonce)`. The MAC means we can tell a real
phantom token from a random look-alike without storing anything, and the nonce
maps back to the attacker session it was minted for. If a token ever shows up
again (in a later command, or in someone's auth logs) it is proof of which
intrusion it came from.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

# Shapes are chosen to look plausible in a config file. The access-key prefix is
# deliberately not a real cloud provider's, so tokens can't be mistaken for (or
# accidentally validate as) live keys.
_PREFIX = {"access_key": "PHKA", "db_password": "Pc7", "api_token": "phtok_"}
_NONCE_BYTES = 5
_MAC_BYTES = 5
_BODY_CHARS = 16  # base32 of 10 bytes
_TOKEN_RE = re.compile(r"(PHKA|Pc7|phtok_)([A-Z2-7]{16})")


@dataclass(frozen=True)
class CanaryHit:
    token: str
    kind: str
    session_id: str


class CanaryMint:
    def __init__(self, key: bytes | None = None) -> None:
        self._key = key or secrets.token_bytes(32)
        self._owners: dict[str, tuple[str, str]] = {}  # nonce -> (session, kind)

    def _mac(self, kind: str, nonce: bytes) -> bytes:
        msg = b"phantom-canary-v1|" + kind.encode() + b"|" + nonce
        return hmac.new(self._key, msg, hashlib.sha256).digest()[:_MAC_BYTES]

    def mint(self, session_id: str, kind: str) -> str:
        if kind not in _PREFIX:
            raise ValueError(f"unknown canary kind: {kind}")
        nonce = secrets.token_bytes(_NONCE_BYTES)
        body = base64.b32encode(nonce + self._mac(kind, nonce)).decode()
        self._owners[nonce.hex()] = (session_id, kind)
        return _PREFIX[kind] + body

    def lookup(self, token: str) -> CanaryHit | None:
        """Authenticate a token and attribute it. None for anything we didn't mint."""
        m = _TOKEN_RE.fullmatch(token)
        if not m:
            return None
        kind = next(k for k, p in _PREFIX.items() if p == m.group(1))
        try:
            raw = base64.b32decode(m.group(2))
        except ValueError:
            return None
        nonce, mac = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
        # Constant-time compare: don't leak how many MAC bytes matched.
        if not hmac.compare_digest(mac, self._mac(kind, nonce)):
            return None
        owner = self._owners.get(nonce.hex())
        if owner is None:
            return None
        return CanaryHit(token=token, kind=kind, session_id=owner[0])

    def scan(self, text: str) -> list[CanaryHit]:
        """Find every genuine token embedded in free text (e.g. a shell command)."""
        hits = []
        for m in _TOKEN_RE.finditer(text):
            hit = self.lookup(m.group(0))
            if hit:
                hits.append(hit)
        return hits
