"""Tamper-evident evidence ledger.

Every grid event is appended to a SHA-256 hash chain: each entry commits to the
one before it, so editing or dropping a record breaks every hash after it. The
chain head is signed with Ed25519, which lets a third party check a ledger
export against the public key without trusting this process.
"""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel

GENESIS = "0" * 64


class LedgerEntry(BaseModel):
    seq: int
    ts: float
    kind: str
    session_id: str | None
    payload_hash: str
    prev_hash: str
    hash: str


class LedgerHead(BaseModel):
    entries: int
    head: str
    signature: str
    public_key: str


def _canonical(obj: Any) -> bytes:
    # Sorted keys and fixed separators: the same record always hashes the same.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def _entry_hash(seq: int, ts: float, kind: str, session_id: str | None, payload_hash: str,
                prev_hash: str) -> str:
    body = {"seq": seq, "ts": ts, "kind": kind, "session_id": session_id,
            "payload_hash": payload_hash, "prev_hash": prev_hash}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _head_message(entries: int, head: str) -> bytes:
    # Sign the length together with the head so a truncated chain cannot be
    # passed off under an old signature.
    return f"phantom-ledger-v1|{entries}|{head}".encode()


class EvidenceLedger:
    def __init__(self, signing_key: Ed25519PrivateKey | None = None,
                 path: Path | None = None) -> None:
        self._key = signing_key or Ed25519PrivateKey.generate()
        self._entries: list[LedgerEntry] = []
        self._lock = threading.Lock()
        self._path = path
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def public_key_hex(self) -> str:
        raw = self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return raw.hex()

    def append(self, *, ts: float, kind: str, session_id: str | None,
               payload: dict[str, Any]) -> LedgerEntry:
        with self._lock:
            prev = self._entries[-1].hash if self._entries else GENESIS
            seq = len(self._entries) + 1
            payload_hash = hashlib.sha256(_canonical(payload)).hexdigest()
            entry = LedgerEntry(
                seq=seq, ts=ts, kind=kind, session_id=session_id,
                payload_hash=payload_hash, prev_hash=prev,
                hash=_entry_hash(seq, ts, kind, session_id, payload_hash, prev),
            )
            self._entries.append(entry)
            if self._path is not None:
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(entry.model_dump_json() + "\n")
            return entry

    def entries(self, last: int | None = None) -> list[LedgerEntry]:
        with self._lock:
            return list(self._entries if last is None else self._entries[-last:])

    def head(self) -> LedgerHead:
        with self._lock:
            count = len(self._entries)
            head = self._entries[-1].hash if self._entries else GENESIS
        sig = self._key.sign(_head_message(count, head))
        return LedgerHead(entries=count, head=head, signature=sig.hex(),
                          public_key=self.public_key_hex)


def verify_chain(entries: list[LedgerEntry]) -> tuple[bool, int | None]:
    """Recompute the chain. Returns (ok, seq of the first bad entry)."""
    prev = GENESIS
    for i, e in enumerate(entries, start=1):
        expected = _entry_hash(e.seq, e.ts, e.kind, e.session_id, e.payload_hash, prev)
        if e.seq != i or e.prev_hash != prev or e.hash != expected:
            return False, e.seq
        prev = e.hash
    return True, None


def verify_head(head: LedgerHead, entries: list[LedgerEntry]) -> bool:
    """Check a signed head against a ledger export using only public data."""
    ok, _ = verify_chain(entries)
    if not ok or head.entries != len(entries):
        return False
    if (entries[-1].hash if entries else GENESIS) != head.head:
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(head.public_key))
        key.verify(bytes.fromhex(head.signature), _head_message(head.entries, head.head))
    except (InvalidSignature, ValueError):
        return False
    return True
