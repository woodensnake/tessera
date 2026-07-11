"""Tessera prototype — PROTOCOL.md §5–§7.

Scope: the per-message ratchet, wire format, receiver dispatch, and the
Rung-1 retransmit window, for a single epoch. The membership layer (§9)
is stubbed: the test harness plays coordinator and hands every member the
same epoch secret. Ordering (§2.1) is likewise the harness: whoever it
delivers first won the slot.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

VER = 0
FP_LEN = 8
SALT_LEN = 16
NONCE = b"\x00" * 12  # constant by design: uniqueness lives in the key (§5.3)
DEFAULT_WINDOW = 64

LABEL_INIT = b"tessera-chain-init"
LABEL_MSG = b"tessera-msg"
LABEL_FP = b"tessera-fp"
LABEL_ADV = b"tessera-adv"


def kdf(key: bytes, label: bytes, data: bytes) -> bytes:
    return hmac_mod.new(key, label + b"\x00" + data, hashlib.sha256).digest()


def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def roster_hash(roster: dict[bytes, Ed25519PublicKey]) -> bytes:
    canonical = b"".join(
        mid + roster[mid].public_bytes_raw() for mid in sorted(roster)
    )
    return H(canonical)


def chain_init(epoch_secret: bytes, epoch: int, r_hash: bytes,
               fp_close: bytes = b"\x00" * FP_LEN) -> bytes:
    return kdf(epoch_secret, LABEL_INIT, struct.pack("!I", epoch) + r_hash + fp_close)


@dataclass(frozen=True)
class Wire:
    ver: int
    epoch: int
    seq: int
    sender: bytes
    fp: bytes
    body: bytes
    sig: bytes

    def header_bytes(self) -> bytes:
        return (struct.pack("!BIQ", self.ver, self.epoch, self.seq)
                + struct.pack("!B", len(self.sender)) + self.sender
                + self.fp)

    def signed_payload(self) -> bytes:
        return self.header_bytes() + H(self.body)


# --- receiver dispatch events (§6) ---

@dataclass(frozen=True)
class Delivered:
    seq: int
    sender: bytes
    plaintext: bytes

@dataclass(frozen=True)
class Gap:
    expected: int
    got: int

@dataclass(frozen=True)
class Fork:
    position: int

@dataclass(frozen=True)
class BadSignature:
    seq: int

@dataclass(frozen=True)
class Tamper:
    seq: int

@dataclass(frozen=True)
class Duplicate:
    seq: int

@dataclass(frozen=True)
class CloneEvidence:
    seq: int
    sender: bytes
    first: Wire
    second: Wire


class Member:
    def __init__(self, member_id: bytes, signing_key: Ed25519PrivateKey,
                 roster: dict[bytes, Ed25519PublicKey], epoch_secret: bytes,
                 window: int = DEFAULT_WINDOW):
        self.id = member_id
        self.signing_key = signing_key
        self.roster = roster
        self.epoch = 0
        self.seq = 0  # next expected position
        self.ck = chain_init(epoch_secret, self.epoch, roster_hash(roster))
        self.window = window
        self.seen: dict[int, Wire] = {}   # last `window` accepted wires
        self.buffer: dict[int, Wire] = {}  # future messages awaiting a gap fill

    # --- key schedule (§5.2) ---

    def _mk(self, seq: int, sender: bytes) -> bytes:
        return kdf(self.ck, LABEL_MSG,
                   struct.pack("!IQ", self.epoch, seq) + sender)

    def _fp(self, seq: int) -> bytes:
        return kdf(self.ck, LABEL_FP, struct.pack("!IQ", self.epoch, seq))[:FP_LEN]

    @staticmethod
    def _advance(ck: bytes, salt: bytes, plaintext: bytes, header: bytes) -> bytes:
        return kdf(ck, LABEL_ADV, H(salt + plaintext) + H(header))

    # --- sending (§6) ---

    def send(self, plaintext: bytes) -> Wire:
        """Build a message for the current slot. The sender does NOT advance
        here — it advances like everyone else when the ordering layer (the
        harness) delivers the slot winner back to it."""
        seq = self.seq
        salt = os.urandom(SALT_LEN)
        fp = self._fp(seq)
        partial = Wire(VER, self.epoch, seq, self.id, fp, b"", b"")
        header = partial.header_bytes()
        mk = self._mk(seq, self.id)
        body = ChaCha20Poly1305(mk).encrypt(NONCE, salt + plaintext, header)
        sig = self.signing_key.sign(header + H(body))
        return Wire(VER, self.epoch, seq, self.id, fp, body, sig)

    # --- receiving (§6 dispatch) ---

    def receive(self, wire: Wire) -> list:
        events = [self._dispatch(wire)]
        # a successful advance may unblock buffered future messages
        while isinstance(events[-1], Delivered) and self.seq in self.buffer:
            events.append(self._dispatch(self.buffer.pop(self.seq)))
        return events

    def _dispatch(self, wire: Wire):
        pub = self.roster.get(wire.sender)
        if pub is None:
            return BadSignature(wire.seq)
        try:
            pub.verify(wire.sig, wire.signed_payload())
        except InvalidSignature:
            return BadSignature(wire.seq)

        if wire.seq > self.seq:
            self.buffer[wire.seq] = wire
            return Gap(expected=self.seq, got=wire.seq)

        if wire.seq < self.seq:
            prior = self.seen.get(wire.seq)
            if prior is not None and H(prior.body) != H(wire.body):
                return CloneEvidence(wire.seq, wire.sender, prior, wire)
            return Duplicate(wire.seq)

        # wire.seq == self.seq: fp is checkable, and its meaning is exact —
        # same position, different fingerprint is never packet loss (§6)
        if wire.fp != self._fp(wire.seq):
            return Fork(position=wire.seq)

        mk = self._mk(wire.seq, wire.sender)
        try:
            payload = ChaCha20Poly1305(mk).decrypt(NONCE, wire.body,
                                                   wire.header_bytes())
        except InvalidTag:
            return Tamper(wire.seq)

        salt, plaintext = payload[:SALT_LEN], payload[SALT_LEN:]
        self.ck = self._advance(self.ck, salt, plaintext, wire.header_bytes())
        self.seen[wire.seq] = wire
        self.seen.pop(wire.seq - self.window, None)
        self.seq += 1
        return Delivered(wire.seq, wire.sender, plaintext)

    # --- Rung 1: retransmit (§7) ---

    def missing_range(self) -> tuple[int, int] | None:
        if not self.buffer:
            return None
        return (self.seq, min(self.buffer))

    def serve_retransmit(self, start: int, end: int) -> list[Wire]:
        return [self.seen[i] for i in range(start, end) if i in self.seen]
