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
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
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
LABEL_SEAL = b"tessera-seal"
LABEL_PROP = b"tessera-prop"


def kdf(key: bytes, label: bytes, data: bytes) -> bytes:
    return hmac_mod.new(key, label + b"\x00" + data, hashlib.sha256).digest()


def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


@dataclass(frozen=True)
class MemberKeys:
    """The spec (§2.2) says 'an Ed25519 identity keypair'; code disagrees.
    Signatures need Ed25519, but sealing epoch secrets (§9) needs a DH-capable
    key — an identity is a *pair* of keypairs."""
    sig_pk: Ed25519PublicKey
    kem_pk: X25519PublicKey


def roster_hash(roster: dict[bytes, MemberKeys]) -> bytes:
    canonical = b"".join(
        mid + roster[mid].sig_pk.public_bytes_raw()
        + roster[mid].kem_pk.public_bytes_raw()
        for mid in sorted(roster)
    )
    return H(canonical)


def seal(kem_pk: X25519PublicKey, plaintext: bytes, context: bytes) -> tuple[bytes, bytes]:
    """Ephemeral-static X25519 + AEAD: a stand-in for RFC 9180 HPKE (§9).
    Ephemeral, not static-static — the re-key channel must be as
    forward-secret as the chain it re-keys."""
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes_raw()
    shared = eph.exchange(kem_pk)
    key = kdf(shared, LABEL_SEAL, eph_pub + kem_pk.public_bytes_raw() + H(context))
    return eph_pub, ChaCha20Poly1305(key).encrypt(NONCE, plaintext, context)


def open_sealed(kem_sk: X25519PrivateKey, eph_pub: bytes, ct: bytes,
                context: bytes) -> bytes:
    shared = kem_sk.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    key = kdf(shared, LABEL_SEAL,
              eph_pub + kem_sk.public_key().public_bytes_raw() + H(context))
    return ChaCha20Poly1305(key).decrypt(NONCE, ct, context)


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


@dataclass(frozen=True)
class Heartbeat:
    """§6: header-only, does not advance the chain. The counter — not a
    timestamp — is the freshness mechanism: swarm clock sync is not
    assumable, and a clock-dependent liveness check fails open exactly
    when a partitioned or GPS-denied swarm needs it."""
    epoch: int
    seq: int
    sender: bytes
    fp: bytes
    counter: int
    sig: bytes

    def signed_payload(self) -> bytes:
        return (b"tessera-hb" + struct.pack("!IQQ", self.epoch, self.seq,
                                            self.counter)
                + struct.pack("!B", len(self.sender)) + self.sender + self.fp)


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
class EpochMismatch:
    """Not in the spec's §6 dispatch — found while implementing epochs.
    A wire from an older epoch is stale noise; one from a NEWER epoch means
    we missed an epoch change and must rejoin (§7 Rung 2)."""
    ours: int
    theirs: int

@dataclass(frozen=True)
class EpochChanged:
    epoch: int
    op: str

@dataclass(frozen=True)
class Evicted:
    epoch: int

@dataclass(frozen=True)
class ContinuityBreak:
    """fp_close in an epoch change doesn't match our chain position: the
    epoch is being cut over a history we don't share (§5.1)."""
    epoch: int

@dataclass(frozen=True)
class QuorumRejected:
    epoch: int
    have: int
    need: int

@dataclass(frozen=True)
class StaleHeartbeat:
    """§6 freshness: counter <= the last seen from this sender — a replayed
    heartbeat, which would otherwise mask a dead or captured agent."""
    sender: bytes

@dataclass(frozen=True)
class ChainDivergence:
    """A heartbeat's fp disagrees with the wire we hold at that position:
    its signer is on a different chain. Clone, fork, or hijack (§8)."""
    sender: bytes
    position: int

@dataclass(frozen=True)
class PeerAhead:
    """Not an alarm — the honest liveness signal. The sender is further
    along than we are, so we are behind and would not otherwise know."""
    sender: bytes
    epoch: int
    seq: int

@dataclass(frozen=True)
class CloneEvidence:
    seq: int
    sender: bytes
    first: Wire
    second: Wire


def proposal_bytes(op: str, new_epoch: int, subject: bytes | None) -> bytes:
    return (LABEL_PROP + op.encode() + b"\x00"
            + struct.pack("!I", new_epoch) + (subject or b""))


@dataclass(frozen=True)
class EpochChange:
    """§9: a membership operation cutting over to a new epoch. Travels on
    the ordered broadcast; the sealed epoch secret is per-member."""
    op: str                      # "JOIN" | "EVICT" | "HEAL"
    new_epoch: int
    subject: bytes | None
    roster: tuple                # ((mid, sig_pk_raw, kem_pk_raw), ...) sorted
    fp_close: bytes
    close_seq: int
    sealed: tuple                # ((mid, eph_pub, ct), ...) sorted by mid
    proposal_sigs: tuple         # ((mid, sig), ...) over proposal_bytes
    coordinator: bytes
    coord_sig: bytes             # over digest() — binds every field above

    def context(self) -> bytes:
        return (proposal_bytes(self.op, self.new_epoch, self.subject)
                + b"".join(mid + s + k for mid, s, k in self.roster)
                + self.fp_close + struct.pack("!Q", self.close_seq))

    def digest(self) -> bytes:
        return H(self.context()
                 + b"".join(mid + eph + ct for mid, eph, ct in self.sealed))

    def roster_dict(self) -> dict[bytes, MemberKeys]:
        return {mid: MemberKeys(Ed25519PublicKey.from_public_bytes(s),
                                X25519PublicKey.from_public_bytes(k))
                for mid, s, k in self.roster}


class Member:
    def __init__(self, member_id: bytes, signing_key: Ed25519PrivateKey,
                 kem_key: X25519PrivateKey,
                 roster: dict[bytes, MemberKeys], epoch_secret: bytes,
                 window: int = DEFAULT_WINDOW, epoch: int = 0,
                 fp_close: bytes = b"\x00" * FP_LEN):
        self.id = member_id
        self.signing_key = signing_key
        self.kem_key = kem_key
        self.roster = roster
        self.epoch = epoch
        self.seq = 0  # next expected position
        self.ck = chain_init(epoch_secret, epoch, roster_hash(roster), fp_close)
        self.window = window
        self.seen: dict[int, Wire] = {}   # last `window` accepted wires
        self.buffer: dict[int, Wire] = {}  # future messages awaiting a gap fill
        self.hb_counter = 0                # our own heartbeat counter
        self.hb_seen: dict[bytes, int] = {}  # highest counter seen per sender

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
        keys = self.roster.get(wire.sender)
        if keys is None:
            return BadSignature(wire.seq)
        try:
            keys.sig_pk.verify(wire.sig, wire.signed_payload())
        except InvalidSignature:
            return BadSignature(wire.seq)

        if wire.epoch != self.epoch:
            return EpochMismatch(ours=self.epoch, theirs=wire.epoch)

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

    # --- heartbeats (§6) ---

    def heartbeat(self) -> Heartbeat:
        self.hb_counter += 1
        hb = Heartbeat(self.epoch, self.seq, self.id, self._fp(self.seq),
                       self.hb_counter, b"")
        return Heartbeat(hb.epoch, hb.seq, hb.sender, hb.fp, hb.counter,
                         self.signing_key.sign(hb.signed_payload()))

    def receive_heartbeat(self, hb: Heartbeat):
        keys = self.roster.get(hb.sender)
        if keys is None:
            return BadSignature(hb.seq)
        try:
            keys.sig_pk.verify(hb.sig, hb.signed_payload())
        except InvalidSignature:
            return BadSignature(hb.seq)

        if hb.counter <= self.hb_seen.get(hb.sender, 0):
            return StaleHeartbeat(hb.sender)
        self.hb_seen[hb.sender] = hb.counter

        if hb.epoch != self.epoch:
            return (PeerAhead(hb.sender, hb.epoch, hb.seq)
                    if hb.epoch > self.epoch else EpochMismatch(self.epoch,
                                                                hb.epoch))
        if hb.seq > self.seq:
            return PeerAhead(hb.sender, hb.epoch, hb.seq)

        # The sender claims a position at or behind ours, so we can check its
        # fingerprint against the history we hold. This is how a *silent*
        # stale clone is caught: it can sign, but it cannot produce the
        # fingerprint of a chain it fell off (§8).
        if hb.seq == self.seq:
            expected = self._fp(hb.seq)
        else:
            wire = self.seen.get(hb.seq)
            if wire is None:
                return None  # aged out of our window; nothing to compare
            expected = wire.fp
        if hb.fp != expected:
            return ChainDivergence(hb.sender, hb.seq)
        return None

    # --- Rung 1: retransmit (§7) ---

    def missing_range(self) -> tuple[int, int] | None:
        if not self.buffer:
            return None
        return (self.seq, min(self.buffer))

    def serve_retransmit(self, start: int, end: int) -> list[Wire]:
        return [self.seen[i] for i in range(start, end) if i in self.seen]

    # --- §9: membership ---

    def sign_proposal(self, op: str, subject: bytes | None) -> tuple[bytes, bytes]:
        return (self.id,
                self.signing_key.sign(proposal_bytes(op, self.epoch + 1, subject)))

    def make_epoch_change(self, op: str, subject: bytes | None = None,
                          subject_keys: MemberKeys | None = None,
                          proposal_sigs: tuple = ()) -> tuple[EpochChange, bytes]:
        """Coordinator side. Returns the change and the fresh epoch secret
        (the secret is returned only so tests can hand it to a joiner's
        constructor; on the wire the joiner unwraps its sealed copy)."""
        new_epoch = self.epoch + 1
        new_roster = dict(self.roster)
        if op == "JOIN":
            new_roster[subject] = subject_keys
        elif op == "EVICT":
            del new_roster[subject]
        roster_tuple = tuple(
            (mid, new_roster[mid].sig_pk.public_bytes_raw(),
             new_roster[mid].kem_pk.public_bytes_raw())
            for mid in sorted(new_roster))
        secret = os.urandom(32)
        partial = EpochChange(op, new_epoch, subject, roster_tuple,
                              self._fp(self.seq), self.seq, (), proposal_sigs,
                              self.id, b"")
        sealed = tuple(
            (mid, *seal(new_roster[mid].kem_pk, secret, partial.context()))
            for mid in sorted(new_roster))
        unsigned = EpochChange(op, new_epoch, subject, roster_tuple,
                               partial.fp_close, partial.close_seq, sealed,
                               proposal_sigs, self.id, b"")
        return (EpochChange(op, new_epoch, subject, roster_tuple,
                            partial.fp_close, partial.close_seq, sealed,
                            proposal_sigs, self.id,
                            self.signing_key.sign(unsigned.digest())), secret)

    def apply_epoch_change(self, ec: EpochChange):
        if ec.new_epoch != self.epoch + 1:
            return EpochMismatch(ours=self.epoch, theirs=ec.new_epoch)

        coord = self.roster.get(ec.coordinator)
        if coord is None:
            return BadSignature(ec.close_seq)
        unsigned = EpochChange(ec.op, ec.new_epoch, ec.subject, ec.roster,
                               ec.fp_close, ec.close_seq, ec.sealed,
                               ec.proposal_sigs, ec.coordinator, b"")
        try:
            coord.sig_pk.verify(ec.coord_sig, unsigned.digest())
        except InvalidSignature:
            return BadSignature(ec.close_seq)

        if ec.op == "EVICT":
            # §9 rule 2: quorum of the CURRENT roster, verified locally —
            # a unilateral evict is a partition weapon
            prop = proposal_bytes(ec.op, ec.new_epoch, ec.subject)
            valid = set()
            for mid, sig in ec.proposal_sigs:
                keys = self.roster.get(mid)
                if keys is None:
                    continue
                try:
                    keys.sig_pk.verify(sig, prop)
                    valid.add(mid)
                except InvalidSignature:
                    pass
            need = len(self.roster) // 2 + 1
            if len(valid) < need:
                return QuorumRejected(ec.new_epoch, have=len(valid), need=need)

        # §5.1: the epoch must cut over OUR history, at OUR position
        if ec.close_seq != self.seq or ec.fp_close != self._fp(self.seq):
            return ContinuityBreak(ec.new_epoch)

        new_roster = ec.roster_dict()
        if self.id not in new_roster:
            return Evicted(ec.new_epoch)

        eph, ct = next((e, c) for mid, e, c in ec.sealed if mid == self.id)
        try:
            secret = open_sealed(self.kem_key, eph, ct, ec.context())
        except InvalidTag:
            return BadSignature(ec.close_seq)

        self.roster = new_roster
        self.epoch = ec.new_epoch
        self.seq = 0
        self.ck = chain_init(secret, self.epoch, roster_hash(new_roster),
                             ec.fp_close)
        self.seen.clear()
        self.buffer.clear()
        # Heartbeat counters are per-epoch: a rejoining member restarts at 0,
        # so peers must forget the old counters or reject its heartbeats as
        # stale forever. The epoch number in the signed payload keeps a
        # cross-epoch replay from being useful.
        self.hb_counter = 0
        self.hb_seen.clear()
        return EpochChanged(self.epoch, ec.op)

    @classmethod
    def join(cls, member_id: bytes, signing_key: Ed25519PrivateKey,
             kem_key: X25519PrivateKey, ec: EpochChange,
             window: int = DEFAULT_WINDOW) -> "Member":
        """Joiner side. Note the trust asymmetry the spec doesn't state:
        a joiner has no history, so it CANNOT verify fp_close or the
        coordinator's roster — it trusts the bundle it was handed. Its
        protection is forward-looking only: from ck'_0 on, it's in lockstep."""
        secret_entry = next((e, c) for mid, e, c in ec.sealed if mid == member_id)
        secret = open_sealed(kem_key, *secret_entry, ec.context())
        m = cls.__new__(cls)
        m.id = member_id
        m.signing_key = signing_key
        m.kem_key = kem_key
        m.roster = ec.roster_dict()
        m.epoch = ec.new_epoch
        m.seq = 0
        m.ck = chain_init(secret, ec.new_epoch, roster_hash(m.roster),
                          ec.fp_close)
        m.window = window
        m.seen = {}
        m.buffer = {}
        m.hb_counter = 0
        m.hb_seen = {}
        return m
