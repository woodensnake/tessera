"""Per-sender lanes (PROTOCOL §11.1) — removing the perfect sequencer.

The single-chain design (tessera.py) needs a total order on messages, which
the whole M1-M3 evaluation supplied via a perfect global sequencer — its
biggest validity gap (EXPERIMENTS §8). This module prototypes the way out.

Idea: give each sender its OWN chain (a "lane"). A member's message advances
only its own lane; every member tracks one chain per sender. Because only a
sender writes its own lane, ordering within a lane is trivial (the sender is
the sole author) and messages from *different* senders never share a slot —
so there is nothing to globally order. Concurrent sends commit without
coordination; the slot-confirmation latency of the single chain (§11.7)
disappears.

Continuity is recovered by BRAID: a hash over every lane's fingerprint at a
position vector. Two members with identical lane state produce the same
braid; any lane divergence surfaces at the next braid. The single chain's
"one gap locks you out" becomes "one gap in *some* lane locks you out of
*that* lane," detected at braid time.

Scope of this prototype: the sequencer-free convergence property (the point)
and per-lane detection + quiescent braids. The fully asynchronous braid
checkpoint — agreeing *which* position vector to braid over while lanes keep
moving — is the remaining open problem (see test docstrings and §11.1).
"""

from __future__ import annotations

import os
import struct
from collections import deque
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from tessera import (
    FP_LEN, NONCE, SALT_LEN, H, MemberKeys, kdf, open_sealed, roster_hash,
    seal,
)

L_INIT = b"tessera-lane-init"
L_MSG = b"tessera-lane-msg"
L_FP = b"tessera-lane-fp"
L_ADV = b"tessera-lane-adv"
L_BRAID = b"tessera-lane-braid"
L_RESYNC = b"tessera-lane-resync"


@dataclass(frozen=True)
class LaneWire:
    sender: bytes
    lane_seq: int
    fp: bytes
    body: bytes
    sig: bytes

    def header(self) -> bytes:
        return (b"lw" + struct.pack("!B", len(self.sender)) + self.sender
                + struct.pack("!Q", self.lane_seq) + self.fp)

    def signed(self) -> bytes:
        return self.header() + H(self.body)


# dispatch events (mirror the single-chain ones, but per lane)
@dataclass(frozen=True)
class Delivered:
    sender: bytes
    lane_seq: int
    plaintext: bytes

@dataclass(frozen=True)
class Gap:
    sender: bytes
    expected: int
    got: int

@dataclass(frozen=True)
class LaneFork:
    sender: bytes
    lane_seq: int

@dataclass(frozen=True)
class Duplicate:
    sender: bytes
    lane_seq: int

@dataclass(frozen=True)
class CloneEvidence:
    sender: bytes
    lane_seq: int
    first: LaneWire
    second: LaneWire

@dataclass(frozen=True)
class BadSignature:
    sender: bytes

@dataclass(frozen=True)
class BraidClaim:
    """§11.1 asynchronous checkpoint: a signed statement of one member's view
    of every lane's fingerprint at its current position vector. A peer at a
    different position can still verify it — for each lane it recomputes (if it
    is AT that position) or looks up its retained history (if it is PAST it) —
    and localize any divergence to the exact lane and seq. This is what makes
    divergence detection latency ≈ the braid interval, with no shared clock or
    global order."""
    claimant: bytes
    entries: tuple           # ((lane_owner, seq, fp), ...) sorted by lane_owner
    sig: bytes

    def signed(self) -> bytes:
        body = b"".join(mid + struct.pack("!Q", seq) + fp
                        for mid, seq, fp in self.entries)
        return b"tessera-braid-claim" + self.claimant + body

@dataclass(frozen=True)
class BraidOK:
    """Every lane we could check agreed. `partial` is True if some lanes were
    ahead of us and left unchecked (we'll catch them at a later braid)."""
    claimant: bytes
    partial: bool

@dataclass(frozen=True)
class BraidDivergence:
    """A lane's fingerprint in the claim disagrees with our history: the
    claimant is on a different chain in that lane. Localized, attributable."""
    claimant: bytes
    lane: bytes
    seq: int

@dataclass(frozen=True)
class LaneResyncGrant:
    """§7 Rung 1.5 on lanes: a lockstep peer seals its *current* state for
    every lane (key + position) to a returning roster member. As in the single
    chain, this mints no epoch and re-keys no one, so a wave of returns costs N
    independent resyncs, not a cascade — the storm cannot form. Even more
    natural on lanes: the returner just adopts each lane's current head."""
    returner: bytes
    roster_hash: bytes
    eph: bytes
    ct: bytes
    grantor: bytes
    sig: bytes

    def signed(self) -> bytes:
        return (L_RESYNC + self.returner + self.roster_hash + self.eph
                + self.ct + self.grantor)

    def context(self) -> bytes:
        return L_RESYNC + b"ctx" + self.returner + self.roster_hash

@dataclass(frozen=True)
class LaneResynced:
    returner: bytes

@dataclass(frozen=True)
class LaneNeedsFullJoin:
    reason: str


class LaneMember:
    """One chain per sender. No global sequencer: a member advances its own
    lane on send, and lane[X] on receiving X's message. Members converge to
    identical per-lane state under ANY delivery order that respects per-sender
    FIFO — which is the whole point (test_any_delivery_order_converges)."""

    def __init__(self, member_id, signing_key, kem_key, roster, epoch_secret):
        self.id = member_id
        self.signing_key = signing_key
        self.kem_key = kem_key
        self.roster = roster
        r_hash = roster_hash(roster)
        # every member derives the same initial key for every lane
        self.lanes = {mid: kdf(epoch_secret, L_INIT, mid + r_hash)
                      for mid in roster}
        self.lane_seq = {mid: 0 for mid in roster}
        self.seen = {mid: {} for mid in roster}   # lane -> {seq: wire}
        self.buffer = {mid: {} for mid in roster}  # lane -> {seq: wire}
        # bounded per-lane fingerprint history, so we can verify a braid claim
        # from a peer that is at a DIFFERENT position than us. fp_hist[s][v] is
        # the fingerprint of lane s at position v — which equals the wire.fp of
        # the wire at seq v, and equals what a member sitting AT position v
        # would compute for its current position.
        self.fp_hist = {mid: {} for mid in roster}
        self.fp_keep = 256                        # entries retained per lane

    # --- key schedule, per lane ---

    @staticmethod
    def _mk(ck, sender, seq):
        return kdf(ck, L_MSG, sender + struct.pack("!Q", seq))

    @staticmethod
    def _fp(ck, sender, seq):
        return kdf(ck, L_FP, sender + struct.pack("!Q", seq))[:FP_LEN]

    @staticmethod
    def _advance(ck, salt, plaintext, header):
        return kdf(ck, L_ADV, H(salt + plaintext) + H(header))

    # --- send: advances only our OWN lane ---

    def send(self, plaintext: bytes) -> LaneWire:
        seq = self.lane_seq[self.id]
        ck = self.lanes[self.id]
        salt = os.urandom(SALT_LEN)
        fp = self._fp(ck, self.id, seq)
        wire = LaneWire(self.id, seq, fp, b"", b"")
        header = wire.header()
        mk = self._mk(ck, self.id, seq)
        body = ChaCha20Poly1305(mk).encrypt(NONCE, salt + plaintext, header)
        sig = self.signing_key.sign(header + H(body))
        # advance own lane; receivers do the same when they process this wire
        self.lanes[self.id] = self._advance(ck, salt, plaintext, header)
        self.lane_seq[self.id] += 1
        w = LaneWire(self.id, seq, fp, body, sig)
        self.seen[self.id][seq] = w
        self._record_fp(self.id, seq, fp)
        return w

    def _record_fp(self, sender: bytes, seq: int, fp: bytes) -> None:
        h = self.fp_hist[sender]
        h[seq] = fp
        if len(h) > self.fp_keep:
            del h[min(h)]

    # --- receive: advances lane[sender] ---

    def receive(self, wire: LaneWire) -> list:
        events = [self._dispatch(wire)]
        s = wire.sender
        while (isinstance(events[-1], Delivered)
               and self.lane_seq[s] in self.buffer[s]):
            events.append(self._dispatch(self.buffer[s].pop(self.lane_seq[s])))
        return events

    def _dispatch(self, wire: LaneWire):
        s = wire.sender
        keys = self.roster.get(s)
        if keys is None:
            return BadSignature(s)
        try:
            keys.sig_pk.verify(wire.sig, wire.signed())
        except InvalidSignature:
            return BadSignature(s)
        if s == self.id:
            return Duplicate(s, wire.lane_seq)  # our own echo; already advanced

        exp = self.lane_seq[s]
        if wire.lane_seq > exp:
            self.buffer[s][wire.lane_seq] = wire
            return Gap(s, exp, wire.lane_seq)
        if wire.lane_seq < exp:
            prior = self.seen[s].get(wire.lane_seq)
            if prior is not None and H(prior.body) != H(wire.body):
                return CloneEvidence(s, wire.lane_seq, prior, wire)
            return Duplicate(s, wire.lane_seq)

        ck = self.lanes[s]
        if wire.fp != self._fp(ck, s, wire.lane_seq):
            return LaneFork(s, wire.lane_seq)
        mk = self._mk(ck, s, wire.lane_seq)
        try:
            payload = ChaCha20Poly1305(mk).decrypt(NONCE, wire.body, wire.header())
        except InvalidTag:
            return LaneFork(s, wire.lane_seq)
        salt, pt = payload[:SALT_LEN], payload[SALT_LEN:]
        self.lanes[s] = self._advance(ck, salt, pt, wire.header())
        self.seen[s][wire.lane_seq] = wire
        self._record_fp(s, wire.lane_seq, wire.fp)
        self.lane_seq[s] += 1
        return Delivered(s, wire.lane_seq, pt)

    # --- BRAID: swarm-wide consistency checkpoint over all lanes ---

    def braid(self) -> bytes:
        """Hash over (sender, lane_seq, lane fingerprint) for every lane, in
        canonical order. Two members with identical lane state -> identical
        braid; any lane divergence changes it. Meaningful to *compare* only at
        a shared position vector (e.g. quiescence); the asynchronous-checkpoint
        version is the §11.1 open problem."""
        parts = b"".join(
            mid + struct.pack("!Q", self.lane_seq[mid])
            + self._fp(self.lanes[mid], mid, self.lane_seq[mid])
            for mid in sorted(self.roster))
        return H(L_BRAID + parts)

    def position_vector(self) -> tuple:
        return tuple((mid, self.lane_seq[mid]) for mid in sorted(self.roster))

    # --- asynchronous braid checkpoint (§11.1) ---

    def make_braid_claim(self) -> BraidClaim:
        """Sign our current view: for each lane, its fingerprint at our current
        position. Cheap (N entries) and emitted on the braid timer."""
        entries = tuple(
            (mid, self.lane_seq[mid],
             self._fp(self.lanes[mid], mid, self.lane_seq[mid]))
            for mid in sorted(self.roster))
        claim = BraidClaim(self.id, entries, b"")
        return BraidClaim(self.id, entries,
                          self.signing_key.sign(claim.signed()))

    def verify_braid_claim(self, claim: BraidClaim):
        keys = self.roster.get(claim.claimant)
        if keys is None:
            return BadSignature(claim.claimant)
        try:
            keys.sig_pk.verify(claim.sig, claim.signed())
        except InvalidSignature:
            return BadSignature(claim.claimant)

        partial = False
        for lane, seq, fp in claim.entries:
            if lane not in self.roster:
                return BraidDivergence(claim.claimant, lane, seq)  # roster split
            mine = self._fp_at(lane, seq)
            if mine is None:
                partial = True          # we are behind (or it aged out) here
                continue
            if mine != fp:
                return BraidDivergence(claim.claimant, lane, seq)
        return BraidOK(claim.claimant, partial)

    def _fp_at(self, lane: bytes, seq: int) -> bytes | None:
        """Our fingerprint for `lane` at position `seq`: recomputed if we are
        sitting there now, from retained history if we are past it, else None
        (we are behind, or it aged out of history)."""
        if seq == self.lane_seq[lane]:
            return self._fp(self.lanes[lane], lane, seq)
        if seq < self.lane_seq[lane]:
            return self.fp_hist[lane].get(seq)
        return None

    # --- lane resync (§7 Rung 1.5, storm-free recovery) ---

    def make_lane_resync(self, returner_id: bytes) -> LaneResyncGrant | None:
        """Seal our current head (key + position) for every lane to a returning
        roster member. None if the returner is not a member (must full-join)."""
        keys = self.roster.get(returner_id)
        if keys is None:
            return None
        r_hash = roster_hash(self.roster)
        payload = b"".join(
            struct.pack("!B", len(lane)) + lane + self.lanes[lane]
            + struct.pack("!Q", self.lane_seq[lane])
            for lane in sorted(self.lanes))
        stub = LaneResyncGrant(returner_id, r_hash, b"", b"", self.id, b"")
        eph, ct = seal(keys.kem_pk, payload, stub.context())
        grant = LaneResyncGrant(returner_id, r_hash, eph, ct, self.id, b"")
        return LaneResyncGrant(returner_id, r_hash, eph, ct, self.id,
                               self.signing_key.sign(grant.signed()))

    def apply_lane_resync(self, grant: LaneResyncGrant):
        if grant.returner != self.id:
            return None
        gk = self.roster.get(grant.grantor)
        if gk is None:
            return BadSignature(grant.grantor)
        try:
            gk.sig_pk.verify(grant.sig, grant.signed())
        except InvalidSignature:
            return BadSignature(grant.grantor)
        if grant.roster_hash != roster_hash(self.roster):
            return LaneNeedsFullJoin("roster changed during outage")
        payload = open_sealed(self.kem_key, grant.eph, grant.ct, grant.context())
        i = 0
        while i < len(payload):
            ln = payload[i]; i += 1
            lane = payload[i:i + ln]; i += ln
            ck = payload[i:i + 32]; i += 32
            seq = struct.unpack("!Q", payload[i:i + 8])[0]; i += 8
            # NEVER adopt a peer's view of our OWN lane: we are its sole author,
            # we sent nothing while away, so our own state is authoritative and
            # the peer's copy may even be stale. Overwriting it would rewind our
            # send position and fork our own lane.
            if lane == self.id:
                continue
            self.lanes[lane] = ck
            self.lane_seq[lane] = seq
            self.buffer[lane].clear()
            self.fp_hist[lane].clear()
        return LaneResynced(self.id)
