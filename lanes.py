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
    epoch: int
    sender: bytes
    lane_seq: int
    fp: bytes
    body: bytes
    sig: bytes

    def header(self) -> bytes:
        return (b"lw" + struct.pack("!IB", self.epoch, len(self.sender))
                + self.sender + struct.pack("!Q", self.lane_seq) + self.fp)

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
class LaneEpochMismatch:
    ours: int
    theirs: int

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

@dataclass(frozen=True)
class LaneEpochChange:
    """Re-key every lane (EVICT or HEAL). Cuts over at a position vector; the
    braid over that vector binds the new epoch to the shared past (continuity),
    and the fresh secret — sealed per remaining member — locks out an evictee,
    who knew the old lane keys. Quorum-gated for EVICT (majority of the current
    roster), so no single member can re-key the swarm around another."""
    op: str                   # "EVICT" | "HEAL"
    new_epoch: int
    subject: bytes | None
    roster: tuple             # ((mid, sig_pk_raw, kem_pk_raw), ...) sorted
    close_vector: tuple       # ((lane, seq), ...) sorted — the cutover point
    braid_close: bytes        # braid over close_vector (continuity binding)
    sealed: tuple             # ((mid, eph, ct), ...) sorted — new secret per member
    proposal_sigs: tuple      # ((mid, sig), ...) over the proposal (EVICT quorum)
    coordinator: bytes
    coord_sig: bytes

    def proposal_bytes(self) -> bytes:
        return (b"tessera-lane-prop" + self.op.encode() + b"\x00"
                + struct.pack("!I", self.new_epoch) + (self.subject or b""))

    def context(self) -> bytes:
        r = b"".join(m + s + k for m, s, k in self.roster)
        v = b"".join(lane + struct.pack("!Q", seq) for lane, seq in self.close_vector)
        return self.proposal_bytes() + r + v + self.braid_close

    def digest(self) -> bytes:
        return H(self.context()
                 + b"".join(m + e + c for m, e, c in self.sealed))

    def roster_dict(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey)
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PublicKey)
        return {m: MemberKeys(Ed25519PublicKey.from_public_bytes(s),
                              X25519PublicKey.from_public_bytes(k))
                for m, s, k in self.roster}

@dataclass(frozen=True)
class LaneEpochChanged:
    epoch: int
    op: str

@dataclass(frozen=True)
class LaneEvicted:
    epoch: int

@dataclass(frozen=True)
class LaneContinuityBreak:
    """Our braid at the cutover vector disagrees with the coordinator's: the
    epoch is being cut over a history we don't share. We are forked."""
    epoch: int

@dataclass(frozen=True)
class LaneNeedsCatchup:
    """We haven't reached the cutover vector yet; catch up (NACK/resync) and
    re-apply. Not an error — the async analogue of §9's pending-EC buffering."""
    epoch: int

@dataclass(frozen=True)
class LaneQuorumRejected:
    epoch: int
    have: int
    need: int


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
        self.epoch = 0
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

    # --- bootstrap: establish the genesis secret (the first shared key) ---

    @staticmethod
    def make_genesis(coordinator_id, coordinator_sk, roster):
        """A designated coordinator samples the genesis secret and HPKE-seals
        it to every member's identity KEM key, signing the bundle. This is the
        concrete first-secret establishment the earlier draft assumed: it turns
        trusted *identity* keys (established out of band — provisioning, CA,
        DID) into a shared *group* secret. Returns (bundle, secret); the secret
        is returned only so a caller can also build the coordinator's own
        member — on the wire every member unseals its own copy."""
        secret = os.urandom(32)
        r_hash = roster_hash(roster)
        ctx = b"tessera-lane-genesis" + r_hash
        sealed = tuple((m, *seal(roster[m].kem_pk, secret, ctx))
                       for m in sorted(roster))
        roster_tuple = tuple(
            (m, roster[m].sig_pk.public_bytes_raw(),
             roster[m].kem_pk.public_bytes_raw()) for m in sorted(roster))
        unsigned = H(ctx + b"".join(m + e + c for m, e, c in sealed)
                     + b"".join(m + s + k for m, s, k in roster_tuple))
        bundle = (coordinator_id, roster_tuple, sealed,
                  coordinator_sk.sign(unsigned))
        return bundle, secret

    @classmethod
    def from_genesis(cls, member_id, signing_key, kem_key, bundle):
        """A member builds itself from a genesis bundle: verify the
        coordinator's signature (its identity is trusted via the roster),
        unseal our genesis secret, and initialise. Only a member the
        coordinator sealed to can join — a stranger has no sealed entry."""
        coord_id, roster_tuple, sealed, sig = bundle
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey)
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PublicKey)
        roster = {m: MemberKeys(Ed25519PublicKey.from_public_bytes(s),
                                X25519PublicKey.from_public_bytes(k))
                  for m, s, k in roster_tuple}
        r_hash = roster_hash(roster)
        ctx = b"tessera-lane-genesis" + r_hash
        unsigned = H(ctx + b"".join(m + e + c for m, e, c in sealed)
                     + b"".join(m + s + k for m, s, k in roster_tuple))
        roster[coord_id].sig_pk.verify(sig, unsigned)   # authenticate genesis
        eph, ct = next((e, c) for m, e, c in sealed if m == member_id)
        secret = open_sealed(kem_key, eph, ct, ctx)
        return cls(member_id, signing_key, kem_key, roster, secret)

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
        wire = LaneWire(self.epoch, self.id, seq, fp, b"", b"")
        header = wire.header()
        mk = self._mk(ck, self.id, seq)
        body = ChaCha20Poly1305(mk).encrypt(NONCE, salt + plaintext, header)
        sig = self.signing_key.sign(header + H(body))
        # advance own lane; receivers do the same when they process this wire
        self.lanes[self.id] = self._advance(ck, salt, plaintext, header)
        self.lane_seq[self.id] += 1
        w = LaneWire(self.epoch, self.id, seq, fp, body, sig)
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
        if wire.epoch != self.epoch:
            # older = stale noise; newer = we missed an epoch change (catch up
            # / apply the pending one). Mirrors the single chain's §6 case.
            return LaneEpochMismatch(self.epoch, wire.epoch)
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
        """Hash over (lane, seq, fingerprint) for every lane at our current
        position. Two members with identical lane state -> identical braid."""
        return self.braid_at(self.position_vector())

    def braid_at(self, vector) -> bytes | None:
        """Braid over a specified position vector, using recomputation for
        lanes we sit at and retained history for lanes we are past. Returns
        None if we cannot cover some position (behind, or aged out) — the
        caller must catch up first. This is what lets an epoch cut over a
        vector that members reached at different wall-clock times."""
        parts = []
        for lane, seq in vector:
            fp = self._fp_at(lane, seq)
            if fp is None:
                return None
            parts.append(lane + struct.pack("!Q", seq) + fp)
        return H(L_BRAID + b"".join(parts))

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

    # --- lane epoch change: EVICT / HEAL (the re-key operations) ---

    def sign_lane_proposal(self, op: str, subject: bytes | None):
        stub = LaneEpochChange(op, self.epoch + 1, subject, (), (), b"", (), (),
                               self.id, b"")
        return (self.id, self.signing_key.sign(stub.proposal_bytes()))

    def make_lane_epoch(self, op: str, subject: bytes | None = None,
                        proposal_sigs: tuple = ()) -> LaneEpochChange:
        new_epoch = self.epoch + 1
        new_roster = dict(self.roster)
        if op == "EVICT":
            del new_roster[subject]
        roster_tuple = tuple(
            (m, new_roster[m].sig_pk.public_bytes_raw(),
             new_roster[m].kem_pk.public_bytes_raw())
            for m in sorted(new_roster))
        close_vector = self.position_vector()
        braid_close = self.braid()
        secret = os.urandom(32)          # fresh: not derived from any old state
        stub = LaneEpochChange(op, new_epoch, subject, roster_tuple,
                               close_vector, braid_close, (), proposal_sigs,
                               self.id, b"")
        sealed = tuple(
            (m, *seal(new_roster[m].kem_pk, secret, stub.context()))
            for m in sorted(new_roster))
        unsigned = LaneEpochChange(op, new_epoch, subject, roster_tuple,
                                   close_vector, braid_close, sealed,
                                   proposal_sigs, self.id, b"")
        return LaneEpochChange(op, new_epoch, subject, roster_tuple,
                               close_vector, braid_close, sealed, proposal_sigs,
                               self.id, self.signing_key.sign(unsigned.digest()))

    def apply_lane_epoch(self, ec: LaneEpochChange):
        if ec.new_epoch != self.epoch + 1:
            return LaneNeedsCatchup(ec.new_epoch) if ec.new_epoch > self.epoch \
                else None
        coord = self.roster.get(ec.coordinator)
        if coord is None:
            return BadSignature(ec.coordinator)
        unsigned = LaneEpochChange(ec.op, ec.new_epoch, ec.subject, ec.roster,
                                   ec.close_vector, ec.braid_close, ec.sealed,
                                   ec.proposal_sigs, ec.coordinator, b"")
        try:
            coord.sig_pk.verify(ec.coord_sig, unsigned.digest())
        except InvalidSignature:
            return BadSignature(ec.coordinator)

        if ec.op == "EVICT":
            prop = LaneEpochChange(ec.op, ec.new_epoch, ec.subject, (), (), b"",
                                   (), (), ec.coordinator, b"").proposal_bytes()
            valid = set()
            for mid, sig in ec.proposal_sigs:
                k = self.roster.get(mid)
                if k is None:
                    continue
                try:
                    k.sig_pk.verify(sig, prop)
                    valid.add(mid)
                except InvalidSignature:
                    pass
            need = len(self.roster) // 2 + 1
            if len(valid) < need:
                return LaneQuorumRejected(ec.new_epoch, len(valid), need)

        # continuity: our braid at the cutover vector must match the coordinator
        mine = self.braid_at(ec.close_vector)
        if mine is None:
            return LaneNeedsCatchup(ec.new_epoch)   # not there yet; catch up
        if mine != ec.braid_close:
            return LaneContinuityBreak(ec.new_epoch)  # forked history

        new_roster = ec.roster_dict()
        if self.id not in new_roster:
            return LaneEvicted(ec.new_epoch)         # we are the subject
        eph, ct = next((e, c) for m, e, c in ec.sealed if m == self.id)
        try:
            secret = open_sealed(self.kem_key, eph, ct, ec.context())
        except InvalidTag:
            return BadSignature(ec.coordinator)

        # re-key every lane from the fresh secret, bound to braid_close so the
        # epoch chain isn't severed; reset positions and per-lane state
        self.roster = new_roster
        self.epoch = ec.new_epoch
        new_r = roster_hash(new_roster)
        self.lanes = {m: kdf(secret, L_INIT, m + new_r + ec.braid_close)
                      for m in new_roster}
        self.lane_seq = {m: 0 for m in new_roster}
        self.seen = {m: {} for m in new_roster}
        self.buffer = {m: {} for m in new_roster}
        self.fp_hist = {m: {} for m in new_roster}
        return LaneEpochChanged(self.epoch, ec.op)
