"""Adversary harness (EXPERIMENTS.md M2, taxonomy §4).

Each adversary is a parameterized program run against the same seeded
simulator as the honest swarm. They tap the network and, where their
capability allows, inject wires. What each one is *allowed to know* is the
whole point, so it is enforced structurally: an adversary holds only the
state its capability grants (A1 sees ciphertext; A2 additionally holds a
stolen chain key; A3 holds a full state snapshot including identity keys).

Everything here attacks the in-memory simulation only. The goal is to
measure Tessera's detection claims (RQ1), not to attack anything real.
"""

from __future__ import annotations

import copy
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from tessera import (
    FP_LEN, LABEL_ADV, LABEL_FP, LABEL_MSG, NONCE, SALT_LEN, H, Member, Wire,
    kdf,
)


def _derive_mk(ck: bytes, epoch: int, seq: int, sender: bytes) -> bytes:
    """The thief's copy of Member._mk — same key schedule, no Member needed."""
    return kdf(ck, LABEL_MSG, struct.pack("!IQ", epoch, seq) + sender)


def _fp_from(ck: bytes, epoch: int, seq: int) -> bytes:
    return kdf(ck, LABEL_FP, struct.pack("!IQ", epoch, seq))[:FP_LEN]


def _advance(ck: bytes, salt: bytes, plaintext: bytes, header: bytes) -> bytes:
    return kdf(ck, LABEL_ADV, H(salt + plaintext) + H(header))


def _tag_forged(wire: Wire) -> Wire:
    """Mark a wire as adversarial so the swarm can assert it is never
    Delivered (metrics.forged_accepted must stay 0). The tag is sim
    bookkeeping, invisible to the protocol — honest members judge the wire
    purely on its signature and AEAD tag."""
    object.__setattr__(wire, "forged", True)
    return wire


class Wiretap:
    """Sees each broadcast wire, captured independently with probability c
    (EXPERIMENTS §4: the capture-gap rate is 1-c). Base class for the passive
    adversaries A1/A2. The swarm calls on_broadcast once per message; no
    per-recipient tapping, so c is a clean per-message capture probability."""

    def __init__(self, sim, capture: float = 1.0):
        self.sim = sim
        self.capture = capture
        self.saw_gap = False

    def on_broadcast(self, wire) -> None:
        if self.sim.rng.random() < self.capture:
            self.observe_wire(wire)
        else:
            self.saw_gap = True  # a gap: the salt makes it permanent (§5.2)

    def observe_wire(self, wire) -> None:
        pass  # A1 reads nothing; A2 overrides to try decryption


class Eavesdropper(Wiretap):
    """A1: reads wire only. Confirms the floor — ciphertext yields nothing,
    so this adversary is never detected and never reads a plaintext."""

    id = "A1"


class KeyThief(Wiretap):
    """A2: A1 plus a one-time copy of a member's chain key (NOT identity
    keys), taken at injection. It can decrypt and advance the chain for as
    long as it captures every message; the first gap freezes its chain
    forever (§5.2). Measures confidentiality-exposure duration, not
    detection — a passive thief emits nothing to detect."""

    id = "A2"

    def __init__(self, sim, victim: Member, capture: float = 1.0):
        super().__init__(sim, capture)
        # a stolen snapshot of just the chain-key state, no signing power
        self.ck = victim.ck
        self.epoch = victim.epoch
        self.seq = victim.seq
        self.blind = False
        self.reads = 0
        self.blind_from: float | None = None

    def observe_wire(self, wire) -> None:
        if self.blind or wire.epoch != self.epoch or wire.seq != self.seq:
            return  # out of step: a heal or a missed message already froze us
        mk = _derive_mk(self.ck, self.epoch, wire.seq, wire.sender)
        try:
            payload = ChaCha20Poly1305(mk).decrypt(NONCE, wire.body,
                                                   wire.header_bytes())
        except InvalidTag:
            self._go_blind()
            return
        salt, plaintext = payload[:SALT_LEN], payload[SALT_LEN:]
        self.reads += 1
        self.ck = _advance(self.ck, salt, plaintext, wire.header_bytes())
        self.seq += 1

    def on_broadcast(self, wire) -> None:
        if self.sim.rng.random() < self.capture:
            self.observe_wire(wire)
        elif not self.blind:
            self._go_blind()  # missed a message: chain unrecoverable

    def _go_blind(self) -> None:
        self.blind = True
        if self.blind_from is None:
            self.blind_from = self.sim.now


def _inject(swarm, src, wire, subset=None):
    """Deliver an adversarial wire through the real network to honest members
    (or a subset), exactly as an honest broadcast would travel."""
    for a in swarm.agents:
        if getattr(a, "is_adversary", False):
            continue
        if subset is not None and a.id not in subset:
            continue
        swarm.network.unicast(src, a.id, a.on_wire, wire)


class Clone(Wiretap):
    """A3: a full-state snapshot (chain key + identity keys + roster) taken at
    injection. Two detectable behaviours plus one honest negative:
      speaks=True, stale=False -> a live clone alongside the live victim; it
                             speaks a different body at a slot the swarm has
                             already committed -> CloneEvidence (H1b).
      speaks=True, stale=True  -> snapshot-restore of an offline victim; it
                             speaks new content at its frozen (still-in-window)
                             slot -> CloneEvidence (§8: "detected on its next
                             message").
      speaks=False             -> a silent clone. NOT detected — see the
                             finding below. This is H1c, and it is broader
                             than PROTOCOL §8 first claimed.

    Finding (surfaced by running it): a *silent* clone is undetectable by
    fingerprint, whether synced or stale. A clone frozen at a past position
    holds the CORRECT fingerprint for that position, so its heartbeat is
    indistinguishable from an honest member that is merely behind. "Behind"
    is not "forked." Detection requires the clone to SPEAK a contradiction;
    the passive-heartbeat detection PROTOCOL §8 implied does not exist."""

    id = "A3"

    def __init__(self, sim, swarm, victim, capture=1.0, speaks=True, stale=False):
        super().__init__(sim, capture)
        self.swarm = swarm
        self.victim_id = victim.id
        self.member = copy.deepcopy(victim.member)  # ck + keys + roster
        self.speaks = speaks
        self.stale = stale
        self.active = False
        self.spoke = False

    def activate(self) -> None:
        self.active = True
        if self.speaks and self.stale:
            # Speak at the FROZEN slot after a delay long enough that the swarm
            # has committed past it, so honest members hold seen[frozen] and
            # catch the contradiction. Speaking at the live frontier instead
            # would be a race: an uncontested wire at the current slot from a
            # holder of the identity key is, cryptographically, just the victim
            # sending — indistinguishable, hence not detected. Detection needs
            # an ALREADY-COMMITTED slot.
            self.sim.after(3.0, lambda: self._speak_at(self.member.seq,
                                                       self.member.ck))

    def on_broadcast(self, wire) -> None:
        if not self.active:
            return
        if (self.speaks and not self.stale and not self.spoke
                and wire.seq == self.member.seq):
            # Build the competing wire now (while we still hold ck at this
            # slot), but DELAY its delivery so every honest member commits the
            # real wire first. Otherwise the clone's wire races the real one,
            # splitting honest members into forks blamed on innocents — which
            # is exactly what an undelayed version did in testing.
            self.spoke = True
            seq, ck = wire.seq, self.member.ck
            self.sim.after(0.3, lambda: self._speak_at(seq, ck))
        if self.sim.rng.random() < self.capture:
            self.member.receive(wire)  # stay in sync while it can

    def _speak_at(self, seq: int, ck: bytes) -> None:
        """Inject a validly-signed wire with NEW content at `seq`. It is not
        _tag_forged: the clone holds the real identity key, so this is a
        genuine (if treacherous) message. The point is the contradiction with
        the swarm's committed body at `seq`, caught as CloneEvidence."""
        salt = b"\x01" * SALT_LEN
        mk = _derive_mk(ck, self.member.epoch, seq, self.victim_id)
        header = Wire(0, self.member.epoch, seq, self.victim_id,
                      _fp_from(ck, self.member.epoch, seq), b"", b"").header_bytes()
        body = ChaCha20Poly1305(mk).encrypt(NONCE, salt + b"clone-divergent-work",
                                            header)
        w = Wire(0, self.member.epoch, seq, self.victim_id,
                 _fp_from(ck, self.member.epoch, seq), body,
                 self.member.signing_key.sign(header + H(body)))
        _inject(self.swarm, self.victim_id, w)


class Equivocator:
    """A4: a legitimate member that sends two different bodies for the same
    slot to two disjoint halves of the swarm. The halves advance on different
    plaintext and fork; the next honest wire to cross the divide fails its
    fingerprint check -> Fork, attributed to the equivocator by the signed
    headers on the two contradictory wires (§8)."""

    id = "A4"

    def __init__(self, sim, swarm, malicious_agent):
        self.sim = sim
        self.swarm = swarm
        self.agent = malicious_agent  # a real member, now dishonest

    def activate(self) -> None:
        m = self.agent.member
        ids = [a.id for a in self.swarm.agents
               if not getattr(a, "is_adversary", False) and a.id != self.agent.id]
        half = set(ids[: len(ids) // 2])
        other = set(ids[len(ids) // 2:])
        # NOT _tag_forged: both wires are validly signed by the equivocator.
        # Delivering one is not "accepting a forgery" — the attack is the
        # contradiction between them, caught as a Fork. forged_accepted is
        # reserved for wires that should be cryptographically unacceptable.
        wire_a = m.send(b"equivocation-A")
        wire_b = m.send(b"equivocation-B")  # same seq, different body
        _inject(self.swarm, self.agent.id, wire_a, subset=half)
        _inject(self.swarm, self.agent.id, wire_b, subset=other)
        m.receive(wire_a)  # the attacker commits to one side


class Impostor:
    """A6: no keys at all. Injects wires it cannot validly sign; every honest
    member rejects them (BadSignature). The claim is a zero: forged_accepted
    must never leave 0. It cannot fork, clone, or equivocate — it simply
    cannot speak (§8)."""

    id = "A6"

    def __init__(self, sim, swarm, target_id):
        self.sim = sim
        self.swarm = swarm
        self.target_id = target_id  # identity it tries to impersonate
        self.captured = None

    def on_broadcast(self, wire) -> None:
        self.captured = wire  # remember a real wire to tamper with

    def activate(self) -> None:
        if self.captured is None:
            return
        w = self.captured
        forged_body = bytes([w.body[0] ^ 0xFF]) + w.body[1:]  # break the tag
        forged = _tag_forged(Wire(w.ver, w.epoch, w.seq, self.target_id,
                                  w.fp, forged_body, w.sig))
        _inject(self.swarm, self.target_id, forged)


# ---------------------------------------------------------------- runner

from sim import (DRAIN, GilbertElliott, IIDLoss, Network, Poisson, Sim, Swarm)

ADVERSARIES = ("A1", "A2", "A3", "A3-stale", "A3-silent", "A4", "A6")


def run_adversary_trial(adversary: str, n: int = 5, duration: float = 600.0,
                        seed: int = 0, rate: float = 0.2, loss: float = 0.0,
                        capture: float = 1.0, inject_at: float = 100.0,
                        burst_len: float | None = None) -> dict:
    """One seeded trial with one adversary injected at `inject_at`. Returns the
    metrics dict, extended with adversary-specific fields."""
    sim = Sim(seed)
    loss_model = (GilbertElliott.from_mean(loss, burst_len)
                  if burst_len else IIDLoss(loss))
    network = Network(sim, loss_model)
    swarm = Swarm(sim, network, n)
    swarm.metrics.adversary = adversary
    swarm.start_traffic(Poisson(rate), stop=duration - DRAIN)
    swarm.start_heartbeats(stop=duration - 5.0)

    victim = swarm.agents[0]
    holder = {"adv": None}

    def inject():
        swarm.inject(victim.id)
        adv = _build(adversary, sim, swarm, victim, capture)
        holder["adv"] = adv
        if isinstance(adv, Wiretap):
            swarm.wiretap = adv        # A1/A2/A3 tap the broadcast stream
        if hasattr(adv, "activate"):
            adv.activate()

    sim.after(inject_at, inject)
    sim.run(duration)

    m = swarm.finalize(duration)
    d = m.to_dict()
    adv = holder["adv"]
    d["adversary_reads"] = getattr(adv, "reads", 0)
    d["adversary_blind_from"] = getattr(adv, "blind_from", None)
    d["adversary_saw_gap"] = getattr(adv, "saw_gap", None)
    return d


def _build(adversary, sim, swarm, victim, capture):
    if adversary == "A1":
        return Eavesdropper(sim, capture)
    if adversary == "A2":
        return KeyThief(sim, victim.member, capture)
    if adversary == "A3":
        return Clone(sim, swarm, victim, capture, speaks=True)
    if adversary == "A3-stale":
        # snapshot-restore of a now-offline victim that then speaks new content
        # at its frozen (still-in-window) slot -> CloneEvidence
        victim.online = False
        return Clone(sim, swarm, victim, capture=0.0, speaks=True, stale=True)
    if adversary == "A3-silent":
        # a silent clone: undetectable by fingerprint (H1c), synced or not
        return Clone(sim, swarm, victim, capture=1.0, speaks=False, stale=False)
    if adversary == "A4":
        return Equivocator(sim, swarm, victim)
    if adversary == "A6":
        return Impostor(sim, swarm, victim.id)
    raise ValueError(adversary)
