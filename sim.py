"""Tessera simulator core (EXPERIMENTS.md M1).

Discrete-event simulation of an honest swarm running the real protocol
code from tessera.py over a lossy, delaying, partitioning network, with
the §7 recovery ladder driven by simulated timers.

Idealizations (per EXPERIMENTS.md §8, stated up front):
- The ordering layer is a perfect global sequencer: commits are
  instantaneous and totally ordered. All liveness results are therefore
  upper bounds.
- Heartbeats and adversaries land with M2; in an honest swarm with a
  perfect sequencer there is nothing for them to detect.
- Traffic intents that fire while an agent is behind are suppressed (and
  counted), not queued: a real agent would send fresh state on recovery
  anyway.

Usage: python sim.py --n 5 --rate 0.2 --loss 0.02 --duration 600 --seed 1
"""

from __future__ import annotations

import argparse
import heapq
import json
import random
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from tessera import (
    DEFAULT_WINDOW, BadSignature, ChainDivergence, CloneEvidence,
    ContinuityBreak, Delivered, EpochChanged, EpochMismatch, Evicted, Fork,
    Gap, Member, MemberKeys, PeerAhead, StaleHeartbeat,
)

# ---------------------------------------------------------------- engine

class Sim:
    def __init__(self, seed: int):
        self.now = 0.0
        self.rng = random.Random(seed)
        self._q: list = []
        self._i = 0

    def after(self, delay: float, fn) -> None:
        heapq.heappush(self._q, (self.now + delay, self._i, fn))
        self._i += 1

    def run(self, until: float) -> None:
        while self._q and self._q[0][0] <= until:
            self.now, _, fn = heapq.heappop(self._q)
            fn()
        self.now = until

# ------------------------------------------------------------- loss models

class IIDLoss:
    def __init__(self, p: float):
        self.p = p

    def lost(self, rng, link) -> bool:
        return rng.random() < self.p


class GilbertElliott:
    """Two-state burst loss, one chain per link (state advances per packet)."""

    def __init__(self, p_gb: float, p_bg: float, loss_good: float, loss_bad: float):
        self.p_gb, self.p_bg = p_gb, p_bg
        self.loss = {False: loss_good, True: loss_bad}
        self.state: dict = {}  # link -> in_bad

    @classmethod
    def from_mean(cls, p: float, burst_len: float, loss_bad: float = 0.5,
                  loss_good: float = 0.0):
        """Parameterize from target overall loss p and mean bad-state dwell
        (in packets)."""
        pi_b = (p - loss_good) / (loss_bad - loss_good)
        assert 0 < pi_b < 1, "unreachable target loss for these state rates"
        p_bg = 1.0 / burst_len
        p_gb = pi_b / (1 - pi_b) * p_bg
        return cls(p_gb, p_bg, loss_good, loss_bad)

    def lost(self, rng, link) -> bool:
        bad = self.state.get(link, False)
        bad = (rng.random() < self.p_gb) if not bad else (rng.random() >= self.p_bg)
        self.state[link] = bad
        return rng.random() < self.loss[bad]

# ---------------------------------------------------------------- network

@dataclass
class Partition:
    start: float
    end: float
    group_a: frozenset  # member ids; everyone else is group B

    def severed(self, now: float, src: bytes, dst: bytes) -> bool:
        return (self.start <= now < self.end
                and (src in self.group_a) != (dst in self.group_a))


class Network:
    def __init__(self, sim: Sim, loss, delay=(0.010, 0.050),
                 partitions: list[Partition] = ()):  # delay: uniform range, s
        self.sim, self.loss, self.delay = sim, loss, delay
        self.partitions = list(partitions)
        self.dropped = 0

    def unicast(self, src: bytes, dst: bytes, fn, *args) -> None:
        if any(p.severed(self.sim.now, src, dst) for p in self.partitions):
            self.dropped += 1
            return
        if self.loss.lost(self.sim.rng, (src, dst)):
            self.dropped += 1
            return
        self.sim.after(self.sim.rng.uniform(*self.delay), lambda: fn(*args))

# ---------------------------------------------------------------- traffic

class Poisson:
    def __init__(self, rate: float):
        self.rate = rate

    def start(self, sim: Sim, fire, stop: float) -> None:
        def tick():
            if sim.now >= stop:
                return
            fire()
            sim.after(sim.rng.expovariate(self.rate), tick)
        sim.after(sim.rng.expovariate(self.rate), tick)


class MMPP:
    """2-state Markov-modulated Poisson: calm rate r, burst rate ratio*r.
    Approximation: an in-flight gap is not resampled on state switch."""

    def __init__(self, rate: float, ratio: float = 10.0,
                 dwell_calm: float = 60.0, dwell_burst: float = 10.0):
        self.rates = (rate, rate * ratio)
        self.dwells = (dwell_calm, dwell_burst)

    def start(self, sim: Sim, fire, stop: float) -> None:
        state = {"burst": False}

        def switch():
            if sim.now >= stop:
                return
            state["burst"] = not state["burst"]
            sim.after(sim.rng.expovariate(1.0 / self.dwells[state["burst"]]), switch)

        def tick():
            if sim.now >= stop:
                return
            fire()
            sim.after(sim.rng.expovariate(self.rates[state["burst"]]), tick)

        sim.after(sim.rng.expovariate(1.0 / self.dwells[False]), switch)
        sim.after(sim.rng.expovariate(self.rates[False]), tick)

# ---------------------------------------------------------------- metrics

@dataclass
class Detection:
    """First alarm at an honest member (EXPERIMENTS §5). `latency` is measured
    from the adversary's INJECTION instant, not its first action — the
    stricter choice, so a lurking adversary gets no flattering numbers."""
    kind: str            # Fork | CloneEvidence | ChainDivergence | ContinuityBreak
    accuser: bytes
    accused: bytes | None
    at_time: float
    latency: float
    positions: int       # chain positions elapsed since injection


@dataclass
class Metrics:
    sent: int = 0
    suppressed_sends: int = 0
    delivered: int = 0
    gaps: int = 0
    nacks: int = 0
    retransmits_served: int = 0
    rung1_recoveries: int = 0
    rejoin_requests: int = 0
    rejoins: int = 0
    epoch_changes: int = 0
    messages_lost_to_laggards: int = 0
    continuity_breaks: int = 0
    forks: int = 0
    network_dropped: int = 0
    behind_at_end: int = 0
    swarm_dead: bool = False
    recovery_times: list = field(default_factory=list)
    # --- adversary accounting (M2) ---
    forged_accepted: int = 0       # MUST be 0: a forged wire was Delivered
    stale_heartbeats: int = 0      # replayed heartbeats caught by counter
    detections: list = field(default_factory=list)
    adversary_reads: int = 0       # plaintexts an eavesdropper/thief recovered
    adversary_blind_from: float | None = None  # when it lost the chain
    culprit: bytes | None = None   # who was actually compromised
    adversary: str | None = None   # taxonomy id (A1..A6), None = honest run

    def to_dict(self) -> dict:
        skip = {"recovery_times", "detections", "culprit"}
        d = {k: v for k, v in self.__dict__.items() if k not in skip}
        rt = sorted(self.recovery_times)
        d["recoveries"] = len(rt)
        d["recovery_p50"] = rt[len(rt) // 2] if rt else None
        d["recovery_max"] = rt[-1] if rt else None
        first = self.detections[0] if self.detections else None
        d["detected"] = first is not None
        d["detection_kind"] = first.kind if first else None
        d["detection_latency"] = first.latency if first else None
        d["detection_positions"] = first.positions if first else None
        d["detection_count"] = len(self.detections)
        # attribution is correct only if the FIRST alarm names the actual
        # culprit; naming an innocent is the RQ1 kill criterion
        d["attribution_correct"] = (
            None if first is None or self.culprit is None
            else first.accused == self.culprit)
        d["false_positive"] = self.adversary is None and bool(self.detections)
        return d

# ---------------------------------------------------------------- swarm

NACK_TIMEOUT = 0.5     # s before a laggard asks for a replay, and between retries
REJOIN_RETRY = 2.0     # s between rejoin request attempts
DEATH_STALL = 60.0     # s without a commit while intents fire = swarm death
HEARTBEAT_T = 10.0     # s between heartbeats (PROTOCOL §6, sim-layer version)
DRAIN = 30.0           # s of no new traffic at the end so trials end quiescent


class Agent:
    def __init__(self, swarm: "Swarm", member_id: bytes,
                 sk: Ed25519PrivateKey, kk: X25519PrivateKey, member: Member):
        self.swarm = swarm
        self.id = member_id
        self.sk, self.kk = sk, kk
        self.member = member
        self.alive = True          # member of the current roster
        self.online = True         # reachable via the network
        self.pending_ec = None     # epoch change awaiting catch-up
        self.nack_pending = False
        self.rejoining = False
        self.behind_since: float | None = None
        self.known_head = 0        # highest same-epoch seq seen in heartbeats

    # --- state queries ---

    def in_lockstep(self) -> bool:
        return (self.member.epoch == self.swarm.epoch
                and self.member.seq == self.swarm.next_slot
                and not self.member.buffer and self.pending_ec is None)

    def _mark_behind(self) -> None:
        if self.behind_since is None:
            self.behind_since = self.swarm.sim.now

    def _check_recovered(self) -> None:
        if (self.behind_since is not None and not self.member.buffer
                and self.pending_ec is None and not self.rejoining
                and self.known_head <= self.member.seq
                and self.member.epoch == self.swarm.epoch):
            self.swarm.metrics.recovery_times.append(
                self.swarm.sim.now - self.behind_since)
            self.behind_since = None

    # --- receive paths ---

    def on_wire(self, wire) -> None:
        if not self.online:
            return
        for ev in self.member.receive(wire):
            if isinstance(ev, Delivered):
                self.swarm.metrics.delivered += 1
                if getattr(wire, "forged", False):
                    self.swarm.metrics.forged_accepted += 1  # MUST stay 0
            elif isinstance(ev, Gap):
                self.swarm.metrics.gaps += 1
                self._mark_behind()
                self._arm_nack()
            elif isinstance(ev, EpochMismatch) and ev.theirs > ev.ours:
                # we missed an epoch change; ask for a replay of the bundle
                self._mark_behind()
                self.swarm.request_ec_replay(self)
            elif isinstance(ev, Fork):
                self.swarm.metrics.forks += 1  # must stay 0 in honest runs
                self.swarm.record_detection("Fork", self.id, wire.sender,
                                            ev.position)
            elif isinstance(ev, CloneEvidence):
                self.swarm.record_detection("CloneEvidence", self.id,
                                            ev.sender, ev.seq)
        self._maybe_apply_pending_ec()
        self._check_recovered()

    def on_epoch_change(self, ec) -> None:
        if not self.online:
            return
        if ec.op == "JOIN" and ec.subject == self.id and self.rejoining:
            self.member = Member.join(self.id, self.sk, self.kk, ec)
            self.rejoining = False
            self.pending_ec = None
            self.known_head = 0
            self.swarm.metrics.rejoins += 1
            self._check_recovered()
            return
        res = self.member.apply_epoch_change(ec)
        if isinstance(res, EpochChanged):
            self.pending_ec = None
            self.known_head = 0
        elif isinstance(res, ContinuityBreak) and ec.close_seq > self.member.seq:
            # not a fork — we're behind the cutover point; catch up, then apply
            self.pending_ec = ec
            self._mark_behind()
            self._arm_nack()
        elif isinstance(res, ContinuityBreak):
            self.swarm.metrics.continuity_breaks += 1  # must stay 0 honest
            self.swarm.record_detection("ContinuityBreak", self.id,
                                        ec.coordinator, ec.close_seq)
        elif isinstance(res, Evicted):
            self.alive = False
        self._check_recovered()

    def _maybe_apply_pending_ec(self) -> None:
        if self.pending_ec and self.member.seq == self.pending_ec.close_seq:
            self.on_epoch_change(self.pending_ec)

    # --- Rung 1: NACK / retransmit ---

    def _arm_nack(self) -> None:
        if not self.nack_pending:
            self.nack_pending = True
            self.swarm.sim.after(NACK_TIMEOUT, self._nack)

    def _nack(self) -> None:
        self.nack_pending = False
        if not (self.online and self.alive) or self.rejoining:
            return
        rng_range = self.member.missing_range()
        if rng_range is None and self.pending_ec:
            rng_range = (self.member.seq, self.pending_ec.close_seq)
        if rng_range is None and self.known_head > self.member.seq:
            # a heartbeat told us we're behind even though nothing is
            # buffered — the lost-tail case no buffered wire can reveal
            rng_range = (self.member.seq, self.known_head)
        if rng_range is None:
            return
        peer = self.swarm.pick_peer(self)
        if peer is not None:
            self.swarm.metrics.nacks += 1
            self.swarm.network.unicast(self.id, peer.id,
                                       peer.serve_nack, self, rng_range)
        self._arm_nack()  # retry until recovered or escalated

    def serve_nack(self, requester: "Agent", rng_range) -> None:
        if not self.online:
            return
        start, end = rng_range
        wires = (self.member.serve_retransmit(start, end)
                 if self.member.epoch == requester.member.epoch else [])
        for w in wires:
            self.swarm.metrics.retransmits_served += 1
            self.swarm.network.unicast(self.id, requester.id,
                                       requester.on_replayed_wire, w)
        if not wires and (self.member.epoch > requester.member.epoch
                          or self.member.seq >= end):
            # aged out of every window (or epoch moved on): Rung 2
            self.swarm.network.unicast(self.id, requester.id,
                                       requester.on_aged_out)

    def on_replayed_wire(self, wire) -> None:
        had_gap = bool(self.member.buffer) or self.pending_ec is not None
        self.on_wire(wire)
        if had_gap and not self.member.buffer and self.pending_ec is None:
            self.swarm.metrics.rung1_recoveries += 1

    # --- heartbeats (PROTOCOL §6, real signed messages) ---

    def emit_heartbeat(self) -> None:
        if self.online and self.alive and not self.rejoining:
            hb = self.member.heartbeat()
            for a in self.swarm.agents:
                if a is not self:
                    self.swarm.network.unicast(self.id, a.id, a.on_heartbeat, hb)

    def on_heartbeat(self, hb) -> None:
        if not self.online or self.rejoining:
            return
        ev = self.member.receive_heartbeat(hb)
        if isinstance(ev, PeerAhead):
            self._mark_behind()
            if ev.epoch > self.member.epoch:
                self.swarm.request_ec_replay(self)
            else:
                self.known_head = max(self.known_head, ev.seq)
                self._arm_nack()
        elif isinstance(ev, ChainDivergence):
            # a signer whose fingerprint disagrees with our history: the
            # silent-clone tripwire (§8)
            self.swarm.record_detection("ChainDivergence", self.id,
                                        ev.sender, ev.position)
        elif isinstance(ev, StaleHeartbeat):
            self.swarm.metrics.stale_heartbeats += 1
        elif isinstance(ev, BadSignature):
            pass  # impostor: rejected, nothing to detect (§8)
        self._check_recovered()

    def on_aged_out(self) -> None:
        if not self.rejoining and self.online:
            self.rejoining = True
            self.swarm.metrics.messages_lost_to_laggards += max(
                0, self.swarm.total_commits - self.member.seq
                if self.member.epoch == self.swarm.epoch else 0)
            self._request_rejoin()

    # --- Rung 2: rejoin ---

    def _request_rejoin(self) -> None:
        if not (self.rejoining and self.online):
            return
        self.swarm.metrics.rejoin_requests += 1
        coord = self.swarm.pick_peer(self, prefer_lockstep=True)
        if coord is not None:
            self.swarm.network.unicast(self.id, coord.id,
                                       coord.serve_rejoin, self)
        self.swarm.sim.after(REJOIN_RETRY, self._request_rejoin)

    def serve_rejoin(self, requester: "Agent") -> None:
        if not (self.online and self.in_lockstep()):
            return  # requester's retry timer will try someone else
        keys = MemberKeys(requester.sk.public_key(), requester.kk.public_key())
        ec, _ = self.member.make_epoch_change("JOIN", requester.id, keys)
        self.swarm.commit_epoch_change(ec)


class Swarm:
    """Owns the agents, the perfect sequencer, and the metrics."""

    def __init__(self, sim: Sim, network: Network, n: int,
                 window: int = DEFAULT_WINDOW):
        self.sim, self.network = sim, network
        self.metrics = Metrics()
        self.epoch = 0
        self.next_slot = 0
        self.total_commits = 0
        self.last_commit = 0.0
        self.last_ec = None
        self.injected_at: float | None = None
        self.injected_positions = 0
        self.culprit: bytes | None = None
        self.wiretap = None  # optional passive adversary (A1/A2)

        import os
        ids = [f"agent-{i:03d}".encode() for i in range(n)]
        privs = {mid: (Ed25519PrivateKey.generate(), X25519PrivateKey.generate())
                 for mid in ids}
        roster = {mid: MemberKeys(sk.public_key(), kk.public_key())
                  for mid, (sk, kk) in privs.items()}
        secret = os.urandom(32)
        self.agents = [Agent(self, mid, sk, kk,
                             Member(mid, sk, kk, roster, secret, window=window))
                       for mid, (sk, kk) in privs.items()]

    def start_traffic(self, traffic, stop: float) -> None:
        for agent in self.agents:
            traffic.start(self.sim, lambda a=agent: self.want_send(a), stop)

    def start_heartbeats(self, stop: float) -> None:
        def loop(agent):
            if self.sim.now >= stop:
                return
            agent.emit_heartbeat()
            self.sim.after(HEARTBEAT_T, lambda: loop(agent))
        for i, agent in enumerate(self.agents):
            # stagger so heartbeats don't arrive as a synchronized volley
            self.sim.after(HEARTBEAT_T * (i + 1) / len(self.agents),
                           lambda a=agent: loop(a))

    # --- sequencer (perfect, by declared idealization) ---

    def want_send(self, agent: Agent) -> None:
        if not (agent.alive and agent.online) or not agent.in_lockstep():
            self.metrics.suppressed_sends += 1
            return
        wire = agent.member.send(f"t={self.sim.now:.3f}".encode())
        self.metrics.sent += 1
        self.next_slot += 1
        self.total_commits += 1
        self.last_commit = self.sim.now
        if self.wiretap is not None:
            self.wiretap.on_broadcast(wire)
        for a in self.agents:
            self.network.unicast(agent.id, a.id, a.on_wire, wire)

    def commit_epoch_change(self, ec) -> None:
        if ec.new_epoch != self.epoch + 1:
            return  # a competing/stale proposal lost the race; ignore
        self.epoch = ec.new_epoch
        self.next_slot = 0
        self.last_ec = ec
        self.last_commit = self.sim.now
        self.metrics.epoch_changes += 1
        for a in self.agents:
            self.network.unicast(ec.coordinator, a.id, a.on_epoch_change, ec)

    def request_ec_replay(self, agent: Agent) -> None:
        if self.last_ec is not None:
            self.network.unicast(b"sequencer", agent.id,
                                 agent.on_epoch_change, self.last_ec)

    def pick_peer(self, requester: Agent, prefer_lockstep: bool = False):
        pool = [a for a in self.agents
                if a is not requester and a.alive and a.online
                and not getattr(a, "is_adversary", False)
                and (a.in_lockstep() if prefer_lockstep else True)]
        return self.sim.rng.choice(pool) if pool else None

    # --- adversary accounting (M2) ---

    def inject(self, culprit: bytes) -> None:
        """Mark the instant an adversary enters. Detection latency is measured
        from here (EXPERIMENTS §5)."""
        self.injected_at = self.sim.now
        self.injected_positions = self.total_commits
        self.culprit = culprit

    def record_detection(self, kind: str, accuser: bytes, accused: bytes | None,
                         position: int) -> None:
        if self.injected_at is None:
            # an alarm with no adversary present is a false positive: the
            # single best canary for dispatch bugs (EXPERIMENTS §5)
            self.metrics.detections.append(
                Detection(kind, accuser, accused, self.sim.now, 0.0, 0))
            return
        self.metrics.detections.append(Detection(
            kind=kind, accuser=accuser, accused=accused,
            at_time=self.sim.now,
            latency=self.sim.now - self.injected_at,
            positions=self.total_commits - self.injected_positions))

    # --- end-of-run accounting ---

    def finalize(self, duration: float) -> Metrics:
        m = self.metrics
        m.network_dropped = self.network.dropped
        m.behind_at_end = sum(1 for a in self.agents
                              if a.alive and a.online
                              and not getattr(a, "is_adversary", False)
                              and not a.in_lockstep())
        m.swarm_dead = (duration - self.last_commit) > DEATH_STALL
        m.culprit = self.culprit
        return m

# ---------------------------------------------------------------- runner

def run_trial(n: int = 5, duration: float = 600.0, seed: int = 0,
              rate: float = 0.1, loss: float = 0.0,
              burst_len: float | None = None, bursty_traffic: bool = False,
              partitions: list[Partition] = (),
              offline_windows: dict | None = None,
              window: int = DEFAULT_WINDOW) -> dict:
    """One seeded trial; returns the metrics dict. offline_windows maps
    member id -> (start, end) during which that agent is unreachable."""
    sim = Sim(seed)
    loss_model = (GilbertElliott.from_mean(loss, burst_len)
                  if burst_len else IIDLoss(loss))
    network = Network(sim, loss_model, partitions=partitions)
    traffic = MMPP(rate) if bursty_traffic else Poisson(rate)
    swarm = Swarm(sim, network, n, window=window)
    swarm.start_traffic(traffic, stop=duration - DRAIN)
    swarm.start_heartbeats(stop=duration - 5.0)

    for mid, (start, end) in (offline_windows or {}).items():
        agent = next(a for a in swarm.agents if a.id == mid)
        sim.after(start, lambda a=agent: setattr(a, "online", False))
        sim.after(end, lambda a=agent: setattr(a, "online", True))

    sim.run(duration)
    return swarm.finalize(duration).to_dict()


def main() -> None:
    ap = argparse.ArgumentParser(description="Tessera honest-swarm simulator")
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--duration", type=float, default=600.0)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--rate", type=float, default=0.1, help="msgs/s per agent")
    ap.add_argument("--loss", type=float, default=0.0)
    ap.add_argument("--burst-len", type=float, default=None,
                    help="mean burst length (packets); enables Gilbert-Elliott")
    ap.add_argument("--bursty-traffic", action="store_true")
    args = ap.parse_args()
    print(json.dumps(run_trial(
        n=args.n, duration=args.duration, seed=args.seed, rate=args.rate,
        loss=args.loss, burst_len=args.burst_len,
        bursty_traffic=args.bursty_traffic), indent=2))


if __name__ == "__main__":
    main()
