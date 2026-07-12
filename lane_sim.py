"""Lane liveness simulator (PROTOCOL §11.1).

The single-chain sim (sim.py) needs a perfect global sequencer, so all its
liveness numbers are upper bounds. This sim has NO sequencer: every agent
broadcasts into its own lane, the lossy network reorders and drops freely,
and members recover per lane. The headline metric is convergence — do all
honest members reach one shared braid — established without any global order.

Reuses the discrete-event engine and network models from sim.py; only the
swarm/agent logic is lane-specific.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from sim import DRAIN, GilbertElliott, IIDLoss, Network, Poisson, Sim
from lanes import (BraidDivergence, BraidOK, CloneEvidence, Delivered, Gap,
                   LaneFork, LaneMember, LaneResynced)
from tessera import MemberKeys

NACK_TIMEOUT = 0.5
BRAID_INTERVAL = 5.0
RESYNC_LAG = 32        # if this far behind on a lane, resync instead of NACK


@dataclass
class LaneMetrics:
    sent: int = 0
    delivered: int = 0
    gaps: int = 0
    nacks: int = 0
    retransmits: int = 0
    lane_forks: int = 0            # must be 0 in an honest run
    braid_claims: int = 0
    braid_divergences: int = 0     # must be 0 in an honest run
    resyncs: int = 0               # returning members brought current, no re-key
    rekeys: int = 0                # global re-keys — should stay 0 (no storm)
    converged: bool = False        # all honest members share one braid at end
    distinct_braids_at_end: int = 0
    network_dropped: int = 0

    def to_dict(self):
        return dict(self.__dict__)


class LaneAgent:
    def __init__(self, swarm, member: LaneMember, sk, kk):
        self.swarm = swarm
        self.member = member
        self.id = member.id
        self.sk, self.kk = sk, kk
        self.online = True
        self.nack_armed = False
        self.resyncing = False

    def send(self):
        if not self.online:
            return
        w = self.member.send(f"{self.id!r}@{self.swarm.sim.now:.2f}".encode())
        self.swarm.metrics.sent += 1
        # no sequencer: just broadcast the lane wire to everyone
        for a in self.swarm.agents:
            if a is not self:
                self.swarm.network.unicast(self.id, a.id, a.on_wire, w)

    def on_wire(self, wire):
        if not self.online:
            return
        for ev in self.member.receive(wire):
            if isinstance(ev, Delivered):
                self.swarm.metrics.delivered += 1
            elif isinstance(ev, Gap):
                self.swarm.metrics.gaps += 1
                self._arm_nack(ev.sender)
            elif isinstance(ev, (LaneFork, CloneEvidence)):
                self.swarm.metrics.lane_forks += 1  # honest run: stays 0

    # --- per-lane gap recovery (no global order needed) ---

    def _arm_nack(self, lane):
        if not self.nack_armed:
            self.nack_armed = True
            self.swarm.sim.after(NACK_TIMEOUT, self._nack)

    def _nack(self):
        self.nack_armed = False
        if not self.online:
            return
        # find any lane with a gap and ask a peer for the missing range
        for lane, buf in self.member.buffer.items():
            if not buf:
                continue
            need = (self.member.lane_seq[lane], min(buf))
            peer = self.swarm.pick_peer(self)
            if peer is not None:
                self.swarm.metrics.nacks += 1
                self.swarm.network.unicast(self.id, peer.id, peer.serve,
                                           self, lane, need)
        if any(self.member.buffer.values()):
            self._arm_nack(None)  # retry until caught up

    def serve(self, requester, lane, need):
        if not self.online:
            return
        start, end = need
        for seq in range(start, end):
            w = self.member.seen[lane].get(seq)
            if w is not None:
                self.swarm.metrics.retransmits += 1
                self.swarm.network.unicast(self.id, requester.id,
                                           requester.on_wire, w)

    # --- braid checkpoint (divergence detection, §11.1) ---

    def emit_braid(self):
        if not self.online:
            return
        claim = self.member.make_braid_claim()
        self.swarm.metrics.braid_claims += 1
        for a in self.swarm.agents:
            if a is not self:
                self.swarm.network.unicast(self.id, a.id, a.on_braid, claim)

    def on_braid(self, claim):
        if not self.online:
            return
        res = self.member.verify_braid_claim(claim)
        if isinstance(res, BraidDivergence):
            self.swarm.metrics.braid_divergences += 1  # honest run: stays 0
            return
        # A braid claim also reveals lanes where the claimant is AHEAD of us —
        # the lost-tail case that no in-lane successor would expose (the lane
        # analogue of heartbeat-driven recovery, §6). If we are only slightly
        # behind, NACK the gap; if we are FAR behind on any lane (returned from
        # an outage), resync the whole head in one shot — no re-key, no storm.
        far = any(seq - self.member.lane_seq[lane] > RESYNC_LAG
                  for lane, seq, _fp in claim.entries)
        if far and not self.resyncing:
            self._request_resync()
            return
        for lane, seq, _fp in claim.entries:
            if seq > self.member.lane_seq[lane]:
                self._request_lane(lane, self.member.lane_seq[lane], seq)

    def _request_lane(self, lane, start, end):
        peer = self.swarm.pick_peer(self)
        if peer is not None:
            self.swarm.metrics.nacks += 1
            self.swarm.network.unicast(self.id, peer.id, peer.serve,
                                       self, lane, (start, end))

    # --- lane resync (§7 Rung 1.5): storm-free return of a far-behind member ---

    def _request_resync(self):
        if not (self.online and not self.resyncing):
            return
        self.resyncing = True
        peer = self.swarm.pick_peer(self)
        if peer is not None:
            self.swarm.network.unicast(self.id, peer.id, peer.serve_resync, self)
        self.swarm.sim.after(NACK_TIMEOUT, self._resync_retry)

    def _resync_retry(self):
        if self.resyncing and self.online:      # grant lost; ask again
            self.resyncing = False
            self._request_resync()

    def serve_resync(self, requester):
        if not self.online:
            return
        grant = self.member.make_lane_resync(requester.id)
        if grant is not None:
            self.swarm.network.unicast(self.id, requester.id,
                                       requester.on_resync_grant, grant)

    def on_resync_grant(self, grant):
        if not (self.online and self.resyncing):
            return
        if isinstance(self.member.apply_lane_resync(grant), LaneResynced):
            self.resyncing = False
            self.swarm.metrics.resyncs += 1


class LaneSwarm:
    def __init__(self, sim, network, n):
        self.sim, self.network = sim, network
        self.metrics = LaneMetrics()
        ids = [f"agent-{i:03d}".encode() for i in range(n)]
        privs = {mid: (Ed25519PrivateKey.generate(), X25519PrivateKey.generate())
                 for mid in ids}
        roster = {mid: MemberKeys(sk.public_key(), kk.public_key())
                  for mid, (sk, kk) in privs.items()}
        secret = os.urandom(32)
        self.agents = [LaneAgent(self, LaneMember(mid, sk, kk, roster, secret),
                                 sk, kk)
                       for mid, (sk, kk) in privs.items()]

    def start_traffic(self, rate, stop):
        for agent in self.agents:
            Poisson(rate).start(self.sim, agent.send, stop)

    def start_braids(self, stop):
        def loop(agent):
            if self.sim.now >= stop:
                return
            agent.emit_braid()
            self.sim.after(BRAID_INTERVAL, lambda: loop(agent))
        for i, agent in enumerate(self.agents):
            self.sim.after(BRAID_INTERVAL * (i + 1) / len(self.agents),
                           lambda a=agent: loop(a))

    def pick_peer(self, requester):
        pool = [a for a in self.agents
                if a is not requester and a.online and not a.resyncing]
        return self.sim.rng.choice(pool) if pool else None

    def finalize(self):
        m = self.metrics
        m.network_dropped = self.network.dropped
        online = [a for a in self.agents if a.online]
        braids = {a.member.braid() for a in online}
        m.distinct_braids_at_end = len(braids)
        m.converged = len(braids) == 1
        return m


def run_lane_trial(n=5, duration=400, seed=0, rate=0.2, loss=0.0,
                   burst_len=None, offline_windows=None):
    sim = Sim(seed)
    loss_model = (GilbertElliott.from_mean(loss, burst_len)
                  if burst_len else IIDLoss(loss))
    network = Network(sim, loss_model)
    swarm = LaneSwarm(sim, network, n)
    swarm.start_traffic(rate, stop=duration - DRAIN)
    swarm.start_braids(stop=duration - 5.0)
    for mid, (start, end) in (offline_windows or {}).items():
        agent = next(a for a in swarm.agents if a.id == mid)
        sim.after(start, lambda a=agent: setattr(a, "online", False))
        sim.after(end, lambda a=agent: setattr(a, "online", True))
    sim.run(duration)
    return swarm.finalize().to_dict()


def main():
    ap = argparse.ArgumentParser(description="Tessera lane (sequencer-free) sim")
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--duration", type=float, default=400.0)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--rate", type=float, default=0.2)
    ap.add_argument("--loss", type=float, default=0.0)
    ap.add_argument("--burst-len", type=float, default=None)
    args = ap.parse_args()
    print(json.dumps(run_lane_trial(
        n=args.n, duration=args.duration, seed=args.seed, rate=args.rate,
        loss=args.loss, burst_len=args.burst_len), indent=2))


if __name__ == "__main__":
    main()
