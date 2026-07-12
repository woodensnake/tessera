"""Per-sender lanes (§11.1): the sequencer-free convergence property and
per-lane detection. The headline is test_any_delivery_order_converges — it
is the evidence that the perfect-sequencer idealization can be removed."""

import os
import random

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from lanes import (CloneEvidence, Delivered, Gap, LaneFork, LaneMember)
from tessera import MemberKeys


def make_lane_swarm(n=4):
    keys = {f"a{i}".encode(): (Ed25519PrivateKey.generate(),
                               X25519PrivateKey.generate()) for i in range(n)}
    roster = {mid: MemberKeys(sk.public_key(), kk.public_key())
              for mid, (sk, kk) in keys.items()}
    secret = os.urandom(32)
    return [LaneMember(mid, sk, kk, roster, secret)
            for mid, (sk, kk) in keys.items()]


def random_fifo_schedule(wires_by_sender, rng):
    """A random interleaving of all wires that preserves per-sender FIFO —
    i.e. a legal delivery order for a swarm with NO global sequencer, only
    per-link ordering."""
    queues = {s: list(ws) for s, ws in wires_by_sender.items()}
    order = []
    while any(queues.values()):
        s = rng.choice([s for s, q in queues.items() if q])
        order.append(queues[s].pop(0))
    return order


def test_any_delivery_order_converges():
    """THE property: with per-sender lanes there is no global order to agree
    on. Every member, fed the same messages in its OWN random (FIFO-per-
    sender) order, converges to byte-identical lane state — so a perfect
    sequencer is unnecessary. This is the validity gap the single-chain
    evaluation left open (EXPERIMENTS §8)."""
    swarm = make_lane_swarm(4)
    rng = random.Random(1)

    # every member sends several messages into its own lane
    wires_by_sender = {}
    for m in swarm:
        wires_by_sender[m.id] = [m.send(f"{m.id!r}#{i}".encode()) for i in range(5)]

    # deliver to each member in a DIFFERENT random FIFO-preserving order
    for m in swarm:
        others = {s: ws for s, ws in wires_by_sender.items() if s != m.id}
        for w in random_fifo_schedule(others, rng):
            evs = m.receive(w)
            assert all(not isinstance(e, (LaneFork, CloneEvidence)) for e in evs)

    # despite different delivery orders, all members agree on everything
    braids = {m.braid() for m in swarm}
    assert len(braids) == 1
    lane_states = {tuple(sorted(m.lanes.items())) for m in swarm}
    assert len(lane_states) == 1


def test_concurrent_senders_do_not_contend():
    """Two members 'simultaneously' send — different lanes, so no slot
    contention and no fork (the single chain's §5.2 race cannot arise)."""
    swarm = make_lane_swarm(3)
    a, b, c = swarm
    wa = a.send(b"from a, same instant")
    wb = b.send(b"from b, same instant")
    for m in (b, c):
        assert isinstance(m.receive(wa)[0], Delivered)
    for m in (a, c):
        assert isinstance(m.receive(wb)[0], Delivered)
    assert len({m.braid() for m in swarm}) == 1  # all converge, no fork


def test_lane_fork_is_detected_and_attributed():
    """A sender equivocating within its own lane (two bodies at one lane_seq)
    forks that lane; a receiver holding the other body raises evidence naming
    the sender. Two LaneMembers sharing the liar's identity + lane state stand
    in for the equivocating sender speaking twice at one position."""
    import copy
    swarm = make_lane_swarm(3)
    liar, x, y = swarm
    liar2 = copy.deepcopy(liar)          # same identity + lane state as liar

    w1 = liar.send(b"to x")              # both send at lane_seq 0,
    w2 = liar2.send(b"to y, different")  # different bodies
    assert w1.lane_seq == w2.lane_seq and w1.body != w2.body

    assert isinstance(x.receive(w1)[0], Delivered)
    # y took w2 first; now sees w1 at a past slot with different body
    assert isinstance(y.receive(w2)[0], Delivered)
    ev = y.receive(w1)[0]
    assert isinstance(ev, CloneEvidence) and ev.sender == liar.id


def test_braid_detects_lane_divergence():
    """Continuity via braids: members that saw the SAME message in a lane
    share a braid; one that advanced a lane on DIFFERENT content has a
    different braid — divergence in any single lane surfaces in the checkpoint.
    (Comparing at a shared position vector; the async checkpoint is §11.1.)"""
    import copy
    swarm = make_lane_swarm(4)
    sender, good1, good2, bad = swarm
    liar = copy.deepcopy(sender)

    w_good = sender.send(b"the real message")
    w_bad = liar.send(b"a different message")  # same lane_seq, different body

    good1.receive(w_good)
    good2.receive(w_good)
    bad.receive(w_bad)

    # all three are at the same position vector (one message in sender's lane)
    assert good1.position_vector() == good2.position_vector() == bad.position_vector()
    assert good1.braid() == good2.braid()      # same content -> same braid
    assert good1.braid() != bad.braid()        # the fork shows in the braid


def test_gap_then_catch_up_within_a_lane():
    swarm = make_lane_swarm(3)
    sender, rx, _ = swarm
    ws = [sender.send(f"m{i}".encode()) for i in range(4)]
    # deliver out of order: rx misses m1, gets m2 (buffers), then m1 fills gap
    assert isinstance(rx.receive(ws[0])[0], Delivered)
    assert isinstance(rx.receive(ws[2])[0], Gap)      # m2 arrives early
    evs = rx.receive(ws[1])                            # m1 fills the gap
    kinds = [type(e).__name__ for e in evs]
    assert "Delivered" in kinds
    assert rx.lane_seq[sender.id] == 3                 # caught up through m2
