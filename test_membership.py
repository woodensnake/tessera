"""§9 epoch layer: one test per claim, including the honest negative ones."""

import copy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from tessera import (
    ContinuityBreak, Delivered, EpochChanged, EpochMismatch, Evicted, Fork,
    Member, MemberKeys, NeedsFullJoin, QuorumRejected, Resynced,
)
from test_tessera import broadcast, make_swarm


def chat(swarm, sender_idx, text):
    wire = swarm[sender_idx].send(text)
    return broadcast(swarm, wire)


def test_resync_returns_a_laggard_without_an_epoch_change():
    """§7 Rung 1.5: a returning member jumps to the current chain state via a
    peer's sealed grant. No epoch change, no re-key — the whole point, so it
    cannot cascade into a storm."""
    swarm = make_swarm(4)
    for i in range(6):
        chat(swarm, i % 4, f"msg {i}".encode())
    laggard = swarm[3]
    # simulate having fallen far behind: rewind its chain state
    laggard.epoch, laggard.seq, laggard.ck = 0, 2, b"\x00" * 32
    laggard.seen.clear()

    peer = swarm[0]
    grant = peer.make_resync(laggard.id)
    assert grant is not None
    res = laggard.apply_resync(grant)
    assert res == Resynced(epoch=peer.epoch, seq=peer.seq)
    assert laggard.ck == peer.ck        # now byte-identical to a lockstep peer
    assert peer.epoch == 0              # nobody re-keyed; still epoch 0

    # and the resynced laggard is back in lockstep: it sends and all accept
    results = chat(swarm, 3, b"back in sync")
    assert all(isinstance(ev[0], Delivered) for ev in results.values())
    assert len({m.ck for m in swarm}) == 1


def test_resync_refused_for_a_stranger():
    """Resync only re-admits a roster member; a stranger gets None and must
    take the quorum-gated JOIN path (§9)."""
    swarm = make_swarm(3)
    chat(swarm, 0, b"hello")
    assert swarm[0].make_resync(b"not-a-member") is None


def test_resync_falls_back_to_join_when_roster_changed():
    """If membership changed during the outage, the lightweight handoff is not
    enough — the returner is told to do a full JOIN."""
    swarm = make_swarm(4)
    chat(swarm, 0, b"before")
    laggard = swarm[3]
    laggard.seq, laggard.ck = 0, b"\x00" * 32  # fell behind

    # meanwhile the swarm evicts someone: roster (and epoch) move
    sigs = tuple(m.sign_proposal("EVICT", swarm[2].id) for m in swarm[:3])
    ec, _ = swarm[0].make_epoch_change("EVICT", swarm[2].id, proposal_sigs=sigs)
    for m in swarm[:2]:
        m.apply_epoch_change(ec)

    grant = swarm[0].make_resync(laggard.id)
    assert isinstance(laggard.apply_resync(grant), NeedsFullJoin)


def test_join_enters_lockstep_but_not_history():
    swarm = make_swarm(3)
    chat(swarm, 0, b"pre-join secret")
    recorded = swarm[1].send(b"also pre-join")
    broadcast(swarm, recorded)

    sk, kk = Ed25519PrivateKey.generate(), X25519PrivateKey.generate()
    ec, _ = swarm[0].make_epoch_change(
        "JOIN", b"newcomer", MemberKeys(sk.public_key(), kk.public_key()))
    for m in swarm:
        assert m.apply_epoch_change(ec) == EpochChanged(1, "JOIN")
    newcomer = Member.join(b"newcomer", sk, kk, ec)
    swarm.append(newcomer)

    # lockstep from ck'_0 on: newcomer sends and receives normally
    results = chat(swarm, 3, b"hello from the new agent")
    assert all(isinstance(ev[0], Delivered) for ev in results.values())
    assert len({m.ck for m in swarm}) == 1

    # but pre-join traffic is sealed history: the newcomer holds no epoch-0
    # state at all (epoch re-key on join = history privacy, §9)
    assert newcomer.epoch == 1
    assert newcomer.receive(recorded) == [EpochMismatch(ours=1, theirs=0)]


def test_evictee_locked_out_of_everything_forward():
    swarm = make_swarm(4)
    chat(swarm, 0, b"all four hear this")
    evictee = swarm[3]

    sigs = tuple(m.sign_proposal("EVICT", evictee.id) for m in swarm[:3])
    ec, _ = swarm[0].make_epoch_change("EVICT", evictee.id, proposal_sigs=sigs)
    remaining = swarm[:3]
    for m in remaining:
        assert m.apply_epoch_change(ec) == EpochChanged(1, "EVICT")
    # the evictee learns its fate from the same bundle: no sealed entry for it
    assert evictee.apply_epoch_change(ec) == Evicted(1)

    wire = remaining[0].send(b"post-eviction planning")
    results = broadcast(remaining, wire)
    assert all(isinstance(ev[0], Delivered) for ev in results.values())
    # the evictee still knows the OLD chain key; the fresh epoch secret was
    # never sealed to it, so the new chain is out of reach
    assert evictee.receive(wire) == [EpochMismatch(ours=0, theirs=1)]


def test_unilateral_evict_rejected_without_quorum():
    """§9 rule 2: eviction is not a coordinator's whim."""
    swarm = make_swarm(4)  # quorum = 3
    target = swarm[3]

    lone_sig = (swarm[0].sign_proposal("EVICT", target.id),)
    ec, _ = swarm[0].make_epoch_change("EVICT", target.id, proposal_sigs=lone_sig)
    verdicts = {m.id: m.apply_epoch_change(ec) for m in swarm[:3]}
    assert all(v == QuorumRejected(1, have=1, need=3) for v in verdicts.values())
    # nobody moved: the swarm still operates in epoch 0, target included
    results = chat(swarm, 3, b"still here")
    assert all(isinstance(ev[0], Delivered) for ev in results.values())


def test_fp_close_binds_epochs_across_forked_history():
    """§5.1: an epoch cannot be cut over a history we don't share — a forked
    member rejects the cutover instead of silently rejoining the majority."""
    swarm = make_swarm(3)
    a, b, c = swarm
    chat(swarm, 0, b"shared prefix")

    # c forks: it accepts a slot-1 message the others never saw
    stray = c.send(b"c's private history")
    c.receive(stray)
    w = a.send(b"majority's slot 1")
    a.receive(w)
    b.receive(w)

    ec, _ = a.make_epoch_change("HEAL")
    assert b.apply_epoch_change(ec) == EpochChanged(1, "HEAL")
    assert c.apply_epoch_change(ec) == ContinuityBreak(1)  # not a silent merge


def test_heal_shakes_off_chain_key_thief():
    """§9: fresh DH entropy is the only cure for a stolen ck — and it works,
    because the thief can't open any sealed epoch secret."""
    swarm = make_swarm(3)
    thief = copy.deepcopy(swarm[0])
    thief.kem_key = X25519PrivateKey.generate()  # stole ck, NOT the identity keys

    chat(swarm, 1, b"thief reads this fine")
    thief_events = thief.receive(swarm[0].seen[0])
    assert isinstance(thief_events[0], Delivered)

    ec, _ = swarm[0].make_epoch_change("HEAL")
    for m in swarm:
        assert m.apply_epoch_change(ec) == EpochChanged(1, "HEAL")
    # the thief sees the bundle too — but its sealed entry is addressed to
    # a key it doesn't have
    assert not isinstance(thief.apply_epoch_change(ec), EpochChanged)

    wire = swarm[1].send(b"healed: thief is gone")
    broadcast(swarm, wire)
    assert all(not isinstance(e, Delivered) for e in thief.receive(wire))


def test_heal_does_NOT_shake_identity_thief():
    """§8's honest caveat, demonstrated: a clone holding the identity keys
    receives the new epoch secret like the member it is. PCS is bounded by
    identity-key integrity."""
    swarm = make_swarm(3)
    clone = copy.deepcopy(swarm[0])  # full compromise: ck AND identity keys

    ec, _ = swarm[1].make_epoch_change("HEAL")
    for m in swarm:
        m.apply_epoch_change(ec)
    assert clone.apply_epoch_change(ec) == EpochChanged(1, "HEAL")

    wire = swarm[1].send(b"the heal did not help against this one")
    broadcast(swarm, wire)
    assert isinstance(clone.receive(wire)[0], Delivered)


def test_stale_epoch_change_rejected():
    """Quorum signatures bind the target epoch number: a captured EVICT
    bundle cannot be replayed later to re-evict a re-admitted member."""
    swarm = make_swarm(4)
    target = swarm[3]
    sigs = tuple(m.sign_proposal("EVICT", target.id) for m in swarm[:3])
    ec, _ = swarm[0].make_epoch_change("EVICT", target.id, proposal_sigs=sigs)
    for m in swarm[:3]:
        m.apply_epoch_change(ec)  # now in epoch 1

    # replaying the same bundle later is a no-op: it names epoch 1, we're in it
    assert swarm[0].apply_epoch_change(ec) == EpochMismatch(ours=1, theirs=1)
