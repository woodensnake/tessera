"""Each test demonstrates one security claim from PROTOCOL.md."""

import copy
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from tessera import (
    NONCE, SALT_LEN, BadSignature, CloneEvidence, Delivered, Duplicate, Fork,
    Gap, H, Member, Wire, kdf, LABEL_ADV,
)


def make_swarm(n=3, window=64):
    keys = {f"agent-{i}".encode(): Ed25519PrivateKey.generate() for i in range(n)}
    roster = {mid: sk.public_key() for mid, sk in keys.items()}
    epoch_secret = os.urandom(32)
    return [Member(mid, sk, roster, epoch_secret, window=window)
            for mid, sk in keys.items()]


def broadcast(members, wire):
    """The ordering layer: delivering a wire makes it the slot winner."""
    return {m.id: m.receive(wire) for m in members}


def test_normal_operation_keeps_swarm_in_lockstep():
    swarm = make_swarm(3)
    for i, sender in enumerate([0, 1, 2, 0, 1]):
        wire = swarm[sender].send(f"msg {i}".encode())
        results = broadcast(swarm, wire)
        for events in results.values():
            assert events == [Delivered(i, swarm[sender].id, f"msg {i}".encode())]
    assert len({m.ck for m in swarm}) == 1
    assert {m.seq for m in swarm} == {5}


def test_gap_lockout_for_key_thief():
    """§5.2: a thief with the current chain key who misses one message is
    locked out permanently."""
    swarm = make_swarm(2)
    thief = copy.deepcopy(swarm[0])  # full state compromise at position 0

    w0 = swarm[0].send(b"public enough")
    broadcast(swarm, w0)
    assert isinstance(thief.receive(w0)[0], Delivered)  # thief tracks fine

    w1 = swarm[1].send(b"the one that got away")
    broadcast(swarm, w1)  # thief never sees w1

    w2 = swarm[0].send(b"secret after the gap")
    events = thief.receive(w2)
    # thief buffers w2 as a gap; without w1's ciphertext its chain is
    # frozen at 1, and no future message will ever decrypt for it
    assert events == [Gap(expected=1, got=2)]
    w3 = swarm[0].send(b"still locked out")
    broadcast(swarm, w3)
    assert all(not isinstance(e, Delivered) for e in thief.receive(w3))


def test_salt_defeats_dictionary_attack_through_gap():
    """§5.2: even a thief who GUESSES the missed plaintext exactly cannot
    advance the chain — the salt inside the AEAD payload is unguessable."""
    swarm = make_swarm(2)
    thief = copy.deepcopy(swarm[0])

    missed = swarm[1].send(b"ACK")  # low-entropy, fully guessed by the thief
    broadcast(swarm, missed)

    # thief advances its stolen ck with the exact plaintext but a guessed salt
    guessed_ck = kdf(thief.ck, LABEL_ADV,
                     H(b"\x00" * SALT_LEN + b"ACK") + H(missed.header_bytes()))
    swarm_ck = swarm[0].ck
    assert guessed_ck != swarm_ck  # 2^128 salts stand between guess and chain


def test_insider_forgery_rejected():
    """§5.3: an insider derives the group message key just fine, but cannot
    re-body a peer's signed header — the signature covers the body."""
    swarm = make_swarm(3)
    victim, insider, judge = swarm

    genuine = victim.send(b"the real message")
    # insider knows ck, so it can build a valid ciphertext for victim's slot
    mk = insider._mk(genuine.seq, victim.id)
    fake_body = ChaCha20Poly1305(mk).encrypt(
        NONCE, os.urandom(SALT_LEN) + b"forged words in your mouth",
        genuine.header_bytes())
    forged = Wire(genuine.ver, genuine.epoch, genuine.seq, victim.id,
                  genuine.fp, fake_body, genuine.sig)  # reused signature
    assert judge.receive(forged) == [BadSignature(genuine.seq)]


def test_tampered_message_rejected():
    swarm = make_swarm(2)
    wire = swarm[0].send(b"do not touch")
    flipped = bytes([wire.body[0] ^ 1]) + wire.body[1:]
    tampered = Wire(wire.ver, wire.epoch, wire.seq, wire.sender, wire.fp,
                    flipped, wire.sig)
    assert swarm[1].receive(tampered) == [BadSignature(wire.seq)]


def test_window_recovery_after_transient_loss():
    """§7 Rung 1: a lagging member NACKs, peers replay raw ciphertexts, and
    the laggard walks itself forward using only its own retained chain key."""
    swarm = make_swarm(3)
    laggard, peer_a, peer_b = swarm

    w0 = peer_a.send(b"msg 0")
    broadcast(swarm, w0)

    lost = []
    for i in (1, 2, 3):
        wire = peer_a.send(f"msg {i}".encode())
        peer_a.receive(wire)
        peer_b.receive(wire)
        lost.append(wire)  # never reaches laggard

    w4 = peer_b.send(b"msg 4")
    peer_a.receive(w4)
    peer_b.receive(w4)
    assert laggard.receive(w4) == [Gap(expected=1, got=4)]

    start, end = laggard.missing_range()
    assert (start, end) == (1, 4)
    replayed = peer_b.serve_retransmit(start, end)
    events = [e for wire in replayed for e in laggard.receive(wire)]
    # the last replay unblocks the buffered w4 automatically
    assert [e.seq for e in events if isinstance(e, Delivered)] == [1, 2, 3, 4]
    assert laggard.ck == peer_a.ck and laggard.seq == peer_a.seq


def test_fork_detected_at_exact_position():
    """§6: same position + different fingerprint is never packet loss."""
    swarm = make_swarm(3)
    a, b, c = swarm

    wire = a.send(b"before the split")
    broadcast(swarm, wire)

    # partition: b and c each accept a different (validly signed) slot-1 winner
    w_b = a.send(b"b's history")
    w_c = c.send(b"c's history")
    b.receive(w_b)
    a.receive(w_b)
    c.receive(w_c)

    # first message to cross the partition exposes the fork at its position
    w_next = a.send(b"business as usual")
    assert c.receive(w_next) == [Fork(position=2)]


def test_replay_dropped_and_equivocation_kept_as_evidence():
    """§6: stale duplicates are noise; a *different* signed body at an old
    position is transferable evidence of cloning (§8)."""
    swarm = make_swarm(2)
    honest, judge = swarm
    clone = copy.deepcopy(honest)  # snapshot-restore: state as of before slot 0

    original = honest.send(b"version one")
    broadcast(swarm, original)
    assert judge.receive(original) == [Duplicate(0)]

    # the clone, holding the same identity key and pre-send chain state,
    # produces a validly signed *different* message for the same slot
    second = clone.send(b"version two")
    events = judge.receive(second)
    assert events == [CloneEvidence(0, honest.id, events[0].first, events[0].second)]
    assert H(events[0].first.body) != H(events[0].second.body)
    # both wires verify under the same identity key: a signed contradiction
    pub = judge.roster[honest.id]
    pub.verify(events[0].first.sig, events[0].first.signed_payload())
    pub.verify(events[0].second.sig, events[0].second.signed_payload())
