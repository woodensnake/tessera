"""RQ2 cost harness: the counts are the claim, so pin them."""

from cost import (baseline_signed_no_chain, counting, per_epoch_change,
                  per_message)
import tessera


def test_counting_restores_primitives():
    real_kdf, real_H = tessera.kdf, tessera.H
    with counting():
        pass
    assert tessera.kdf is real_kdf and tessera.H is real_H


def test_per_message_op_counts_match_the_code_paths():
    m = per_message()
    # send: fp + mk = 2 KDF; H(body) for the signature = 1 hash
    assert m["send"].n["kdf"] == 2
    assert m["send"].n["hash"] == 1
    assert m["send"].n["sign"] == 1 and m["send"].n["aead"] == 1
    # recv: expected-fp + mk + advance = 3 KDF; advance H(salt+pt)+H(hdr)
    # plus H(body) for verify = 3 hash
    assert m["recv"].n["kdf"] == 3
    assert m["recv"].n["hash"] == 3
    assert m["recv"].n["verify"] == 1 and m["recv"].n["aead"] == 1


def test_binding_is_cheap_relative_to_the_signature():
    """C4: the transcript binding's marginal cost is a rounding error next to
    the Ed25519 signature the protocol pays for authenticity anyway."""
    m = per_message()
    base = baseline_signed_no_chain()
    marginal = m["send"].micros() - base["send"].micros()
    assert marginal < 0.10 * m["send"].micros()   # < 10% of send cost
    assert m["wire_bytes"] - base["wire_bytes"] == 24  # fp 8 + salt 16


def test_epoch_cost_is_linear_in_n():
    e5, e25, e100 = (per_epoch_change(n) for n in (5, 25, 100))
    # coordinator seals once per member -> O(N)
    assert e25["coordinator"].n["dh"] == 25
    assert e100["coordinator"].n["dh"] == 100
    # a member's own unwrap cost is flat regardless of N
    assert e5["member"].micros() == e100["member"].micros()
