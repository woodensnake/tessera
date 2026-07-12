"""Symbolic model checks, plus negative controls proving the model can DETECT
insecurity (a checker that only ever says 'safe' is worthless)."""

from model import (Attacker, CHECKS, advance, atom, h, message_key, pair, sig,
                   wire_body)


def test_all_properties_hold():
    for name, fn in CHECKS.items():
        assert fn(), f"symbolic property failed: {name}"


# --- negative controls: the model must catch insecurity when it is there ---

def test_stolen_signing_key_DOES_forge():
    """If the attacker has the signing key, it CAN forge — otherwise the
    authenticity check would be vacuous."""
    sk_A = atom("sk_A")
    header, body = atom("header_n"), atom("body_n")
    forged = sig(sk_A, pair(header, h(body)))
    atk = Attacker(known={sk_A, header, body})   # leaked key
    assert atk.derives(forged)                    # forgery succeeds


def test_capturing_thief_derives_next_key():
    """The gap-lockout only bites BECAUSE the thief missed the message. A thief
    that holds salt+plaintext (captured them) derives the next chain key — the
    model is not just always-safe."""
    ck_n, salt_n, pt_n, header = (atom("ck_n"), atom("salt_n"),
                                  atom("pt_n"), atom("header_n"))
    ck_next = advance(ck_n, salt_n, pt_n, header)
    with_capture = Attacker(known={ck_n, salt_n, pt_n, header})
    assert with_capture.derives(ck_next)          # tracks with capture
    without = Attacker(known={ck_n, header})
    assert not without.derives(ck_next)           # locked out without


def test_high_entropy_salt_is_not_guessable():
    """The salt's safety rests on it being unguessable. If we (wrongly) let the
    attacker guess it, lockout breaks — confirming the salt entropy is the load-
    bearing assumption, not an artifact of the model."""
    ck_n, salt_n, pt_n, header = (atom("ck_n"), atom("salt_n"),
                                  atom("pt_n"), atom("header_n"))
    ck_next = advance(ck_n, salt_n, pt_n, header)
    guessed = Attacker(known={ck_n, header}, guessable={salt_n, pt_n})
    assert guessed.derives(ck_next)               # guessable salt -> broken
    real = Attacker(known={ck_n, header}, guessable={pt_n})
    assert not real.derives(ck_next)              # unguessable salt -> safe


def test_closure_terminates_on_deep_terms():
    """Locality bound: deriving a deeply nested target still terminates."""
    t = atom("x")
    for _ in range(50):
        t = h(pair(t, atom("y")))
    atk = Attacker(known={atom("x"), atom("y")})
    assert atk.derives(t)                          # constructible, and it halts
