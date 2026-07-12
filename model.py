"""Symbolic (Dolev-Yao) model of the Tessera chain — the formal track.

No Tamarin/ProVerif here, so instead of an unrunnable model file this is an
*executable* symbolic checker: crypto is idealized (hashes one-way,
signatures unforgeable without the key, AEAD opaque without the key), the
attacker's knowledge is closed under the public derivation rules, and a
property is "is this secret term derivable by the attacker?" It runs, so its
claims are checked rather than asserted — the honest substitute for a
machine-checked proof, at the symbolic level.

What it establishes (see the checks at the bottom and test_model.py):
  1. Authenticity — an attacker without a member's signing key cannot produce
     a wire that verifies as that member's.
  2. Gap-lockout — an attacker holding ck_n but missing message n cannot
     derive ck_{n+1} (PROTOCOL §5.2).
  3. Salt necessity — WITHOUT the per-message salt, a *guessable* plaintext
     lets the attacker derive ck_{n+1}, breaking lockout. The salt is what
     makes gap-lockout unconditional on content (the v0.2 finding, mechanized).

Idealization and limits: this is a symbolic (not computational) model, and it
covers the per-message chain, not epochs/quorum/lanes. It abstracts hash
collisions and side channels away. It is evidence at the Dolev-Yao level,
which is exactly the level Tamarin/ProVerif work at — not a replacement for a
computational proof (FORMAL.md sketches those).
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ---- term algebra -----------------------------------------------------------
# Terms are immutable nested tuples tagged by their head symbol.

def atom(name):            return ("atom", name)
def pair(a, b):            return ("pair", a, b)
def h(a):                  return ("hash", a)          # one-way hash
def sig(sk, msg):          return ("sig", sk, msg)     # needs sk to make
def aead(key, pt):         return ("aead", key, pt)    # opaque without key


def subterms(t, acc=None):
    """Every subterm of t, including t itself."""
    acc = acc if acc is not None else set()
    acc.add(t)
    if t[0] in ("pair", "sig", "aead"):
        for part in t[1:]:
            subterms(part, acc)
    elif t[0] == "hash":
        subterms(t[1], acc)
    return acc


@dataclass
class Attacker:
    """Dolev-Yao knowledge closure. Starts from `known` and `guessable` (the
    low-entropy atoms the attacker can brute-force; high-entropy atoms — keys,
    salts — are NEVER guessable) and closes under the public rules. By the
    locality property of Dolev-Yao deduction, to decide whether a target is
    derivable it suffices to build only terms that are *subterms* of the known
    set and the target — so the closure is finite and decidable."""
    known: set = field(default_factory=set)
    guessable: set = field(default_factory=set)

    def derives(self, target) -> bool:
        universe = set()
        for t in set(self.known) | set(self.guessable) | {target}:
            subterms(t, universe)
        k = set(self.known) | set(self.guessable)
        changed = True
        while changed:
            changed = False
            for t in list(k):
                # destructors: projection from pairs, decryption with the key
                if t[0] == "pair":
                    for part in (t[1], t[2]):
                        if part not in k:
                            k.add(part); changed = True
                if t[0] == "aead" and t[1] in k and t[2] not in k:
                    k.add(t[2]); changed = True
            # constructors: only build terms that are subterms of the universe
            # (locality) — hashing, pairing, and AEAD/signature *with the key*
            for cand in universe:
                if cand in k:
                    continue
                head = cand[0]
                if head == "hash" and cand[1] in k:
                    k.add(cand); changed = True
                elif head == "pair" and cand[1] in k and cand[2] in k:
                    k.add(cand); changed = True
                elif head in ("aead", "sig") and cand[1] in k and cand[2] in k:
                    k.add(cand); changed = True
        return target in k


# ---- the Tessera chain, symbolically ---------------------------------------

def advance(ck, salt, plaintext, header):
    """ck_{n+1} = H( ck_n || H(salt||pt) || H(hdr) ), as in tessera._advance."""
    return h(pair(ck, pair(h(pair(salt, plaintext)), h(header))))


def advance_no_salt(ck, plaintext, header):
    """The unsalted variant, to show why the salt is load-bearing."""
    return h(pair(ck, pair(h(plaintext), h(header))))


def message_key(ck, epoch, seq, sender):
    return h(pair(ck, pair(atom(("msg", epoch, seq)), sender)))


def wire_body(mk, salt, plaintext):
    return aead(mk, pair(salt, plaintext))


# ---- the properties, mechanically checked -----------------------------------

def check_authenticity():
    """An attacker without member A's signing key cannot forge a wire that
    verifies as A's. Model: verifying A's wire needs sig(sk_A, hdr||H(body));
    the attacker knows everything public but not sk_A."""
    sk_A = atom("sk_A")
    header = atom("header_n")
    body = atom("body_n")
    forged_sig = sig(sk_A, pair(header, h(body)))
    # attacker knows the public wire parts and its own keys — but not sk_A
    atk = Attacker(known={header, body, atom("sk_attacker"),
                          atom("public")})
    return not atk.derives(forged_sig)   # True == cannot forge


def check_gap_lockout():
    """A thief holding ck_n but MISSING message n cannot derive ck_{n+1}.
    It lacks salt_n and plaintext_n (they rode inside the AEAD it never
    opened), and H is one-way."""
    ck_n = atom("ck_n")
    salt_n = atom("salt_n")          # high-entropy, unguessable, never revealed
    pt_n = atom("pt_n")
    header = atom("header_n")
    ck_next = advance(ck_n, salt_n, pt_n, header)
    # thief knows the current chain key and the public header, nothing else
    atk = Attacker(known={ck_n, header, atom("public")})
    return not atk.derives(ck_next)  # True == locked out


def check_thief_tracks_while_capturing():
    """Sanity / completeness: a thief that DOES capture message n (holds the
    ciphertext) derives ck_{n+1} — so the model is not vacuously safe."""
    ck_n = atom("ck_n")
    salt_n = atom("salt_n")
    pt_n = atom("pt_n")
    header = atom("header_n")
    mk = message_key(ck_n, 0, 0, atom("sender"))
    body = wire_body(mk, salt_n, pt_n)          # captured ciphertext
    ck_next = advance(ck_n, salt_n, pt_n, header)
    # public: the sender id, the msg-key label (epoch/seq are public), header
    atk = Attacker(known={ck_n, header, body, atom("sender"),
                          atom(("msg", 0, 0)), atom("public")})
    return atk.derives(ck_next)      # True == thief tracks (as designed)


def check_salt_necessity():
    """WITHOUT the salt, a *guessable* plaintext breaks lockout: the attacker
    guesses pt_n, computes H(pt_n), and derives ck_{n+1}. The salt is exactly
    what removes this dependence on plaintext entropy (PROTOCOL §5.2)."""
    ck_n = atom("ck_n")
    pt_n = atom("pt_n")              # low-entropy -> guessable
    header = atom("header_n")
    ck_next_unsalted = advance_no_salt(ck_n, pt_n, header)
    atk = Attacker(known={ck_n, header, atom("public")}, guessable={pt_n})
    broken = atk.derives(ck_next_unsalted)      # attacker DOES derive it
    # and with the salt (unguessable), the same guessable plaintext is not enough
    salt_n = atom("salt_n")
    ck_next_salted = advance(ck_n, salt_n, pt_n, header)
    atk2 = Attacker(known={ck_n, header, atom("public")}, guessable={pt_n})
    still_safe = not atk2.derives(ck_next_salted)
    return broken and still_safe


CHECKS = {
    "authenticity": check_authenticity,
    "gap_lockout": check_gap_lockout,
    "thief_tracks_while_capturing": check_thief_tracks_while_capturing,
    "salt_necessity": check_salt_necessity,
}


def main():
    print("Tessera symbolic (Dolev-Yao) model — property checks\n")
    ok = True
    for name, fn in CHECKS.items():
        passed = fn()
        ok &= passed
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
    print("\n", "all properties hold" if ok else "A PROPERTY FAILED")


if __name__ == "__main__":
    main()
