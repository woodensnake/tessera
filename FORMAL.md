# Tessera: Formal Security

**Status:** definitions + proof sketches, plus an executable symbolic model
(`model.py`). This is the "formal track" — what a security-venue submission
needs before its claims are defensible. Proof *sketches*, not full proofs;
symbolic (Dolev-Yao) mechanization, not a computational one. Both boundaries
are marked. This document is honest about what is established and what is
still owed.

## 0. What "secure" means here, and the honesty ledger

A green test suite shows the code does what we intended; it says nothing
about an adversary we did not imagine. This document is the start of closing
that gap. It has three layers, of increasing strength and decreasing
completeness:

| Layer | What it gives | Status |
|---|---|---|
| Game-based definitions (§2) | precise statements an adversary can be run against | **written** |
| Computational proof sketches (§3) | reductions to standard assumptions | **sketched** |
| Symbolic mechanization (`model.py`) | machine-checked Dolev-Yao deductions | **runs, passes** |
| Machine-checked computational proof (Tamarin/EasyCrypt) | the real thing | **owed** |

The novel definitional work is §2.2–2.4 (continuity, gap-lockout, fork
attribution); the confidentiality/FS pieces (§2.1) are standard and cited.

## 1. Primitives and assumptions

- **PRF/KDF.** `KDF(k, ℓ, x)` modeled as a PRF keyed by `k`, domain-separated
  by label `ℓ`. Assumption: PRF security (indistinguishable from random for an
  adversary without `k`).
- **Hash.** `H` is collision-resistant, and in the symbolic model one-way.
- **Signatures.** Ed25519, assumed EUF-CMA (existentially unforgeable under
  chosen-message attack).
- **AEAD.** ChaCha20-Poly1305, assumed IND-CCA2 + INT-CTXT (confidentiality
  and ciphertext integrity).
- **KEM/DH.** X25519, assumed to give a secure KEM (IND-CCA) for the sealed
  epoch/genesis secrets; the initial exchange is authenticated (Noise/TLS or
  the genesis bundle of §6), and identity keys are trusted out of band (PKI is
  out of scope).

All reductions below are against a probabilistic polynomial-time (PPT)
adversary and assume these hold.

## 2. Security definitions (games)

An adversary `A` interacts with a challenger driving honest members; `A`
controls the network (deliver, drop, reorder, inject) and may `Corrupt`
members (learn their state). Advantage is `|Pr[A wins] − 1/2|` (or `Pr[A wins]`
for the unforgeability games), taken negligible in the security parameter.

### 2.1 Confidentiality and forward secrecy (standard)

**Message confidentiality (IND-CPA of the channel).** `A` picks two equal-
length plaintexts for an honest sender's next message; the challenger encrypts
one at random; `A` guesses which. Reduces to AEAD IND-CPA under the per-message
key `mk_n`, which is PRF-derived from a chain key `A` cannot obtain without a
`Corrupt` on a current member. *Standard; stated for completeness.*

**Forward secrecy.** After `Corrupt(member)` at position `n` (yielding `ck_n`),
`A` must distinguish an earlier message `m_{j<n}`. Because `ck` advances by a
one-way PRF and prior chain/message keys are deleted (retained only within the
bounded window, §5.1), `ck_j` is not derivable from `ck_n`; reduces to PRF
security. Window-bounded: FS holds for `j < n − W`.

### 2.2 Continuity (NEW)

*Informal:* possessing the current chain key proves participation in the whole
history — you cannot fast-forward into a conversation you did not follow.

**Game CONT.** The challenger runs an honest session producing transcript `T`
with final chain key `ck_N`. `A` may observe all wires and `Corrupt` members
other than at their current head — i.e. `A` gets every `ck_j` for `j ≤ n_i` of
each member `i`, but not the live head of an uncorrupted member. `A` wins if it
outputs `ck_N` for a transcript `T'` that differs from `T` at any position
`≤ N` (a *forged history* reaching the same head).

**Claim.** `Adv^CONT(A) ≤ Adv^PRF + Adv^CR(H)`. *Sketch:* to reach `ck_N` via a
different transcript, some advance step `ck_{k+1} = KDF(ck_k, H(salt·pt)·H(hdr))`
must be satisfied with a `(pt,hdr) ≠` the real ones but the same output —
either a hash collision (bounded by `Adv^CR`) or predicting a PRF output
(bounded by `Adv^PRF`). Mechanized at the symbolic level by
`check_gap_lockout` / `check_authenticity`.

### 2.3 Gap-lockout (NEW)

*Informal:* an adversary holding a chain key who misses even one message can
never again produce a valid chain value — content entropy is irrelevant.

**Game GAP.** `A` is given `ck_n` (a full `Corrupt` of the chain state, but not
the signing key). The challenger sends message `n` (with fresh 128-bit
`salt_n`) but **withholds its ciphertext from `A`** (the "gap"). `A` may see all
later ciphertexts. `A` wins by outputting `ck_{n+1}` (equivalently, any valid
`fp_{n+2}` or `mk_{n+1}`).

**Claim.** `Adv^GAP(A) ≤ Adv^PRF + 2^{−|salt|}`, *independent of the entropy of
`pt_n`.* *Sketch:* `ck_{n+1} = KDF(ck_n, H(salt_n·pt_n)·H(hdr_n))`. `A` has
`ck_n` and `hdr_n` but not `salt_n·pt_n`; `salt_n` is uniform 128-bit and
appears to `A` only inside an AEAD ciphertext it cannot open (it lacks `mk_n`…
which it *could* derive from `ck_n` — but the ciphertext itself was withheld).
So `A` must guess `salt_n` (prob `2^{−128}`) or break the PRF. The salt term is
what removes any dependence on `pt_n`'s entropy: `check_salt_necessity`
mechanizes that **without** it, a guessable `pt_n` wins. This is the v0.2
finding as a theorem shape.

*Boundary:* GAP models the withheld-ciphertext gap. If `A` captures the
ciphertext it derives `mk_n` from `ck_n`, opens it, and tracks — this is not a
break (it is the "thief tracks while capturing" completeness case,
`check_thief_tracks_while_capturing`); lockout is a property of *gaps*, and a
capturing adversary has none.

### 2.4 Fork attribution (NEW, with a measured caveat)

*Informal:* if a member equivocates, honest members obtain transferable
evidence naming the culprit.

**Game FORK.** `A` corrupts member `M` and causes two honest members to accept
different messages at the same position `(E,n)` of `M`'s history. `A` wins if no
honest member can produce a pair that a third party verifies as proof that `M`
equivocated.

**Claim (soundness).** `Adv^FORK(A) ≤ Adv^EUF-CMA`: the two contradictory wires
each carry `M`'s signature over `header‖H(body)` (this is why the signature must
cover the body, §5.3); the pair is checkable by anyone. To win without the
pair existing, `A` would have to make one honest member accept a wire `M` did
not sign — an EUF-CMA forgery.

**Measured caveat (RESULTS.md RQ1).** *Detection* is unconditional, but the
*first alarm's* attribution is not always the culprit: an equivocation-induced
fork can be first noticed by an innocent member crossing the fork (a `Fork`
naming the messenger). Definitive attribution requires the contradictory-wire
pair, which always exists (the claim above); the real-time event may point at
the wrong party. The paper states this explicitly; the game above is about the
*existence* of evidence, which is what holds.

### 2.5 What is deliberately NOT claimed

Metadata privacy; availability under DoS; deniability (the opposite is a
feature, by design — see PAPER.md); security if the ordering layer is
byzantine (open, §11.4); and post-compromise security beyond an epoch heal
(PCS is bounded by identity-key integrity — a heal re-keys chain state but a
stolen *identity* key survives it, §8/§9).

## 3. The novel-vs-standard split (why this is publishable)

The confidentiality and FS results (§2.1) are textbook — Tessera's channel is
a KDF ratchet, and those reductions are the same as Signal's symmetric layer.
The contribution is that **continuity, gap-lockout, and fork attribution are
new security *notions*** for group messaging, each given a game and a sketch
here. A referee's value question — "what property do you have that MLS/Signal
don't?" — is answered by §2.2–2.4: MLS gives group key agreement and PCS but
no per-message transcript binding, so it satisfies neither CONT nor GAP nor
message-level FORK (RESULTS.md RQ4 is the capability matrix; these games are
its formal underpinning).

## 4. The symbolic model (`model.py`) — what it actually checks

A Dolev-Yao knowledge-closure checker: idealized crypto (one-way `H`,
unforgeable `sig` without the key, opaque `aead` without the key), attacker
knowledge closed under the public rules, decidable by the locality (subterm)
bound. It mechanically verifies, and its negative controls confirm it can
*detect* insecurity:

- `authenticity` — no wire forgery without `sk` (control: `test_stolen_key_
  DOES_forge`).
- `gap_lockout` — no `ck_{n+1}` from `ck_n` across a gap (control:
  `test_capturing_thief_derives_next_key`).
- `salt_necessity` — unsalted + guessable plaintext breaks lockout; salted
  does not (control: `test_high_entropy_salt_is_not_guessable`).

This is genuine, run-on-every-CI evidence at the symbolic level — the level
Tamarin/ProVerif operate at. It is **not** a computational proof and does not
cover epochs, quorum, or lanes.

## 5. What is owed (the honest remainder)

1. **Full computational proofs** of §2.2–2.4, not sketches — ideally in
   EasyCrypt.
2. **A Tamarin/ProVerif model** of the two-party chain + one epoch change,
   covering the parts `model.py` abstracts (interaction, freshness, the epoch
   cutover). `model.py` is the warm-up, not the deliverable.
3. **Epoch/quorum/lane analysis** — the games here are the per-message chain;
   membership and the lane braid need their own definitions (continuity across
   an epoch boundary via `fp_close`/`braid_close`; quorum unforgeability).
4. **Deniability impossibility** — a statement that transferable attribution
   (§2.4) and forgeability-based deniability cannot coexist, formalizing the
   either/or the paper claims.

Until 1–2 exist, the honest phrasing for the paper is: *"security argued via
game-based definitions with proof sketches and a mechanized symbolic model;
full computational verification is future work."* That is a normal and
defensible position for a workshop paper; it is not sufficient for a top-tier
security venue, which is why 1–2 gate that stronger submission.
