# Status — start here

**What this is:** a research *prototype* of a group-messaging protocol whose
key schedule is bound to the message transcript, so that tampering, cloning,
equivocation, and desync become detectable cryptographic events. It has a
spec, five interoperating prototypes, ~60 tests, a simulation-based
evaluation, and a started formal track. It has **not** been reviewed by a
cryptographer, and its author does not have a cryptography background. Treat
every security claim here as *unverified*.

**Provenance note, stated plainly:** much of this repo — including the
security definitions and proof sketches — was produced with heavy help from a
language model. Fluent, confident cryptographic prose is exactly the kind of
output that can be subtly or badly wrong, and neither the author nor the model
can reliably catch such errors. That is the specific reason expert review is
being sought. Please be skeptical accordingly.

## If you are here to sanity-check the cryptography

The whole thing stands or falls on a small number of claims. Read only these:

1. **The transcript-bound chain** — `PROTOCOL.md` §5. Each message advances a
   chain key via `ck_{n+1} = KDF(ck_n, H(salt‖plaintext) ‖ H(header))`; the
   per-message key and a fingerprint are derived from `ck_n`.
2. **The three novel security properties** — `FORMAL.md` §2.2–2.4:
   *continuity* (holding the current key proves full-history participation),
   *gap-lockout* (missing one message locks you out forever, independent of
   plaintext entropy — this is what the salt buys), and *fork attribution*
   (equivocation yields transferable evidence).

If those don't hold, nothing else matters. If they do, the rest is
engineering. A five-minute read of those two sections is the highest-value
thing you can do; **finding a fatal flaw there is a completely welcome
outcome.**

## Known-unfinished — please don't spend time critiquing these

These are already flagged as placeholder or out of scope; no need to report
them:

- **Crypto primitives are stand-ins.** HMAC-as-KDF (not HKDF), a homemade
  ephemeral-static X25519 sealed box (not RFC 9180 HPKE), no constant-time
  discipline, no key zeroization. A real implementation replaces all of these.
- **`model.py` is a symbolic toy.** A Dolev-Yao knowledge-closure checker,
  not a computational proof and not Tamarin/ProVerif. It covers the
  per-message chain only.
- **`FORMAL.md` has proof *sketches*, not proofs.** Reductions are argued, not
  written out; nothing is machine-checked.
- **The single-chain simulations assume a perfect global sequencer** (an upper
  bound). The per-sender-lane design (`lanes.py`) removes that assumption and
  is separately evaluated, but the two are different code paths.
- **PKI / identity bootstrap is out of scope.** Identity keys are "trusted out
  of band."

## The questions I most want answered

1. **Is the core idea sound, or already broken?** Does transcript-binding the
   key schedule buy the continuity / gap-lockout properties as claimed
   (`FORMAL.md` §2.2–2.3), or is there a break in the first few pages?
2. **Are the security definitions the right ones?** Are the games in
   `FORMAL.md` §2 well-formed, and do they capture what a group-messaging
   protocol should guarantee — or are they subtly circular / too weak / non-
   standard in a way that hides a problem?
3. **What's the honest relationship to MLS and the Double Ratchet?** Is the
   "continuity + fork attribution" contribution (`RESULTS.md` RQ4) real, or
   does an existing construction already give it?
4. **Is any of this worth writing up**, and if so, at what venue and with what
   caveats?

## If you want the fuller picture

- `PROTOCOL.md` — the design (v0.10) and its open problems (§11).
- `RESULTS.md` — the simulation findings, including the ones that *revised* or
  *falsified* earlier claims (a rejoin storm at scale, since fixed; a §8
  clone-detection overclaim, since corrected). The honest-negatives are the
  point.
- `FORMAL.md` — definitions, sketches, and an explicit "what is owed" list.
- `PAPER.md` — a workshop-paper outline mapping claims to evidence.

Thank you for looking. A skeptical read is exactly what this needs.
