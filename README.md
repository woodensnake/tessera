# Tessera

A transcript-bound continuity layer for agent swarms: every message
advances a shared chain key, so possession of the current key is at once
the decryption capability, a proof of full-history participation, and a
tripwire that turns tampering, cloning, equivocation, and desync into
loud, attributable failures.

- **[PROTOCOL.md](PROTOCOL.md)** — the design (v0.4), including its open
  problems. Start here.
- **`tessera.py`** — prototype of §5–§7 and §9: the per-message ratchet,
  wire format, receiver dispatch, Rung-1 retransmit recovery, and the
  epoch/membership layer (join, quorum eviction, heal, `fp_close`
  chaining, sealed epoch-secret delivery).
- **`test_tessera.py`** — one test per §5–§7 claim: lockstep operation,
  gap-lockout of key thieves, salt vs. dictionary attacks through gaps,
  insider-forgery rejection, tamper rejection, window recovery, fork
  detection at exact position, and clone evidence.
- **`test_membership.py`** — one test per §9 claim, including the honest
  negative ones: join without history access, evictee lockout, quorum
  enforcement, `fp_close` rejecting cutover across forked history, heal
  shaking off a chain-key thief — and heal *failing* to shake off an
  identity-key thief, as §8 warns.

## Running the tests

```
python3 -m venv .venv
.venv/bin/pip install cryptography pytest
.venv/bin/python -m pytest test_tessera.py -v
```

## Status

Design sketch + prototype. Not reviewed, not audited, not for
production. The honest scoping of what this can and cannot provide is in
PROTOCOL.md §10; the research-grade open problems are in §11.
