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

- **[EXPERIMENTS.md](EXPERIMENTS.md)** — the experiment design: research
  questions, falsifiable hypotheses, adversary taxonomy, metrics, and
  kill criteria for the planned evaluation.

## Running the tests

```
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pytest -v
```

## Status

Design sketch + prototype. **Not reviewed, not audited, not for
production.** The honest scoping of what this can and cannot provide is
in PROTOCOL.md §10; the research-grade open problems are in §11.

The prototype's cryptography deliberately uses stand-ins where the spec
names standards: HMAC-SHA-256 as the KDF (not RFC 5869 HKDF), an
ephemeral-static X25519 sealed box (not RFC 9180 HPKE), and no
constant-time or key-zeroization discipline. These affect none of the
protocol-logic claims the tests exercise, and all of them would need
replacing in any serious implementation.

## License and citation

Apache-2.0 (see [LICENSE](LICENSE)). To cite this work, see
[CITATION.cff](CITATION.cff).
