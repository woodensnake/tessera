# Tessera

A transcript-bound continuity layer for agent swarms: every message
advances a shared chain key, so possession of the current key is at once
the decryption capability, a proof of full-history participation, and a
tripwire that turns tampering, cloning, equivocation, and desync into
loud, attributable failures.

- **[PROTOCOL.md](PROTOCOL.md)** — the design (v0.4), including its open
  problems. Start here.
- **`tessera.py`** — prototype of §5–§7 and §9: the per-message ratchet,
  wire format, receiver dispatch, Rung-1 retransmit recovery, **Rung-1.5
  resync** (return a laggard with no re-key — the storm fix), and the
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
- **`sim.py`** — discrete-event simulator (EXPERIMENTS M1): honest swarm
  on the real protocol code over lossy (i.i.d. / Gilbert–Elliott),
  delaying, partitioning networks, with the §7 recovery ladder driven by
  simulated timers. `python sim.py --n 25 --loss 0.02 --duration 600`
  prints a metrics JSON. Adversaries land with M2.
- **`test_sim.py`** — simulator smoke tests: lossless lockstep, Rung-1
  recovery under i.i.d. and burst loss, Rung-2 rejoin after a
  window-exceeding outage, partition healing, and seed determinism.
- **`adversaries.py`** — adversary harness (EXPERIMENTS M2): the A1–A6
  taxonomy (eavesdropper, key thief, clone, equivocator, impostor) as
  parameterized programs, with `run_adversary_trial` for seeded runs.
- **`test_adversaries.py`** — one test per RQ1 claim, including the honest
  negatives: no false positives in honest runs, impostor never accepted,
  speaking/stale clones caught as contradictions, **silent clones not
  detected** (a finding that corrected PROTOCOL §8), equivocation forked
  and attributed, and the key thief reading until its first capture gap.
- **`sweep.py`** — parameter sweeps (EXPERIMENTS M3): `python sweep.py all`
  runs RQ1 (detection), RQ3a (loss), RQ3b (churn cliff), RQ3c (resync fix),
  and RQ3d (window-in-time fix) at 200 seeds/config across all cores,
  writing `results/*.json` and markdown.
- **`lanes.py`** — per-sender-lane prototype (PROTOCOL §11.1): one chain
  per sender, no global sequencer. `test_lanes.py` proves members converge
  under any per-sender-FIFO delivery order — the evidence that the
  perfect-sequencer idealization can be removed — plus per-lane fork
  detection and the asynchronous **braid** checkpoint (a signed view that a
  peer at a *different* position can verify and use to localize divergence).
- **`lane_sim.py`** — sequencer-free liveness sim: agents broadcast into
  their own lanes over the lossy network with no global order, recovering
  per lane and using braids to drive lost-tail catch-up. `test_lane_sim.py`
  shows the swarm converges to one braid under loss up to 20% — matching the
  single chain's robustness *without* a sequencer.
- **`cost.py`** — RQ2 cost accounting: primitive op-counts per message /
  heartbeat / epoch change and real wire bytes, vs a signed-no-chain
  baseline. `python cost.py` prints the table; JSON in `results/`.
- **[RESULTS.md](RESULTS.md)** — the M3 findings. Headline: the go/no-go
  gate is **GO** — steady loss up to 20% is fully absorbed by Rung-1
  recovery, the real liveness limit is a *survivable*, churn-driven cost
  cliff at outage-vs-window, and the binding's per-message cost is ~1/26 of
  the signature already paid.
- **[PAPER.md](PAPER.md)** — the workshop/preprint outline: claims C1–C4
  mapped to evidence, figure list, and the ordered remaining work.

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
