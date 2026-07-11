# Tessera: Experiment Design

**Status:** draft v0.2 — written before the simulator, deliberately: the
apparatus serves these questions, not the reverse. Companion to
PROTOCOL.md (v0.5). v0.2 records the first result the apparatus produced:
H1a (heartbeat detection of stale clones) was **falsified** while building
the M2 harness — see §1. A falsified hypothesis this early is the process
working, not failing.

## 0. The claim under test

Tessera claims that binding a swarm's key schedule to its full transcript
turns tampering, cloning, equivocation, desync, and hijack into **loud,
attributable, fast** failures, at **bounded cost** in overhead and — the
crux — **without collapsing liveness** under realistic loss, churn, and
partition. Each research question below isolates one clause of that
claim, states a falsifiable hypothesis, and names the result that would
kill or reshape the project.

Execution order: **RQ3 first** (it can kill the project cheapest), then
RQ1, RQ2, RQ4. The formal track (§6) runs in parallel; it shares no
apparatus with the simulator.

---

## 1. RQ1 — Detection: how fast, how sure?

**Question.** For each adversary in the taxonomy (§4), what are the
detection probability and detection latency, as functions of the
adversary's capture-gap rate, the heartbeat interval T, and the swarm's
message rate?

**Hypotheses.** (H1a was *falsified* by the M2 prototype — kept here with
its correction, because a revised hypothesis is a result.)
- ~~H1a: A snapshot clone with capture probability c < 1 is detected as its
  capture gaps, via heartbeat fingerprint divergence.~~ **FALSE.** A clone
  frozen at a past position holds the *correct* fingerprint for it; being
  behind is not being forked, so its heartbeat is indistinguishable from
  an honest laggard's. Corrected claim (**H1a′**): a clone is detected
  only when it **speaks** a contradiction at an already-committed slot;
  a *silent* clone — stale or synced — is invisible to the transcript
  layer. This widens H1c below.
- H1b: A *speaking* clone (both instances live) is detected within ~1
  message of its first divergent send, independent of c. (Confirmed in the
  prototype at ≤ 2 chain positions; needs the full sweep to characterize.)
- H1c: A *silent* clone is never detected, whether synced (c = 1) or
  merely stale — the honest negative, now broader than PROTOCOL §8 first
  admitted. The experiment must *confirm* this limit, not hide it.
- H1d: Detection latency for an equivocation-induced fork is bounded by
  the time to the next crossing message; for divergence noticed via
  heartbeat, by interval T plus one delivery delay.

**Independent variables.** Adversary type and parameters (§4); T ∈
{1, 10, 60} s; per-agent message rate λ ∈ {0.01, 0.1, 1} msg/s; N ∈
{5, 25, 100}.

**Dependent variables (definitions in §5).** Detection probability
within horizon; detection latency in both chain positions and simulated
wall-clock; attribution correctness (did the evidence name the right
identity?); false-positive rate (must be 0; see §5).

**Procedure.** For each config: 1000 seeded trials; inject the adversary
at a uniformly random chain position after warm-up; run to a horizon of
10,000 positions or 24 simulated hours; record first detection event at
any honest member.

**Primary plots.** Detection-latency CDFs per adversary; heatmap of
median latency over (c, T); attribution accuracy table.

**Kill/reshape criterion.** If attribution is ever *wrong* (evidence
names an innocent member), that's a protocol bug of the §8-forgery class:
stop and fix before any other result matters.

---

## 2. RQ2 — Cost: what does continuity charge?

**Question.** What is Tessera's overhead versus doing nothing and versus
baselines, per message and per membership event, as N grows?

**Hypotheses.**
- H2a: Per-message wire overhead is constant at ~88–96 B (fp 8 + salt 16 +
  sig 64 + header framing) regardless of N.
- H2b: Per-message compute is 3 KDF + 1 AEAD + 1 sign / N verifies —
  dominated by the signature, i.e., Tessera's marginal cost over a
  signed-but-unchained baseline is ~2 KDF invocations, effectively noise.
- H2c: Epoch changes cost O(N) sealed secrets ≈ 96 B each; at N = 100
  and heal cadence 15 min this is < 1% of a λ = 0.1 msg/s swarm's traffic.

**Method note.** CPU is measured in *operation counts* (KDF/AEAD/sig
invocations), not Python wall-clock — the prototype's Python overhead
would swamp and misrepresent primitive costs; convert to time using
published per-primitive benchmarks (e.g., libsodium numbers) and say so.

**Dependent variables.** Bytes/message; bytes/epoch-change; op counts;
retransmit amplification (replayed bytes per lost byte) under RQ3 loads.

**Kill/reshape criterion.** None — cost results reshape parameter
defaults, not viability, unless epoch-change traffic exceeds ~10% of
total at defensible cadences, which would demand the MLS-tree upgrade
before publication.

---

## 3. RQ3 — Liveness: where is the cliff? (RUN FIRST)

**Question.** Under packet loss p, agent churn, and partitions, how
often does the swarm stay live via Rung 1 (retransmit), degrade to Rung 2
(rejoin), or die (rejoin storm / no quorum)? Where is the operating
region's edge?

**Hypotheses.**
- H3a: For p ≤ 1% i.i.d. loss with W = 64/30 s, ≥ 99.9% of loss events
  resolve at Rung 1 with no epoch change.
- H3b: Rung-2 events grow smoothly with p (no avalanche) up to some
  p*; beyond p*, rejoin storms — a rejoin's epoch change invalidating
  other laggards' catch-up, forcing more rejoins — produce a sharp
  liveness cliff. Locating p* under burst loss is the experiment's most
  important single number.
- H3c: A partition/heal cycle costs exactly one epoch change and loses
  no quorum-side messages; minority-side agents all re-enter via Rung 2.

**Independent variables.** Loss model: i.i.d. p ∈ {0.1, 0.5, 1, 2, 5,
10}% AND Gilbert–Elliott burst loss (burst lengths 2–50); W ∈ {16, 64,
256} × time-floor {0, 30 s}; churn: agent offline events, exp-distributed
durations crossing the window boundary; partitions: 2-way splits,
duration ∈ {10 s, 10 min}, minority fraction ∈ {0.1, 0.4}; N ∈ {5, 25,
100}; traffic: Poisson and bursty (§5).

**Dependent variables.** Fraction of disruptions resolved per rung;
messages lost to laggards; epoch changes per hour; swarm-death rate;
time-to-full-lockstep after each disruption.

**Primary plots.** Rung-resolution stacked area vs p (i.i.d. and burst);
liveness-cliff location p* vs W; partition-recovery timeline traces.

**Kill/reshape criteria.** If p* < 2% under burst loss at the default
W — i.e., realistic radio conditions sit past the cliff — the protocol
as specified is not deployable on its motivating networks. That result
forces either (a) the per-sender-lane redesign (PROTOCOL §11.1) or (b) an
honest repositioning as a wired-datacenter-swarm protocol. Either way it
becomes the paper's central finding; this is why RQ3 runs first.

---

## 4. Adversary taxonomy (shared across RQs)

Every adversary is a parameterized program in the simulator, run against
the same seeded trials as the honest baseline.

| ID | Adversary | Parameters | Capability |
|---|---|---|---|
| A1 | Eavesdropper | capture prob c | reads wire only |
| A2 | Key thief | theft position; c | A1 + one-time copy of ck (not identity keys) |
| A3 | Snapshot clone | dormancy d; c; speaks? | full state copy (ck + identity keys) at a position |
| A4 | Equivocating insider | target subsets | legitimate member sending divergent messages |
| A5 | Malicious coordinator | secret-equivocation | runs one epoch change dishonestly |
| A6 | Impostor | none | no keys; injects/replays wire traffic |

Notes: A2 with c = 1 defeats confidentiality until the next heal by
design (PROTOCOL §9); the measurement is *time-to-heal exposure*, not
detection. A5's fork-at-epoch-start detection is claimed but untested in
the prototype — the simulator must cover it. A6 exists to confirm zeros
(no forged wire ever accepted).

---

## 5. Metrics: precise definitions

- **Detection event:** first emission, at any honest member, of Fork,
  CloneEvidence, ContinuityBreak, or (for A5) a fork at epoch position 0.
  Heartbeat-triggered detections count; operator-visible only.
- **Detection latency:** (chain positions, and simulated seconds) from
  *injection instant* — not first adversarial action — to detection
  event. Measuring from injection is stricter and prevents flattering
  numbers for adversaries that lurk.
- **Attribution correctness:** the evidence object names the compromised
  identity and no other.
- **False positive:** any detection event in an adversary-free trial.
  By construction this must be zero; it is measured anyway because a
  nonzero rate is the single best canary for implementation bugs in the
  dispatch logic.
- **Rung-k resolution:** a disruption whose affected members return to
  lockstep via rung ≤ k without human-analogue intervention.
- **Swarm death:** no quorum-holding component can advance the chain for
  > 60 simulated seconds.
- **Traffic models:** Poisson(λ) per agent; bursty = 2-state MMPP with
  10× rate ratio; plus one recorded trace of a real multi-agent LLM task
  team (5 agents, collaborative coding session, timestamps + sizes only)
  to check that synthetic results transfer. Collecting this trace is a
  TODO before RQ3's final runs.

**Statistics.** 1000 trials per config (pilot with 100 to size variance);
report medians with bootstrap 95% CIs; never bare means for latency
(heavy tails expected at the cliff). All randomness from named seeds;
every figure regenerable by `make figures` from committed configs.

---

## 6. Formal track (parallel; no simulator dependency)

1. **Definitions.** Game-based definitions of *gap-lockout*
   (indistinguishability for the adversary's post-gap chain), *continuity*
   (unforgeability of participation proofs), and *fork attributability*
   (soundness: evidence implicates only actual equivocators). The
   definitional work is the novel part; confidentiality/FS reductions of
   the HKDF chain to PRF security are expected to be standard.
2. **Tamarin model** scoped to: two-party chain + one epoch change.
   Properties: desync detection (no silent divergence), lockout, and
   evidence soundness. Full quorum machinery is explicitly out of scope
   for v1.
3. **Deniability stance.** One section of the eventual paper defending
   non-repudiation as correct for machine swarms (operators need
   evidence; agents don't need deniability) — this is a known objection
   from the Signal-shaped reviewer and must be met head-on, with the
   deniable-variant construction (MAC-then-sign-optional) sketched as an
   alternative.

---

## 7. Baselines (RQ4, folded into the others' runs)

| Baseline | Role |
|---|---|
| Unsigned TLS-style channel to a hub | floor: cost of doing nothing about continuity |
| Signed messages, no chain | isolates the chain's marginal cost and marginal detection |
| Pairwise Double Ratchet mesh | the "just use Signal" retort, quantified: O(N²) sessions, no group continuity |
| MLS (OpenMLS) | the serious rival: epochs and membership, no per-message transcript binding |

Deliverable: a **detection-capability matrix** — rows the adversary
taxonomy, columns these stacks, cells = detected? attributed? at what
latency/cost — plus overhead comparisons on identical traces. Integration
reality: OpenMLS is Rust; drive it via a thin CLI shim over the same
trace files rather than in-process bindings. If the shim exceeds ~2 days
of work, downgrade MLS to an analytical comparison (published message
sizes and epoch costs) and say so in the paper.

---

## 8. Threats to validity (written down now, so they're designed against)

- **Simulator fidelity.** Discrete-event, not real radios; mitigated by
  Gilbert–Elliott burst loss and the recorded real trace — and by
  publishing the simulator for others to attack.
- **Prototype shortcuts.** HMAC-as-KDF (not RFC-5869 HKDF), sealed-box
  stand-in (not RFC-9180 HPKE), no constant-time discipline. None affect
  message-count/latency results; all are flagged wherever CPU numbers
  appear.
- **Ordering-layer idealization.** The harness plays a perfect
  sequencer. Every liveness result is therefore an *upper bound*; the
  paper must say this in the abstract, not the appendix. (A byzantine
  ordering layer is PROTOCOL §11.4 — future work.)
- **Traffic realism.** One LLM-team trace is anecdote, not distribution;
  claims that depend on traffic shape get sensitivity analysis across
  the synthetic models.

---

## 9. Milestones

| # | Deliverable | Depends on |
|---|---|---|
| M1 | Simulator core: event loop, network models, honest swarm on prototype code | — |
| M2 | Adversary harness A1–A6 + metrics pipeline | M1 |
| M3 | **RQ3 results + go/no-go on p*** | M2 |
| M4 | RQ1 + RQ2 full runs | M3 says go |
| M5 | Baseline shims + capability matrix (RQ4) | M2 |
| M6 | Formal definitions draft + Tamarin model | — (parallel) |
| M7 | arXiv/ePrint preprint + workshop submission | M3–M6 |

M3 is the decision gate: its outcome (deployable operating region vs.
cliff-bound) selects which paper gets written — "Tessera works: here is
its envelope" or "transcript binding's fragility is fundamental: here is
the cliff, and here is the lane-based redesign it motivates." Both are
real papers; only one apparatus is needed to find out which.
