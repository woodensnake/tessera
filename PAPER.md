# Tessera — Paper Outline (workshop / preprint draft)

**Purpose of this file:** the outline is a measurement instrument. It exists
to force the claims into the open *before* more sweeps run, so the remaining
experiments are the ones the argument needs — not a pile of numbers looking
for a use. Anything marked ⟨NEED⟩ is an experiment or artifact the argument
depends on that does not yet exist; anything ⟨HAVE⟩ is committed in the repo.

**Target:** an agentic-security or systems-security workshop (fast cycle,
receptive to design+prototype+measurement), with the arXiv/ePrint preprint
posted alongside. The full security-venue version waits on the formal track
(§Formal below) and is a *later* paper, not this one.

**Working title:** *Tessera: Transcript-Bound Continuity for Agent Swarms.*

---

## The one-paragraph thesis

Agent swarms have a confidentiality story (TLS, MLS) but no *continuity*
story: no cheap, standard way to notice that a member has been hijacked,
cloned, restored from a stale snapshot, or silently desynchronized. Tessera
binds the group's key schedule to its full message transcript, so that
possession of the current chain key is simultaneously a decryption
capability, a proof of full-history participation, and a tripwire: tamper,
fork, equivocation, and desync become loud, attributable cryptographic
events instead of silent drift. We give the construction, a prototype, and a
simulation study that (a) locates the liveness envelope of the fragility
this binding introduces and (b) measures what it does and does not detect —
including the honest negatives, which bound the claim.

## The claims (each maps to evidence)

- **C1 — Continuity as a first-class property.** Transcript binding turns a
  class of swarm attacks that are *silent* in a standard group channel into
  *attributable evidence*. ⟨HAVE⟩ construction (PROTOCOL §5–§8);
  claim-per-test suite; RQ1 detection sweep.
- **C2 — The fragility is survivable, and its limit is characterized.**
  Binding makes any gap a hard desync, which sounds fatal; we show the
  recovery ladder absorbs steady loss entirely (≤20%) and that the real
  cliff is outage-vs-window — a *cost* cliff (rejoin storm), never a
  *death* cliff. ⟨HAVE⟩ RQ3a, RQ3b at N=15. ⟨NEED⟩ scaling to N∈{25,100}
  (running now) to show the cliff shape is N-stable, not an artifact.
- **C3 — Honest negatives, stated not hidden.** A *silent* clone is
  undetectable by the transcript layer; equivocation is always detected but
  first-alarm attribution can finger an innocent bystander (certain
  attribution needs the contradictory-wire pair). ⟨HAVE⟩ RQ1 A3-silent,
  A4 attribution breakdown.
- **C4 — It is cheap and standard-shaped.** ⟨HAVE⟩ RQ2 (`cost.py`): the
  marginal cost of binding over a signed-but-unchained baseline is +2 KDF
  and +1 hash on send — 0.7 µs, ~1/26 of one Ed25519 signature — and +24
  wire bytes. The signature dominates; the chain is essentially free.
  Epoch changes are O(N) at the coordinator, negligible at heal cadence.
  ⟨NEED⟩ still: the RQ4 baseline *columns* for the Fig-3 matrix (MLS /
  pairwise-ratchet detection capability), which is separate from this
  per-message cost comparison.

## Section plan

1. **Introduction.** The swarm continuity gap; the transcript-binding idea
   in one figure; contributions = C1–C4.
2. **Background & related work.** ⟨HAVE⟩ from the literature search: MLS /
   Double Ratchet (confidentiality + group key, *no* per-message transcript
   binding), context-based pairing & bounded-storage (the closest relatives,
   and why they didn't deploy), the LLM-crypto and A2A-protocol lines. Frame
   Tessera as *continuity layered on* a standard confidentiality stack, not
   a replacement — and own the deniability inversion up front (§Deniability).
3. **Construction.** The chain, the wire format, the receiver dispatch, the
   recovery ladder, epochs/membership. ⟨HAVE⟩ PROTOCOL.md v0.5, prototype.
4. **Threat model & detection properties.** The A1–A6 taxonomy; what each
   attack becomes under binding; the honest negatives as first-class.
   ⟨HAVE⟩.
5. **Evaluation.**
   - Method: discrete-event sim on the real protocol code; perfect-sequencer
     idealization stated as an upper bound *in the abstract*. ⟨HAVE⟩.
   - RQ1 detection (Fig 2, Fig 3). ⟨HAVE⟩.
   - RQ3 liveness (Fig 4, Fig 5) — the headline. ⟨HAVE⟩ N=15; ⟨NEED⟩ N-scale.
   - RQ2 cost (Table 2). ⟨NEED⟩.
6. **Discussion / limitations.** Perfect-sequencer bound; one traffic shape;
   prototype crypto; the byzantine-sequencer and lane-based-ordering
   directions as future work. ⟨HAVE⟩ mostly (EXPERIMENTS §8, §11).
7. **Conclusion.**

## Figure & table list (the concrete deliverable)

- **Fig 1 — the idea.** One diagram: chain advance mixing plaintext, and the
  three roles of the chain key. ⟨NEED⟩ (drawing).
- **Fig 2 — detection-latency CDF per adversary.** From RQ1. ⟨HAVE data⟩
  ⟨NEED plot⟩.
- **Fig 3 — the detection-capability matrix.** Rows A1–A6 × columns
  {Tessera, MLS, pairwise-ratchet, signed-no-chain}; cells =
  detected?/attributed?/cost. The single most persuasive object in the
  paper. ⟨HAVE⟩ Tessera column; ⟨NEED⟩ baseline columns (RQ4).
- **Fig 4 — loss is a non-issue.** Rung-resolution vs loss, i.i.d. + burst,
  flat at 100% Rung-1. From RQ3a. ⟨HAVE data⟩ ⟨NEED plot⟩.
- **Fig 5 — the churn cliff.** any-rejoin / mean-rejoins vs outage D, one
  curve per W, with the D≈W-seconds cliff and 0% death annotated. The
  headline figure. ⟨HAVE data⟩ ⟨NEED plot + N-scale overlay⟩.
- **Table 1 — protocol parameters.** ⟨HAVE⟩ PROTOCOL §12.
- **Table 2 — per-message / per-epoch cost vs baselines.** ⟨NEED⟩ RQ2.

## What the outline tells us to do next (and NOT do)

Writing this collapsed the remaining work to a short, ordered list:

1. **Finish C4/RQ2 (cost).** Small: op-counts are already implicit in the
   code; needs a counting harness and one table. *Do it — a claim (C4)
   currently has no evidence.*
2. **RQ4 baseline columns for Fig 3.** The detection matrix is the paper's
   best object and is half-empty. MLS via an OpenMLS shim, or — per
   EXPERIMENTS §7's fallback — an analytical comparison if the shim exceeds
   ~2 days. *Do it; scope defensively.*
3. **N-scale overlay for Fig 5.** *Running now.* Confirms C2 isn't an N=15
   artifact. If the cliff shape is N-stable, one overlay line per N suffices
   — no further loss sweeps needed.
4. **Deniability section.** Prose, not experiment. *Do it; a reviewer will
   raise it regardless.*
5. **Explicitly deferred (do NOT block the workshop paper on these):** the
   real-trace run (nice-to-have sensitivity check, not a claim dependency);
   the byzantine-sequencer study; the formal definitions + Tamarin model
   (these gate the *later* security-venue paper, not this one).

The net: the scaled sweeps are the only *running* dependency, and even they
only feed one figure overlay. The binding constraint on submission is
writing RQ2 + the baseline matrix + prose — not more simulator time. That is
the whole argument for drafting now rather than waiting for data.

## Deniability (the objection to meet head-on)

**The objection.** A Signal-shaped reviewer will note that Tessera's
messages are *non-repudiable*: every wire carries an Ed25519 signature over
`header || H(body)`, so any holder of a message can prove to a third party
that a specific identity authored specific content. This is the exact
opposite of the deniability that secure-messaging research has spent a
decade engineering *in*. Left unaddressed, it reads as a novice mistake.

**Why it is the right default here.** Deniability protects a *human* who may
be coerced to reveal a conversation and wants to disavow it. That threat
model does not transfer to a machine swarm. What swarm *operators* need is
the opposite: durable, transferable *evidence* — which agent cloned itself,
which equivocated, which was restored from a stale snapshot — so that a
misbehaving member can be attributed and evicted, and so that a post-incident
audit can assign responsibility. Non-repudiation is not a leak in this
setting; it is the feature that makes §8's "attributable evidence" claim
mean anything. Tessera's entire value proposition is that attacks become
*evidence*, and evidence that anyone can forge or disavow is not evidence.
The paper states this as a deliberate design stance, in the threat-model
section, not buried.

**For settings that do want deniability**, the construction degrades
cleanly. Replace the per-message signature with a group-MAC keyed from the
chain (`mk`-derived): every member can then verify a message came from
*someone* holding the chain, and — crucially — every member can also *forge*
one, which is precisely deniability. The cost is exactly the property we
were selling: third-party attribution of clones and equivocators is lost
(reduced to "a member did this," not "*this* member did this"), and the
fork-attribution matrix (Fig 3) collapses a column. So deniability and
attribution are a genuine either/or here, not a free axis — which is itself
a clean thing to say in the paper. Default to attribution for swarms; offer
the MAC variant as a documented mode for deployments that answer the
threat-model question the other way.

⟨HAVE⟩ argument and variant sketch. ⟨NEED⟩ nothing further for the workshop
paper; a formal deniability/attribution impossibility-style statement (you
cannot have transferable attribution and forgeability at once) would
strengthen the later security-venue version and belongs with the formal
track.
