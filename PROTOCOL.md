# Tessera: Transcript-Bound Continuity for Agent Swarms

**Status:** design sketch, v0.5 — nothing here is final; every section marked
OPEN is a known unsolved decision.
v0.5 corrects §8 with a finding from the M2 adversary harness: a *silent*
clone (stale or synced) is not detectable by fingerprint — "behind" is not
"forked", so a stale clone's heartbeat is indistinguishable from a
laggard's. Clone detection relies on a *spoken* contradiction; the earlier
"or heartbeat" claim was wrong.
v0.4 incorporates what implementing §9 surfaced: identities are a pair of
keypairs (sig + KEM), the receiver dispatch needs a cross-epoch case, a
joiner's trust is forward-looking only, and epoch bundles need replay/
splice binding (quorum sigs cover the target epoch; seals are
context-bound). Coordinator secret-equivocation is detected at the new
epoch's first message, not prevented.
v0.2 fixed six gaps found in review: insider forgery via header-only
signatures, a broken join derivation, slot-contention key reuse,
dictionary attacks through gaps, needless key retention in the retransmit
window, and heartbeat replay.
v0.3 fixed five more: epoch re-keys severing the transcript chain
(`fp_close`), unilateral eviction as a partition weapon (quorum +
ordered membership ops), static-DH re-key delivery without forward
secrecy (HPKE), an overclaimed clone-detection guarantee (now scoped to
speak-time and capture gaps), and gap/fork/replay conflation in the
receiver dispatch. It also demoted heartbeat timestamps to optional
(clock sync is not assumable) and noted that group-key possession proofs
are transferable among colluding members.

## 1. What this is

Named for the *tessera hospitalis* — a token split between two parties and
matched later to prove a standing relationship — and the *tessera
militaris*, the Roman army's daily watchword. Both are exactly what the
chain key is: a possessed token whose match proves shared history.

Tessera is a group messaging layer for agent swarms in which the key
schedule is bound to the full message transcript. Every message advances a
shared **chain key**; possession of the current chain key is simultaneously:

- the **decryption capability** for the next message,
- a **membership proof** ("I have participated in every step of this
  conversation"),
- a **continuity check** (a hijacked, cloned, or snapshot-restored agent
  presents a stale or forked chain and is detected on its next message).

The design goal is *not* to replace standard confidentiality (the bootstrap
and epoch layers use ordinary DH). The goal is the property standard stacks
don't give swarms: **tamper, desync, equivocation, and identity
discontinuity all surface as loud, attributable cryptographic failures**
instead of silent weirdness.

### Non-goals

- Metadata privacy (who talks to whom, when, how much).
- DoS resistance. A member can always flood; that's rate-limiting's job.
- Byzantine agreement on message *content*. We detect forks; we do not
  arbitrate them.
- Post-quantum anything, for now.

## 2. Assumptions

1. **Ordered broadcast.** Within an epoch there exists a total order on
   messages that all live members observe. How the swarm gets this
   (sequencer node, token ring, leader from the coordination layer it
   already runs) is out of scope, exactly as MLS delegates ordering to its
   Delivery Service. OPEN: how gracefully we can degrade to causal order.
2. **Long-term identities.** Every agent's identity is a *pair* of
   keypairs — Ed25519 for signatures and X25519 for receiving sealed
   epoch secrets (§9) — with trust established out of band (provisioning,
   swarm CA, DID — don't care). One keypair is not enough: signing and
   KEM are different operations, a distinction "identity key," singular,
   hid until implementation.
3. **An eavesdropper may be strong.** We assume full packet capture is
   possible; confidentiality never *relies* on the attacker missing
   traffic. Gap-lockout is defense-in-depth, not the foundation.

## 3. Primitives and notation

| Symbol | Meaning |
|---|---|
| `KDF(k, label, input)` | HKDF-SHA-256, domain-separated by `label` |
| `H(x)` | SHA-256 |
| `AEAD` | ChaCha20-Poly1305 |
| `DH` | X25519 |
| `HPKE` | RFC 9180, ephemeral-static X25519, for epoch-secret delivery (§9) |
| `Sig` | Ed25519 over `header || H(body)` |
| `ck_n` | chain key after message *n* (32 bytes) |
| `E` | epoch number (u32), `n` | sequence number within epoch (u64) |

## 4. Per-agent state

```
identity_sk / identity_pk        long-term Ed25519
epoch E                          current epoch number
ck                               current chain key (only key state kept!)
n                                next expected sequence number
window[]                         last W raw ciphertexts (no keys — §7)
roster                           member list for epoch E, with identity_pks
```

Old chain keys and message keys are **deleted on advance**, with no
exceptions — `window` holds only ciphertexts, which are worthless without
a chain position that was never advanced past them. This is what makes
the transcript binding forward-secret rather than an ever-growing
liability.

## 5. Key schedule

### 5.1 Epoch bootstrap

Each epoch starts from an `epoch_secret` established by the membership
layer (§9): fresh DH entropy contributed at every membership change or
periodic update.

```
ck_0 = KDF(epoch_secret, "tessera-chain-init", E || roster_hash || fp_close)
```

where `fp_close` is the fingerprint at the previous epoch's final chain
position (all-zeros for the swarm's first epoch).

Binding `roster_hash` into `ck_0` means two agents that disagree about
*who is in the swarm* cannot accidentally interoperate. `roster_hash`
must be computed over a canonical encoding (members sorted by identity
key, fixed serialization) or honest agents will disagree about it.

Binding `fp_close` is what makes the *epochs themselves* a chain. Without
it, every eviction or heal — whose `epoch_secret` is deliberately fresh
rather than derived from `ck` (§9) — would sever the transcript: the new
epoch would be cryptographically unrelated to everything before it, and
"possession proves full-history participation" would silently shrink to
"participation since the last eviction." `fp_close` is safe to mix even
though the evictee knows it: secrecy comes entirely from `epoch_secret`;
`fp_close` contributes only the *binding*. Each epoch therefore ends with
an explicit, coordinator-signed **EPOCH-CLOSE** record naming the final
`(E, n, fp)`, so all members agree on exactly where the old chain ended.

### 5.2 Per-message ratchet (the ledger)

For message *n* in epoch *E*:

```
mk_n   = KDF(ck_n, "tessera-msg", E || n || sender_id)  # one-time message key
fp_n   = KDF(ck_n, "tessera-fp",  E || n)[0:8]          # chain fingerprint, 8 bytes
salt_n = 16 fresh random bytes, carried inside the AEAD payload
ck_n+1 = KDF(ck_n, "tessera-adv", H(salt_n || plaintext_n) || H(header_n))
```

Properties, each load-bearing:

- **`ck_n+1` mixes the plaintext** → transcript feedback. An observer who
  misses one plaintext can never advance the chain again (gap-lockout),
  and any undetected-tamper scenario is impossible: a modified message
  either fails AEAD now or forks the chain visibly at *n+1*.
- **`salt_n` puts a floor under gap-lockout.** Without it, the lockout is
  only as strong as the missed plaintext: every derivation is
  deterministic, so an attacker holding `ck_n` who missed message *n* can
  brute-force candidate plaintexts offline against the *public* `fp_n+1`
  — and agent traffic is full of guessable "ACK"-shaped messages. The
  salt guarantees ≥128 bits of unguessable entropy per missed message,
  making the lockout unconditional on content.
- **`ck_n+1` also mixes the header** → sender identity and sequence
  numbers are transcript-bound; you can't replay a message under a
  different position or author.
- **`mk_n` binds `sender_id`** so that two agents racing for the same slot
  *n* encrypt under different keys. Without this, slot contention means
  two different plaintexts under the same key and nonce — catastrophic
  keystream reuse. See §6 for how races resolve.
- **`fp_n` reveals nothing about `ck_n`** (independent KDF branch) but is
  checkable by anyone holding `ck_n`. This is the divergence tripwire.
- **KDF, not embedding; hash, not sampling.** The whole design needs
  "slightly wrong input → useless output." Exactness is the feature.

### 5.3 Wire format

```
header:  ver | E | n | sender_id | fp_n
body:    AEAD(mk_n, nonce = 0, aad = header, salt_n || plaintext)
sig:     Sig(identity_sk, header || H(body))
```

Two details here are anti-footguns, not style:

- **The signature MUST cover the body.** `mk_n` is a *group* key — every
  member can derive it. A header-only signature lets any insider take a
  peer's genuine signed header and attach a freshly encrypted body of
  their choosing: a perfect in-group forgery attributed to the victim,
  which would also poison the fork-attribution claims in §8. Covering
  `H(body)` makes every message non-repudiably the sender's.
- **The nonce is constant** because `mk_n` is single-use and now
  sender-bound (§5.2); deriving uniqueness from the key, not the nonce,
  removes the reuse hazard entirely.

## 6. Normal operation

1. Sender at state `(E, n, ck)` computes `mk_n`, `fp_n`, encrypts, sends,
   and stores the ciphertext in `window`. It does **not** advance until the
   ordering layer confirms its message won slot *n*.
2. Each receiver dispatches on `(seq, fp)` **before** decrypting — the
   three failure shapes are different conditions with different meanings,
   and conflating them turns routine packet loss into false fork alarms:
   - **seq = expected, fp matches** → decrypt, deliver plaintext up to
     the agent, advance chain.
   - **seq = expected, fp differs** → FORK. This is never packet loss;
     the sender's history genuinely diverges from ours at this exact
     position. Do not process; raise the alarm (§7, §8).
   - **seq ahead of expected** → GAP. We missed messages; we cannot even
     check this fp yet. Buffer the message, NACK the missing range
     (§7 Rung 1).
   - **seq behind expected** → duplicate or replay; drop. If its content
     differs from what we saw at that position, keep it: it is signed
     evidence of cloning or equivocation (§8).
   - **epoch differs from ours** (checked before any of the above) → an
     *older* epoch is stale noise, drop; a *newer* epoch means we missed
     an epoch change entirely and must rejoin (§7 Rung 2). This case was
     missing from the dispatch until the prototype hit it: a spec with
     epochs must say what a cross-epoch wire means.
3. Every member — including pure listeners — advances the same chain, so
   the swarm's states stay identical after every message.

**Slot contention.** Two agents may race for the same *n*. Their message
keys differ (sender-bound, §5.2), so there is no cryptographic harm; the
ordering layer picks one winner, everyone advances on the winner's
message, and the loser discards its attempt and re-encrypts at the next
free slot — the loser's ciphertext is dead, never reused, because its key
derivation is pinned to a slot it didn't win.

Idle agents emit a **heartbeat** every T seconds: a header-only message
(it does not advance the chain) carrying `fp` at their current position
and a monotonic heartbeat counter, all signed. The counter is the
freshness mechanism — receivers reject any counter ≤ the last one seen
from that sender. (A timestamp may ride along where synced clocks exist,
but MUST NOT be the mechanism: swarm clock sync cannot be assumed, and a
clock-dependent liveness check fails open exactly when a partitioned or
GPS-denied swarm needs it.) Freshness matters because heartbeats are the
one message type an attacker could usefully replay: without it, a
captured heartbeat replayed during a quiet period masks the death or
capture of the agent it came from. This turns "quietly diverged three
hours ago" into "detected within T".

One honest caveat: `fp` is derived from the *group* chain key, so a
heartbeat proves its signer *or any colluding member* holds the chain —
possession proofs built on a group secret are transferable inside the
group. That's acceptable (a colluding member could forward everything
anyway) but it means heartbeats authenticate liveness and sync, not
exclusive possession.

## 7. Desync: detection and the recovery ladder

Divergence is detected at the first message after it happens, and the
fingerprint pinpoints *the exact sequence number* where states split.
Recovery escalates:

**Rung 1 — retransmit (transient loss).** Receiver missing messages
`[a, b)` NACKs; *any* peer replays the stored ciphertexts from its
`window`. The receiver still holds `ck_a` (it never advanced past the
gap), so it can derive every needed message key itself and catch up.
Note what this means for forward secrecy: the window stores **only
ciphertexts, never keys** — an attacker who compromises an agent gets the
current `ck` and a pile of ciphertexts that `ck` cannot open. Lagging
receivers don't need stored keys because the lockout works in their
favor: not having advanced *is* the decryption capability. NACKs should
be rate-limited per peer; replay-on-request is an amplification vector.

**Rung 2 — rejoin (beyond the window).** An agent offline longer than W
messages cannot recover the chain, *by design* — that's the same property
that locks out an eavesdropper. It re-authenticates with its identity key
and is admitted as a joiner into a fresh epoch (§9). Missed content is
gone for it. Forward secrecy and lockout are the same mechanism; you
cannot have a backdoor for friends that isn't a backdoor.

**Rung 3 — partition merge.** Two halves that both kept talking have
forked chains that can never be merged (transcript binding forbids
CRDT-style reconciliation, deliberately). Resolution is political, not
cryptographic: pick a surviving side by policy (larger half, senior
member, coordination-layer leader), and the other side rejoins via Rung 2.
OPEN: policy language for this; whether the losing side's transcript
should be re-broadcast as content.

## 8. Fork, clone, and hijack detection

The signed header + fingerprint makes equivocation self-incriminating:

- **Clone / snapshot-restore:** a restored agent is detected on its first
  **message** at a slot the swarm has already committed: the body differs,
  so it is a signed contradiction (next bullet). Evict via §9.
  *Correction, from implementing the M2 harness:* an earlier draft here
  said "first message **or heartbeat**." The heartbeat half is wrong, and
  the distinction is load-bearing. A clone frozen at a past position holds
  the **correct** fingerprint for that position — being *behind* is not
  being *forked* — so its heartbeat is indistinguishable from an honest
  member that is merely lagging. A silent clone is therefore **not**
  detectable by fingerprint at all, whether it is stale or perfectly
  synced; only a spoken contradiction reveals it. This is broader than the
  "perfectly synced, silent" exception the draft admitted: *any* silent
  clone is invisible to the transcript layer, and catching one needs
  hardware attestation or behavioral/liveness signals (e.g. one identity
  answering from two places at once) — out of scope, and no transcript
  scheme can do it. The rest of the original caveat stands: a full-state
  clone (`ck` + identity keys) is not shaken off by epoch heals, because
  to the heal it *is* the member; and the instant its capture ever gaps,
  the salt makes the lockout permanent (§5.2).
- **Two clones of one identity, both live:** both hold valid `ck`, so both
  produce valid messages — but the *second* one at the same `(E, n)` with
  different content is a signed contradiction. Any member can present the
  pair `(header, H(body), sig) × 2` as transferable **proof of cloning** —
  this is why the signature must cover the body (§5.3): with header-only
  signatures, an innocent victim of insider re-bodying would be
  indistinguishable from a clone. Evict.
- **Equivocation (member sends different messages to different peers):**
  the two recipient subsets fork at `n+1`, fingerprints collide at the
  next crossing message, and the signed headers identify the author.
- **Impostor without `ck`:** cannot produce a valid `fp` or AEAD tag at
  all. Nothing to detect; it simply cannot speak.

This is the payoff of transcript binding: attacks that are *silent* in a
standard group channel become *attributable evidence* here.

## 9. Epochs and membership

Membership changes and periodic healing both work by starting a new epoch.
Sketch (deliberately boring — this layer should be as close to MLS as
possible, and could literally *be* MLS):

Two rules govern *every* membership operation, before the per-operation
details:

1. **Membership operations are transcript events.** A proposal
   (JOIN/EVICT/HEAL) is submitted through the ordered broadcast like any
   message and takes effect at its assigned position. This serializes
   concurrent membership changes — without it, two simultaneous joins
   both mint "epoch E+1" and fork the swarm at the epoch level, which
   would be a self-inflicted Rung-3 partition.
2. **Eviction requires quorum, not a coordinator's whim.** An EVICT
   proposal takes effect only when signed by a policy-defined quorum of
   the current roster (default: majority). A unilateral evict would be a
   partition weapon: any single insider could re-key the swarm around
   whoever it dislikes, or split it down the middle. The quorum rule also
   interacts with partitions — a minority partition can never evict the
   majority, which makes Rung-3 merges tractable (the quorum side's
   epochs are the legitimate line). OPEN: quorum policy language;
   amnesty/fast-rejoin for members evicted for unreachability who were
   in fact alive on the other side of a partition.

- **Join:** joiner authenticates; a current member (coordinator for this
  change) runs an ephemeral DH with the joiner and derives
  `epoch_secret' = KDF(ck_current, "tessera-epoch", DH_out || E+1)`.
  The joiner gets it over the DH channel; existing members get it
  broadcast, wrapped under `KDF(ck_current, "tessera-wrap", E+1)`. (They
  cannot derive it locally — `DH_out` is known only to the coordinator
  and joiner. An earlier draft claimed local derivation; it was wrong.)
  Both paths require what their recipients uniquely have: the joiner has
  the DH, the members have the chain. Joiner enters at `ck'_0` and
  **cannot derive anything earlier** — history-privacy for free.
  Trust asymmetry, surfaced by implementation: a joiner has no history,
  so it *cannot verify* `fp_close`, the roster, or the coordinator's
  legitimacy — it trusts the bundle it is handed, and its guarantees are
  forward-looking only (from `ck'_0` it is in lockstep). Joining is
  therefore exactly as trustworthy as the coordinator selection, no more.
- **Evict:** coordinator samples a *fresh* `epoch_secret'` (not derived
  from `ck`, which the evictee knows; the transcript stays bound via
  `fp_close`, §5.1) and sends it to each remaining member under **HPKE
  with a fresh ephemeral sender key** (ephemeral-static DH to each
  member's identity key). Ephemeral, not static-static: with pairwise
  static DH, an adversary who records the eviction traffic and *later*
  steals any member's identity key would decrypt that epoch secret
  retroactively — and with it everything the "fresh" re-key was supposed
  to protect. The re-key channel must have the same forward secrecy as
  the chain it re-keys. O(N) per eviction; MLS's tree makes this
  O(log N) if it matters. Evictee is locked out of everything forward.
- **Heal (PCS):** same as evict with nobody evicted, on a timer. Fresh DH
  entropy is the *only* thing that shakes off an attacker who stole `ck`
  and is capturing everything — transcript feedback alone never heals.
  Scope honestly: a heal shakes off an attacker who stole *chain state*,
  not one who stole the *identity key* — the latter receives the new
  epoch secret like any legitimate member (see the clone caveat, §8).
  PCS is bounded by identity-key integrity; there is no cryptographic
  cure for a stolen identity, only revocation and eviction.
  OPEN: heal cadence vs. swarm size tradeoff.

Three integrity details for every epoch-change bundle, learned in
implementation: (1) quorum signatures cover the *target epoch number*, so
a captured EVICT bundle is inert if replayed after the epoch has moved on
— it names an epoch nobody is entering. (2) The sealed per-member secrets
are bound (as AEAD context) to the operation, roster, and `fp_close`, so
a bundle cannot be spliced from parts of two others. (3) A coordinator
that seals *different* secrets to different members forks the swarm at
the new epoch's first message — detected by the normal fork dispatch, not
prevented; a coordinator can always DoS the swarm it coordinates, and
epoch-start fork detection is what keeps that sabotage loud.

## 10. Security properties

| Property | Provided by |
|---|---|
| Confidentiality vs. outsiders | epoch DH bootstrap + AEAD (standard) |
| Forward secrecy | one-way chain advance + key deletion (full — window stores no keys) |
| Post-compromise security | epoch heals (fresh DH), **not** the transcript |
| Gap-lockout of key thieves | transcript feedback + per-message salt (≥128-bit gaps) |
| In-group sender authenticity | body-covering signature (group `mk` alone proves nothing) |
| Tamper evidence | AEAD now, chain fork at n+1 as backstop |
| Channel/session binding | header + roster hash mixed into chain |
| Membership continuity proof | fp possession ≡ full-history participation (epoch chain via `fp_close`); transferable among colluding members |
| Clone/equivocation attribution | signed headers + fp collision — at speak time or on any capture gap; a synced, silent, full-state clone is undetectable (§8) |
| History privacy from joiners | epoch re-key on join |
| Membership-change integrity | quorum-signed EVICT, ordered membership ops, HPKE re-key delivery |

Explicitly **not** provided: metadata privacy, availability under DoS,
content arbitration between forks, security if the ordering layer
equivocates (OPEN: can we fingerprint the ordering service too?).

## 11. Open problems (the actual research)

1. **Ordering without a sequencer.** Everything above assumes total order.
   Real swarms are gossipy. Can the chain run over causal order with
   per-sender lanes that periodically braid (cross-mix) into a swarm
   checkpoint? Sketch idea: per-sender chains `ck^(s)`, plus a periodic
   BRAID message that mixes all lane fingerprints into every lane —
   divergence detection latency becomes the braid interval.
2. **Partition-merge policy** (§7 Rung 3) — including how a side *proves*
   it holds the quorum (roster signatures, not self-reported counts), and
   amnesty for members evicted as unreachable who were alive across the
   partition (§9).
3. **Heal cadence vs. cost** for large N; adopting the MLS tree wholesale.
4. **Ordering-layer trust** — a malicious sequencer can partition the
   swarm invisibly; can its behavior be transcript-bound as well?
5. **Formal analysis.** The chain is close enough to the MLS/Double
   Ratchet literature that a Tamarin or ProVerif model of the desync and
   fork-attribution claims is plausible and would be the paper's spine.
6. **Quorum policy language** for eviction and merges (§9): fixed
   majority is a placeholder; real swarms will want weighted, role-based,
   or attestation-gated quorums, and the policy itself must be
   transcript-bound or it becomes the new unauthenticated surface.
7. **Slot-confirmation latency.** Senders wait for the ordering layer
   before advancing (§6); at swarm message rates this round-trip may
   dominate. Speculative advance with rollback, or the per-sender-lane
   design from (1), are the candidate fixes — this pressure is another
   reason (1) may be the real architecture rather than the fallback.

## 12. Parameters (initial guesses)

| Param | Value | Note |
|---|---|---|
| W (retransmit window) | 64 msgs or 30 s, whichever is longer | ciphertexts only; time floor so a burst can't flush a slow peer's recovery |
| salt | 16 bytes | entropy floor for gap-lockout (§5.2) |
| T (heartbeat) | 10 s | detection latency for silent divergence |
| fp length | 8 bytes | collision ≈ 2⁻⁶⁴ per check; it's a tripwire, not a MAC |
| heal cadence | 15 min or 1k msgs | OPEN |
